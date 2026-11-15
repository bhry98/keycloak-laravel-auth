<?php

use Bhry98\KeycloakAuth\Facades\KCAuth;
use Bhry98\KeycloakAuth\Facades\Keycloak;
use Bhry98\KeycloakAuth\Models\KCUserModel;
use Bhry98\KeycloakAuth\Services\KeycloakGroupService;
use Bhry98\KeycloakAuth\Services\KeycloakJWTService;
use Bhry98\KeycloakAuth\Services\KeycloakRoleService;
use Bhry98\KeycloakAuth\Services\KeycloakSocialiteProvider;
use Bhry98\KeycloakAuth\Services\KeycloakUsersService;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

$adminToken = fn () => ['https://kc.test/realms/master/protocol/openid-connect/token' => Http::response(['access_token' => 'admin-token', 'expires_in' => 60])];

it('creates a keycloak user and syncs the local model (1.x users service)', function () use ($adminToken) {
    Http::fake([
        ...$adminToken(),
        $this->adminUrl('users') => Http::response(null, 201, ['Location' => $this->adminUrl('users/0b7e7a8e-0000-4000-8000-000000000001')]),
        $this->adminUrl('users/0b7e7a8e-0000-4000-8000-000000000001') => Http::response([
            'id' => '0b7e7a8e-0000-4000-8000-000000000001',
            'username' => 'jane',
            'email' => 'jane@example.com',
            'firstName' => 'Jane',
            'lastName' => 'Doe',
            'emailVerified' => true,
            'enabled' => true,
        ]),
    ]);

    $user = KeycloakUsersService::guard('web')->create(['username' => 'jane', 'email' => 'jane@example.com', 'type' => 'staff']);

    expect($user)->toBeInstanceOf(KCUserModel::class)
        ->and($user->keycloak_id)->toBe('0b7e7a8e-0000-4000-8000-000000000001')
        ->and($user->name)->toBe('Jane Doe')
        ->and($user->type)->toBe('staff')
        ->and($user->account_enable)->toBeTrue();
});

it('keeps the 1.x role service targeting the admin realm', function () use ($adminToken) {
    Http::fake([
        ...$adminToken(),
        $this->adminUrl('roles', 'master') => Http::response(null, 201),
        $this->adminUrl('roles/editor', 'master') => Http::response(['id' => 'r', 'name' => 'editor']),
        $this->adminUrl('groups/g/role-mappings/realm', 'master') => Http::response(null, 204),
        $this->adminUrl('roles', 'demo') => Http::response(null, 201),
    ]);

    expect((new KeycloakRoleService)->createRole('editor', 'Editors'))->toBeTrue()
        ->and((new KeycloakRoleService)->assignRoleToGroup('g', 'editor'))->toBeTrue()
        ->and(KeycloakRoleService::guard('web')->createRole('editor'))->toBeTrue();

    Http::assertSent(fn (Request $r) => $r->url() === $this->adminUrl('roles', 'demo'));
});

it('keeps the 1.x group service working', function () use ($adminToken) {
    Http::fake([
        ...$adminToken(),
        $this->adminUrl('groups') => Http::sequence()
            ->push(null, 201, ['Location' => $this->adminUrl('groups/g1')])
            ->push([['id' => 'g1']]),
    ]);

    expect((new KeycloakGroupService)->createGroup('staff'))->toBeTrue()
        ->and((new KeycloakGroupService)->getAllGroups())->toBe([['id' => 'g1']]);
});

it('keeps the 1.x jwt service working', function () {
    $jwt = $this->keycloakToken(['sub' => 's1'], 'web');

    expect((new KeycloakJWTService)->validateAndDecode($jwt)['sub'])->toBe('s1')
        ->and((new KeycloakJWTService)->decodeToken($jwt)->sub)->toBe('s1')
        ->and((new KeycloakJWTService)->validateAndDecode('bad'))->toBeNull();
});

it('keeps KCAuth role helpers working', function () {
    config()->set('bhry98-keycloak.provisioning.enabled', false);
    Route::middleware('keycloak.api')->get('/kcauth', fn () => [
        'roles' => KCAuth::userRoles(),
        'access' => KCAuth::hasAccess(['admin']),
        'client_only' => KCAuth::hasAccess(['admin'], true),
    ]);

    $this->actingAsKeycloakUser(['roles' => ['admin'], 'client_roles' => ['editor']])
        ->getJson('/kcauth')
        ->assertJson(['roles' => ['admin', 'editor'], 'access' => true, 'client_only' => false]);
});

it('exposes roles on the model and an avatar fallback', function () {
    Route::middleware('keycloak.api')->get('/model', fn () => [
        'realm' => auth()->user()->realm_roles,
        'has' => auth()->user()->hasRole('admin'),
        'avatar' => auth()->user()->avatar_url,
    ]);

    $this->actingAsKeycloakUser(['sub' => '0b7e7a8e-0000-4000-8000-0000000000aa', 'roles' => ['admin'], 'picture' => null])
        ->getJson('/model')
        ->assertJson(['realm' => ['admin'], 'has' => true])
        ->assertJsonPath('avatar', fn ($url) => str_starts_with($url, 'https://www.gravatar.com/avatar/'));
});

it('still registers the 1.x middleware aliases and routes', function () {
    $aliases = app('router')->getMiddleware();

    expect($aliases)->toHaveKeys(['keycloak.api', 'keycloak.web', 'keycloak.role', 'keycloak.scope', 'keycloak.permission'])
        ->and(route('keycloak.login', ['guard' => 'web']))->toEndWith('/auth/keycloak/login/web')
        ->and(Keycloak::socialite('web'))->toBeInstanceOf(KeycloakSocialiteProvider::class);
});
