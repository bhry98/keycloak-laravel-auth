<?php

use Bhry98\KeycloakAuth\Exceptions\AdminApiException;
use Bhry98\KeycloakAuth\Facades\Keycloak;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

function fakeAdminToken(): array
{
    return [TestAdmin::tokenUrl() => Http::response(['access_token' => 'admin-token', 'expires_in' => 60])];
}

class TestAdmin
{
    public static function tokenUrl(): string
    {
        return 'https://kc.test/realms/master/protocol/openid-connect/token';
    }
}

it('gets the admin token from the admin guard and caches it', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('users/count') => Http::response('42'),
    ]);

    expect(Keycloak::users('web')->count())->toBe(42)
        ->and(Keycloak::users('web')->count())->toBe(42);

    Http::assertSentCount(3); // 1 token + 2 calls
    Http::assertSent(fn (Request $r) => $r->url() === TestAdmin::tokenUrl()
        && $r['grant_type'] === 'client_credentials'
        && $r['client_id'] === 'admin-cli-sa');
    Http::assertSent(fn (Request $r) => str_starts_with($r->url(), $this->adminUrl('users/count'))
        && $r->hasHeader('Authorization', 'Bearer admin-token'));
});

it('refreshes the admin token and retries once on 401', function () {
    Http::fake([
        TestAdmin::tokenUrl() => Http::sequence()
            ->push(['access_token' => 'stale', 'expires_in' => 60])
            ->push(['access_token' => 'fresh', 'expires_in' => 60]),
        $this->adminUrl('users/count') => Http::sequence()->push(null, 401)->push('7'),
    ]);

    expect(Keycloak::users('web')->count())->toBe(7);
});

it('creates a user from snake_case input and returns its id', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('users') => Http::response(null, 201, ['Location' => $this->adminUrl('users/new-uuid')]),
    ]);

    $id = Keycloak::users('web')->create([
        'username' => 'jane',
        'email' => 'jane@example.com',
        'first_name' => 'Jane',
        'last_name' => 'Doe',
        'email_verified' => 'true',
        'attributes' => ['department' => 'IT'],
        'password' => 'S3cret!',
        'temp_password' => true,
        'type' => 'local-only',
    ]);

    expect($id)->toBe('new-uuid');
    Http::assertSent(fn (Request $r) => $r->method() === 'POST' && $r->url() === $this->adminUrl('users') && $r->data() === [
        'username' => 'jane',
        'email' => 'jane@example.com',
        'firstName' => 'Jane',
        'lastName' => 'Doe',
        'emailVerified' => true,
        'attributes' => ['department' => ['IT']],
        'credentials' => [['type' => 'password', 'value' => 'S3cret!', 'temporary' => true]],
        'enabled' => true,
    ]);
});

it('returns null for missing users and throws on other errors', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('users/missing') => Http::response(['error' => 'User not found'], 404),
        $this->adminUrl('users/broken') => Http::response(['errorMessage' => 'boom'], 500),
    ]);

    expect(Keycloak::users('web')->find('missing'))->toBeNull();

    Keycloak::users('web')->find('broken');
})->throws(AdminApiException::class, 'boom');

it('searches users exactly by email / username / attribute', function () {
    Http::fake([...fakeAdminToken(), $this->adminUrl('users*') => Http::response([['id' => 'u1']])]);

    expect(Keycloak::users('web')->findByEmail('a@b.c')['id'])->toBe('u1');
    Keycloak::users('web')->findByAttribute('employee_id', '42');

    Http::assertSent(fn (Request $r) => str_contains($r->url(), 'email=a%40b.c') && str_contains($r->url(), 'exact=true'));
    Http::assertSent(fn (Request $r) => str_contains(urldecode($r->url()), 'q=employee_id:42'));
});

it('walks all users lazily, page by page', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('users*') => Http::sequence()
            ->push([['id' => 1], ['id' => 2]])
            ->push([['id' => 3], ['id' => 4]])
            ->push([['id' => 5]]),
    ]);

    expect(Keycloak::users('web')->cursor([], 2)->pluck('id')->all())->toBe([1, 2, 3, 4, 5]);
});

it('assigns realm roles by name', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('roles/editor') => Http::response(['id' => 'r1', 'name' => 'editor']),
        $this->adminUrl('users/u1/role-mappings/realm') => Http::response(null, 204),
    ]);

    expect(Keycloak::users('web')->assignRealmRoles('u1', 'editor'))->toBeTrue();
    Keycloak::users('web')->removeRealmRoles('u1', ['editor']);

    Http::assertSent(fn (Request $r) => $r->method() === 'POST' && str_ends_with($r->url(), 'users/u1/role-mappings/realm') && $r->data() === [['id' => 'r1', 'name' => 'editor']]);
    Http::assertSent(fn (Request $r) => $r->method() === 'DELETE' && str_ends_with($r->url(), 'users/u1/role-mappings/realm'));
    // Role representation is memoized.
    Http::assertSentCount(4);
});

it('assigns client roles via a cached client uuid lookup', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('clients?clientId=billing') => Http::response([['id' => 'client-uuid', 'clientId' => 'billing']]),
        $this->adminUrl('clients/client-uuid/roles/viewer') => Http::response(['id' => 'cr1', 'name' => 'viewer']),
        $this->adminUrl('users/u1/role-mappings/clients/client-uuid') => Http::response(null, 204),
        $this->adminUrl('groups/g1/role-mappings/clients/client-uuid') => Http::response(null, 204),
    ]);

    Keycloak::users('web')->assignClientRoles('u1', 'billing', ['viewer']);
    Keycloak::forgetResolved();
    Keycloak::groups('web')->assignClientRoles('g1', 'billing', ['viewer']);

    Http::assertSent(fn (Request $r) => str_ends_with($r->url(), 'users/u1/role-mappings/clients/client-uuid') && $r->data() === [['id' => 'cr1', 'name' => 'viewer']]);
    expect(collect(Http::recorded())->filter(fn ($pair) => str_contains($pair[0]->url(), 'clients?clientId'))->count())->toBe(1);
});

it('manages groups and membership', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('groups') => Http::response(null, 201, ['Location' => $this->adminUrl('groups/g-new')]),
        $this->adminUrl('groups/g-new/children') => Http::response(null, 201, ['Location' => $this->adminUrl('groups/g-child')]),
        $this->adminUrl('group-by-path/company/engineering') => Http::response(['id' => 'g-child', 'path' => '/company/engineering']),
        $this->adminUrl('users/u1/groups/g-child') => Http::response(null, 204),
        $this->adminUrl('groups/g-child/members*') => Http::response([['id' => 'u1']]),
    ]);

    $groups = Keycloak::groups('web');

    expect($groups->create('company'))->toBe('g-new')
        ->and($groups->createChild('g-new', 'engineering'))->toBe('g-child')
        ->and($groups->findByPath('/company/engineering')['id'])->toBe('g-child')
        ->and($groups->addUser('g-child', 'u1'))->toBeTrue()
        ->and($groups->members('g-child'))->toBe([['id' => 'u1']]);

    Http::assertSent(fn (Request $r) => $r->method() === 'PUT' && str_ends_with($r->url(), 'users/u1/groups/g-child'));
});

it('sends required-action e-mails', function () {
    Http::fake([...fakeAdminToken(), $this->adminUrl('users/u1/execute-actions-email*') => Http::response(null, 204)]);

    Keycloak::users('web')->sendResetPasswordEmail('u1', 3600);

    Http::assertSent(fn (Request $r) => $r->method() === 'PUT'
        && str_contains($r->url(), 'execute-actions-email?lifespan=3600')
        && $r->data() === ['UPDATE_PASSWORD']);
});

it('targets the realm of the requested guard', function () {
    Http::fake([
        ...fakeAdminToken(),
        $this->adminUrl('roles', 'master').'*' => Http::response([['name' => 'm']]),
        $this->adminUrl('roles').'*' => Http::response([['name' => 'd']]),
    ]);

    expect(Keycloak::roles('admin')->names())->toBe(['m'])
        ->and(Keycloak::roles('web')->names())->toBe(['d']);
});
