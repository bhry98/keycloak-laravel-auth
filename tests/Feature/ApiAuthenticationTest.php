<?php

use Bhry98\KeycloakAuth\Auth\KeycloakUser;
use Bhry98\KeycloakAuth\Events\TokenValidationFailed;
use Bhry98\KeycloakAuth\Events\UserProvisioned;
use Bhry98\KeycloakAuth\Facades\Keycloak;
use Bhry98\KeycloakAuth\Models\KCUserModel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Route::middleware('keycloak.api')->get('/api/me', fn (Request $request) => [
        'class' => get_class($request->user()),
        'id' => $request->user()->getAuthIdentifier(),
        'roles' => Keycloak::token()->roles(),
        'claims_bc' => $request->attributes->get('keycloak_user')['sub'] ?? null,
    ]);

    Route::middleware('auth:kc')->get('/api/guard', fn (Request $request) => [
        'class' => get_class($request->user()),
        'email' => $request->user()->email,
        'admin' => auth('kc')->hasRole('admin'),
    ]);
});

it('returns 401 without a bearer token', function () {
    $this->getJson('/api/me')
        ->assertUnauthorized()
        ->assertJson(['error' => 'Missing or invalid Authorization header'])
        ->assertHeader('WWW-Authenticate', 'Bearer');
});

it('returns 401 for an invalid token and dispatches an event', function () {
    Event::fake([TokenValidationFailed::class]);

    $this->withToken('nope')->getJson('/api/me')
        ->assertUnauthorized()
        ->assertJson(['error' => 'Invalid or expired token'])
        ->assertJsonMissingPath('message');

    Event::assertDispatched(TokenValidationFailed::class);
});

it('authenticates with a stateless user when provisioning is off', function () {
    config()->set('bhry98-keycloak.provisioning.enabled', false);

    $this->actingAsKeycloakUser(['sub' => 'u-1', 'roles' => ['admin'], 'client_roles' => ['editor']])
        ->getJson('/api/me')
        ->assertOk()
        ->assertJson([
            'class' => KeycloakUser::class,
            'id' => 'u-1',
            'roles' => ['admin', 'editor'],
            'claims_bc' => 'u-1',
        ]);

    expect(KCUserModel::count())->toBe(0);
});

it('provisions a local user once and skips writes while claims are unchanged', function () {
    Event::fake([UserProvisioned::class]);
    $sub = '7b3c2f1e-1111-4a4a-9999-000000000001';
    $claims = ['sub' => $sub, 'email' => 'jane@example.com', 'given_name' => 'Jane', 'family_name' => 'Doe', 'name' => 'Jane Doe', 'locale' => 'en-US'];

    $this->actingAsKeycloakUser($claims)->getJson('/api/me')->assertOk()->assertJson(['class' => KCUserModel::class]);
    $this->actingAsKeycloakUser($claims)->getJson('/api/me')->assertOk();

    Event::assertDispatchedTimes(UserProvisioned::class, 1);

    $user = KCUserModel::sole();
    expect($user->keycloak_id)->toBe($sub)
        ->and($user->keycloak_realm)->toBe('demo')
        ->and($user->first_name)->toBe('Jane')
        ->and($user->locale)->toBe('en-US');

    // Changed claims are written.
    $this->actingAsKeycloakUser([...$claims, 'given_name' => 'Janet'])->getJson('/api/me')->assertOk();
    expect($user->fresh()->first_name)->toBe('Janet');
    Event::assertDispatchedTimes(UserProvisioned::class, 2);
});

it('adopts an existing row with the same email', function () {
    $existing = KCUserModel::forceCreate(['keycloak_id' => 'old-id', 'keycloak_realm' => 'demo', 'name' => 'Old', 'email' => 'old@example.com']);

    $this->actingAsKeycloakUser(['sub' => 'new-id', 'email' => 'old@example.com'])->getJson('/api/me')->assertOk();

    expect(KCUserModel::count())->toBe(1)->and($existing->fresh()->keycloak_id)->toBe('new-id');
});

it('never provisions service accounts', function () {
    $this->actingAsKeycloakUser(['preferred_username' => 'service-account-billing', 'email' => null, 'client_id' => 'billing'])
        ->getJson('/api/me')
        ->assertOk()
        ->assertJson(['class' => KeycloakUser::class]);

    expect(KCUserModel::count())->toBe(0);
});

it('works as a laravel auth guard', function () {
    config()->set('bhry98-keycloak.provisioning.enabled', false);

    $this->getJson('/api/guard')->assertUnauthorized();

    $this->actingAsKeycloakUser(['email' => 'g@example.com', 'roles' => ['admin']])
        ->getJson('/api/guard')
        ->assertOk()
        ->assertJson(['class' => KeycloakUser::class, 'email' => 'g@example.com', 'admin' => true]);
});

it('lets the app resolve users itself', function () {
    Keycloak::resolveUserUsing(fn ($token) => new KeycloakUser($token));

    $this->actingAsKeycloakUser()->getJson('/api/me')->assertOk()->assertJson(['class' => KeycloakUser::class]);
    expect(KCUserModel::count())->toBe(0);
});

it('rejects the request when the custom resolver returns null', function () {
    Keycloak::resolveUserUsing(fn () => null);

    $this->actingAsKeycloakUser()->getJson('/api/me')->assertUnauthorized()->assertJson(['error' => 'Unauthenticated']);
    $this->actingAsKeycloakUser()->getJson('/api/guard')->assertUnauthorized();
});

it('validates credentials through the guard', function () {
    expect(auth('kc')->validate(['token' => $this->keycloakToken()]))->toBeTrue()
        ->and(auth('kc')->validate(['token' => 'x']))->toBeFalse();
});
