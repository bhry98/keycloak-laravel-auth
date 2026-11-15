<?php

use Bhry98\KeycloakAuth\Auth\WebSession;
use Bhry98\KeycloakAuth\Events\TokenRefreshed;
use Bhry98\KeycloakAuth\Events\UserLoggedIn;
use Bhry98\KeycloakAuth\Events\UserLoggedOut;
use Bhry98\KeycloakAuth\Facades\Keycloak;
use Bhry98\KeycloakAuth\Models\KCUserModel;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    Route::middleware(['web', 'keycloak.web'])->get('/dashboard', fn () => 'roles:'.implode(',', Keycloak::token()?->roles() ?? []));
});

function webUser(): KCUserModel
{
    return KCUserModel::forceCreate([
        'keycloak_id' => '11111111-2222-3333-4444-555555555555',
        'keycloak_realm' => 'demo',
        'name' => 'Jane',
        'email' => 'jane@example.com',
    ]);
}

it('redirects guests to the keycloak login page with PKCE', function () {
    $response = $this->get('/dashboard')->assertRedirect();
    $location = $response->headers->get('Location');

    expect($location)->toStartWith($this->oidcUrl('auth').'?')
        ->toContain('client_id=web-app')
        ->toContain('code_challenge=')
        ->toContain('code_challenge_method=S256')
        ->toContain('scope=openid+email+profile')
        ->toContain(urlencode('https://app.test/auth/keycloak/callback/web'));

    expect(session('redirect_to'))->toBe('http://localhost/dashboard');
});

it('answers json requests with 401 instead of redirecting', function () {
    $this->getJson('/dashboard')->assertUnauthorized();
});

it('lets a logged-in user through without calling keycloak', function () {
    Http::fake();

    $this->actingAsKeycloakWebUser(webUser(), ['roles' => ['admin']])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('roles:admin');

    Http::assertNothingSent();
});

it('refreshes an expiring access token with the refresh token', function () {
    Event::fake([TokenRefreshed::class]);
    $user = webUser();
    $fresh = $this->fakeKeycloak()->tokenResponse(['sub' => $user->keycloak_id, 'roles' => ['fresh-role']], 'web');
    Http::fake([$this->oidcUrl('token') => Http::response($fresh)]);

    $this->actingAsKeycloakWebUser($user)
        ->withSession([WebSession::EXPIRES_AT => time() - 1])
        ->get('/dashboard')
        ->assertOk()
        ->assertSee('roles:fresh-role');

    Http::assertSent(fn ($request) => $request['grant_type'] === 'refresh_token'
        && $request['client_id'] === 'web-app'
        && $request['client_secret'] === 'web-secret');
    Event::assertDispatched(TokenRefreshed::class);
    expect(session(WebSession::ACCESS))->toBe($fresh['access_token']);
});

it('sends the user back to login when the refresh token is rejected', function () {
    Http::fake([$this->oidcUrl('token') => Http::response(['error' => 'invalid_grant'], 400)]);

    $this->actingAsKeycloakWebUser(webUser())
        ->withSession([WebSession::EXPIRES_AT => time() - 1])
        ->get('/dashboard')
        ->assertRedirectContains($this->oidcUrl('auth'));

    $this->assertGuest();
});

it('can validate the session through cached introspection', function () {
    config()->set('bhry98-keycloak.web.validation', 'introspect');
    Http::fake([$this->oidcUrl('token/introspect') => Http::sequence()->push(['active' => true, 'exp' => time() + 300])->push(['active' => false])]);

    $user = webUser();
    $this->actingAsKeycloakWebUser($user)->get('/dashboard')->assertOk();
    $this->get('/dashboard')->assertOk(); // cached answer

    Http::assertSentCount(1);
});

it('completes the authorization-code callback', function () {
    Event::fake([UserLoggedIn::class]);
    $fake = $this->fakeKeycloak();
    $tokens = $fake->tokenResponse(['sub' => '99999999-2222-3333-4444-555555555555', 'roles' => ['admin']], 'web');

    Http::fake([
        $this->oidcUrl('token') => Http::response($tokens),
        $this->oidcUrl('userinfo') => Http::response([
            'sub' => '99999999-2222-3333-4444-555555555555',
            'email' => 'new@example.com',
            'given_name' => 'New',
            'family_name' => 'Person',
            'preferred_username' => 'new.person',
        ]),
    ]);

    $this->withSession(['state' => 'abc', 'code_verifier' => 'verifier', 'redirect_to' => '/dashboard'])
        ->get('/auth/keycloak/callback/web?code=the-code&state=abc')
        ->assertRedirect('/dashboard');

    $user = KCUserModel::sole();
    expect($user->email)->toBe('new@example.com')
        ->and($user->username)->toBe('new.person')
        ->and(auth()->id())->toBe($user->id)
        ->and(session(WebSession::ID))->toBe($tokens['id_token'])
        ->and(session('keycloak_realm_roles'))->toBe(['admin']);

    Http::assertSent(fn ($request) => $request->url() === $this->oidcUrl('token')
        && $request['code'] === 'the-code'
        && $request['code_verifier'] === 'verifier');
    Event::assertDispatched(UserLoggedIn::class);
});

it('restarts the login on an invalid state', function () {
    $this->withSession(['state' => 'abc'])
        ->get('/auth/keycloak/callback/web?code=x&state=WRONG')
        ->assertRedirect(route('keycloak.login', ['guard' => 'web']));
});

it('shows an error when keycloak returns one', function () {
    $this->get('/auth/keycloak/callback/web?error=access_denied&error_description=Denied')->assertUnauthorized();
});

it('logs out locally and at keycloak', function () {
    Event::fake([UserLoggedOut::class]);
    $user = webUser();

    $this->actingAsKeycloakWebUser($user);
    $idToken = session(WebSession::ID) ?? null;

    $response = $this->get('/auth/keycloak/logout/web');
    $location = $response->headers->get('Location');

    expect($location)->toStartWith($this->oidcUrl('logout').'?')
        ->toContain('client_id=web-app')
        ->toContain('id_token_hint=')
        ->toContain(urlencode('https://app.test/bye'));

    $this->assertGuest();
    Event::assertDispatched(UserLoggedOut::class);
});

it('remembers a local redirect target on login', function () {
    $this->get('/auth/keycloak/login/web?redirect=/reports')->assertRedirect();
    expect(session('redirect_to'))->toBe('/reports');

    $this->get('/auth/keycloak/login/web?redirect=https://evil.test/x');
    expect(session('redirect_to'))->toBe('/reports');
});
