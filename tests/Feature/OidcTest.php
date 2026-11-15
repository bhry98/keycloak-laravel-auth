<?php

use Bhry98\KeycloakAuth\Exceptions\OidcException;
use Bhry98\KeycloakAuth\Facades\Keycloak;
use Illuminate\Support\Facades\Http;

it('performs a password grant with the guard credentials', function () {
    Http::fake([$this->oidcUrl('token') => Http::response(['access_token' => 'a', 'refresh_token' => 'r', 'expires_in' => 300])]);

    $tokens = Keycloak::oidc('api')->password('jane', 'secret-pass');

    expect($tokens['access_token'])->toBe('a');
    Http::assertSent(fn ($r) => $r['grant_type'] === 'password'
        && $r['username'] === 'jane'
        && $r['client_id'] === 'api-app'
        && $r['client_secret'] === 'api-secret'
        && $r->hasHeader('Content-Type', 'application/x-www-form-urlencoded'));
});

it('exposes the oauth error of a failed grant', function () {
    Http::fake([$this->oidcUrl('token') => Http::response(['error' => 'invalid_grant', 'error_description' => 'Invalid user credentials'], 401)]);

    try {
        Keycloak::oidc('api')->password('jane', 'wrong');
        $this->fail('Expected an exception');
    } catch (OidcException $e) {
        expect($e->error())->toBe('invalid_grant')
            ->and($e->errorDescription())->toBe('Invalid user credentials')
            ->and($e->status())->toBe(401)
            ->and($e->getMessage())->toContain('Invalid user credentials');
    }
});

it('caches the service token until it expires', function () {
    Http::fake([$this->oidcUrl('token') => Http::response(['access_token' => 'svc', 'expires_in' => 300])]);

    expect(Keycloak::serviceToken('api'))->toBe('svc')
        ->and(Keycloak::serviceToken('api'))->toBe('svc');

    Http::assertSentCount(1);
});

it('adds service and user tokens to outgoing http calls', function () {
    Http::fake([
        $this->oidcUrl('token') => Http::response(['access_token' => 'svc', 'expires_in' => 300]),
        'orders.test/*' => Http::response(['ok' => true]),
    ]);

    Http::withKeycloakToken('api')->get('https://orders.test/a');
    Http::assertSent(fn ($r) => $r->url() === 'https://orders.test/a' && $r->hasHeader('Authorization', 'Bearer svc'));

    $jwt = $this->keycloakToken();
    Keycloak::setToken(Keycloak::validate($jwt, 'api'));
    Http::withKeycloakUserToken()->get('https://orders.test/b');
    Http::assertSent(fn ($r) => $r->url() === 'https://orders.test/b' && $r->hasHeader('Authorization', 'Bearer '.$jwt));
});

it('introspects with an optional short cache', function () {
    Http::fake([$this->oidcUrl('token/introspect') => Http::response(['active' => true, 'exp' => time() + 300])]);

    expect(Keycloak::oidc('api')->isActive('t'))->toBeTrue()
        ->and(Keycloak::oidc('api')->isActive('t'))->toBeTrue();
    Http::assertSentCount(1);

    Keycloak::oidc('api')->introspect('t');
    Http::assertSentCount(2);
});

it('supports refresh, exchange, userinfo, logout and revoke', function () {
    Http::fake([
        $this->oidcUrl('token') => Http::response(['access_token' => 'new']),
        $this->oidcUrl('userinfo') => Http::response(['sub' => 'u']),
        $this->oidcUrl('logout') => Http::response(null, 204),
        $this->oidcUrl('revoke') => Http::response(null, 200),
    ]);

    $oidc = Keycloak::oidc('api');

    expect($oidc->refresh('r')['access_token'])->toBe('new')
        ->and($oidc->exchange('subject', 'orders-api')['access_token'])->toBe('new')
        ->and($oidc->userInfo('at'))->toBe(['sub' => 'u'])
        ->and($oidc->logout('r'))->toBeTrue()
        ->and($oidc->revoke('r'))->toBeTrue();

    Http::assertSent(fn ($r) => ($r['grant_type'] ?? null) === 'urn:ietf:params:oauth:grant-type:token-exchange' && $r['audience'] === 'orders-api');
    Http::assertSent(fn ($r) => $r->url() === $this->oidcUrl('userinfo') && $r->hasHeader('Authorization', 'Bearer at'));
});

it('builds the front-channel logout url', function () {
    expect(Keycloak::oidc('web')->logoutUrl('idt', 'https://app.test'))
        ->toBe($this->oidcUrl('logout').'?client_id=web-app&id_token_hint=idt&post_logout_redirect_uri=https%3A%2F%2Fapp.test');
});

it('lists uma permissions', function () {
    Http::fake([$this->oidcUrl('token') => Http::response([['rsname' => 'invoice', 'scopes' => ['read']]])]);

    expect(Keycloak::oidc('api')->permissions('at'))->toBe([['rsname' => 'invoice', 'scopes' => ['read']]]);
});

it('reads the discovery document once', function () {
    Http::fake(['https://kc.test/realms/demo/.well-known/openid-configuration' => Http::response(['issuer' => 'https://kc.test/realms/demo'])]);

    Keycloak::oidc('api')->discovery();
    expect(Keycloak::oidc('api')->discovery()['issuer'])->toBe('https://kc.test/realms/demo');
    Http::assertSentCount(1);
});
