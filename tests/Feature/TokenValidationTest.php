<?php

use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\Facades\Keycloak;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Testing\FakeKeycloak;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Http;

/** A token signed by the fake key, without making the main manager trust it. */
function untrustedSigner(): FakeKeycloak
{
    return (new KeycloakManager(app()))->fake();
}

it('validates a signed token offline', function () {
    $jwt = $this->keycloakToken(['sub' => 'user-1', 'roles' => ['admin']]);

    $token = Keycloak::validate($jwt, 'api');

    expect($token->subject())->toBe('user-1')
        ->and($token->hasRole('admin'))->toBeTrue()
        ->and($token->guard())->toBe('api');
});

it('rejects expired tokens', function () {
    $jwt = $this->fakeKeycloak()->token([], 'api', ttl: -120);

    Keycloak::validate($jwt, 'api');
})->throws(TokenValidationException::class);

it('honours the clock-skew leeway', function () {
    $jwt = $this->fakeKeycloak()->token([], 'api', ttl: -10);

    expect(Keycloak::validate($jwt, 'api')->subject())->not->toBeNull();
});

it('rejects tokens from another issuer', function () {
    $jwt = $this->keycloakToken(['iss' => 'https://evil.test/realms/demo']);

    Keycloak::validate($jwt, 'api');
})->throws(TokenValidationException::class, 'issuer');

it('accepts a configured public issuer', function () {
    config()->set('bhry98-keycloak.token.issuer', 'https://sso.public.test');
    Keycloak::forgetResolved();
    $this->fakeKeycloak()->trust('api');

    $jwt = $this->keycloakToken(['iss' => 'https://sso.public.test/realms/demo']);

    expect(Keycloak::check($jwt, 'api'))->not->toBeNull();
});

it('enforces the audience when configured', function () {
    config()->set('bhry98-keycloak.guard.api.audience', 'orders-api');
    Keycloak::forgetResolved();
    $fake = $this->fakeKeycloak()->trust('api');

    expect(Keycloak::check($fake->token(['aud' => 'account', 'azp' => 'spa'], 'api'), 'api'))->toBeNull()
        ->and(Keycloak::check($fake->token(['aud' => ['account', 'orders-api']], 'api'), 'api'))->not->toBeNull()
        ->and(Keycloak::check($fake->token(['aud' => 'account', 'azp' => 'orders-api'], 'api'), 'api'))->not->toBeNull();
});

it('rejects refresh / id tokens and disallowed algorithms', function () {
    $fake = $this->fakeKeycloak();

    expect(Keycloak::check($fake->token(['typ' => 'Refresh'], 'api'), 'api'))->toBeNull()
        ->and(Keycloak::check($fake->token(['typ' => 'ID'], 'api'), 'api'))->toBeNull();

    $hs = JWT::encode(['sub' => 'x', 'exp' => time() + 60, 'iss' => 'https://kc.test/realms/demo'], str_repeat('k', 64), 'HS256', FakeKeycloak::KID);
    expect(Keycloak::check($hs, 'api'))->toBeNull();

    expect(Keycloak::check('garbage', 'api'))->toBeNull();
});

it('rejects a tampered payload', function () {
    $jwt = $this->keycloakToken(['roles' => ['user']]);
    [$h, , $s] = explode('.', $jwt);
    $payload = rtrim(strtr(base64_encode(json_encode(['sub' => 'x', 'exp' => time() + 60, 'realm_access' => ['roles' => ['admin']]])), '+/', '-_'), '=');

    Keycloak::validate("{$h}.{$payload}.{$s}", 'api');
})->throws(TokenValidationException::class);

it('downloads the realm keys once and caches them', function () {
    $signer = untrustedSigner();
    Http::fake([$this->oidcUrl('certs') => Http::response($signer->jwks())]);

    $jwt = $signer->token([], 'api');
    expect(Keycloak::validate($jwt, 'api')->subject())->not->toBeNull();

    Keycloak::forgetResolved(); // drop in-memory state, keep the cache store
    Keycloak::validate($signer->token([], 'api'), 'api');

    Http::assertSentCount(1);
});

it('re-downloads keys when a token uses an unknown kid (rotation), with a cooldown', function () {
    $signer = untrustedSigner();
    Http::fakeSequence()
        ->push(['keys' => []])
        ->push($signer->jwks())
        ->push(['keys' => []]);

    $jwt = $signer->token([], 'api');

    expect(Keycloak::validate($jwt, 'api')->subject())->not->toBeNull();
    Http::assertSentCount(2);

    // An unknown kid within the cooldown window does not hit Keycloak again.
    $bad = JWT::encode(['sub' => 'x', 'exp' => time() + 60], openssl_pkey_get_private(openssl_pkey_export(openssl_pkey_new(['private_key_bits' => 2048]), $pem) ? $pem : ''), 'RS256', 'other-kid');
    expect(Keycloak::check($bad, 'api'))->toBeNull();
    Http::assertSentCount(2);
});

it('fails cleanly when keycloak is unreachable', function () {
    $signer = untrustedSigner();
    Http::fake([$this->oidcUrl('certs') => Http::response('down', 503)]);

    Keycloak::validate($signer->token([], 'api'), 'api');
})->throws(TokenValidationException::class, 'Unable to download');
