<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Testing;

use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Firebase\JWT\JWT;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Issues RS256 tokens signed by a local key pair and makes the package
 * trust them for every configured guard - no Keycloak server needed.
 *
 *     $jwt = Keycloak::fake()->token(['roles' => ['admin']], 'api');
 */
class FakeKeycloak
{
    public const KID = 'bhry98-fake-key';

    /** @var array{private: string, jwk: array<string, string>}|null */
    protected static ?array $keyPair = null;

    public function __construct(protected KeycloakManager $keycloak)
    {
        foreach ([...$keycloak->guards(), $keycloak->defaultGuard()] as $guard) {
            $this->trust($guard);
        }
    }

    /** Trust the fake key for an extra guard / realm. */
    public function trust(RealmConfig|string $guard): static
    {
        $this->keycloak->jwks()->fake($this->keycloak->realm($guard), $this->jwks());

        return $this;
    }

    /**
     * Signed access token. Shortcuts: `roles` (realm roles), `client_roles`
     * (array, or [client => roles]), `scopes` (array), `groups` (array).
     *
     * @param  array<string, mixed>  $claims
     */
    public function token(array $claims = [], ?string $guard = null, int $ttl = 300): string
    {
        $realm = $this->keycloak->realm($guard);
        $now = time();

        $payload = [
            'exp' => $now + $ttl,
            'iat' => $now,
            'jti' => (string) Str::uuid(),
            'iss' => $realm->issuers[0] ?? $realm->baseUrl.'/realms/'.$realm->realm,
            'aud' => $realm->audience !== [] ? $realm->audience : 'account',
            'sub' => (string) Str::uuid(),
            'typ' => 'Bearer',
            'azp' => $realm->clientId,
            'sid' => (string) Str::uuid(),
            'scope' => 'openid email profile',
            'email_verified' => true,
            'name' => 'Test User',
            'preferred_username' => 'test.user',
            'given_name' => 'Test',
            'family_name' => 'User',
            'email' => 'test.user@example.com',
        ];

        if (array_key_exists('roles', $claims)) {
            $payload['realm_access'] = ['roles' => array_values((array) $claims['roles'])];
            unset($claims['roles']);
        }

        if (array_key_exists('client_roles', $claims)) {
            $clientRoles = (array) $claims['client_roles'];
            $payload['resource_access'] = array_is_list($clientRoles)
                ? [$realm->clientId => ['roles' => $clientRoles]]
                : array_map(fn ($roles) => ['roles' => array_values((array) $roles)], $clientRoles);
            unset($claims['client_roles']);
        }

        if (array_key_exists('scopes', $claims)) {
            $payload['scope'] = implode(' ', (array) $claims['scopes']);
            unset($claims['scopes']);
        }

        $payload = array_filter([...$payload, ...$claims], fn ($v) => $v !== null);

        return JWT::encode($payload, self::keyPair()['private'], 'RS256', self::KID);
    }

    /**
     * A parsed token (KeycloakToken) instead of the JWT string.
     *
     * @param  array<string, mixed>  $claims
     */
    public function make(array $claims = [], ?string $guard = null, int $ttl = 300): KeycloakToken
    {
        return $this->keycloak->decode($this->token($claims, $guard, $ttl), $guard);
    }

    /**
     * Token-endpoint style answer (for faking Http responses).
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    public function tokenResponse(array $claims = [], ?string $guard = null, int $ttl = 300): array
    {
        return [
            'access_token' => $this->token($claims, $guard, $ttl),
            'expires_in' => $ttl,
            'refresh_expires_in' => 1800,
            'refresh_token' => 'fake-refresh-'.Str::random(16),
            'id_token' => $this->token(['typ' => 'ID', ...$claims], $guard, $ttl),
            'token_type' => 'Bearer',
            'scope' => 'openid email profile',
        ];
    }

    /** @return array{keys: array<int, array<string, string>>} */
    public function jwks(): array
    {
        return ['keys' => [self::keyPair()['jwk']]];
    }

    /** @return array{private: string, jwk: array<string, string>} */
    protected static function keyPair(): array
    {
        if (self::$keyPair !== null) {
            return self::$keyPair;
        }

        $resource = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($resource === false || ! openssl_pkey_export($resource, $private)) {
            throw new RuntimeException('Unable to generate an RSA key pair (is ext-openssl configured?).');
        }

        $details = (array) openssl_pkey_get_details($resource);
        $b64 = static fn (string $v) => rtrim(strtr(base64_encode($v), '+/', '-_'), '=');

        return self::$keyPair = [
            'private' => (string) $private,
            'jwk' => [
                'kid' => self::KID,
                'kty' => 'RSA',
                'alg' => 'RS256',
                'use' => 'sig',
                'n' => $b64((string) $details['rsa']['n']),
                'e' => $b64((string) $details['rsa']['e']),
            ],
        ];
    }
}
