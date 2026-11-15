<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Token;

use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Firebase\JWT\JWT;
use Throwable;

/**
 * Verifies Keycloak access tokens offline: signature (cached JWKS), expiry,
 * issuer, audience and token type. No network call on the hot path.
 */
class TokenValidator
{
    /** Small in-process cache so the same token is verified once per process. */
    protected const MEMO_LIMIT = 256;

    /** @var array<string, KeycloakToken> */
    protected array $memo = [];

    public function __construct(
        protected KeycloakManager $keycloak,
        protected JwksProvider $jwks,
    ) {}

    /**
     * @throws TokenValidationException
     */
    public function validate(string $jwt, RealmConfig $realm): KeycloakToken
    {
        $jwt = trim($jwt);

        if ($jwt === '') {
            throw new TokenValidationException('Empty token.');
        }

        $memoKey = $realm->name.'|'.hash('xxh128', $jwt);

        if (isset($this->memo[$memoKey])) {
            $token = $this->memo[$memoKey];

            if (! $token->isExpired((int) $this->keycloak->config('token.leeway', 30))) {
                return $token;
            }

            unset($this->memo[$memoKey]);
        }

        $header = $this->header($jwt);
        $alg = (string) ($header['alg'] ?? '');
        $kid = (string) ($header['kid'] ?? '');

        if (! in_array($alg, (array) $this->keycloak->config('token.allowed_algs', ['RS256']), true)) {
            throw new TokenValidationException("Token signing algorithm [{$alg}] is not allowed.");
        }

        $keys = $this->jwks->keys($realm);

        if ($kid === '' || ! isset($keys[$kid])) {
            // Unknown key: the realm keys may have been rotated.
            $keys = $this->jwks->refresh($realm);
        }

        if ($kid === '' ? $keys === [] : ! isset($keys[$kid])) {
            throw new TokenValidationException('Token is signed with an unknown key.');
        }

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = (int) $this->keycloak->config('token.leeway', 30);

        try {
            $decoded = JWT::decode($jwt, $kid === '' ? $keys : $keys[$kid]);
        } catch (Throwable $e) {
            throw new TokenValidationException('Invalid token: '.$e->getMessage(), 0, $e);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        /** @var array<string, mixed> $claims */
        $claims = json_decode((string) json_encode($decoded), true);

        $this->assertClaims($claims, $realm);

        $token = new KeycloakToken($claims, $jwt, $realm->name, $this->keycloak->roleClients($realm, $claims));

        if (count($this->memo) >= self::MEMO_LIMIT) {
            $this->memo = array_slice($this->memo, (int) (self::MEMO_LIMIT / 2), null, true);
        }

        return $this->memo[$memoKey] = $token;
    }

    public function flushMemo(): void
    {
        $this->memo = [];
    }

    /** @param  array<string, mixed>  $claims */
    protected function assertClaims(array $claims, RealmConfig $realm): void
    {
        if (! isset($claims['exp'])) {
            throw new TokenValidationException('Token has no expiry.');
        }

        $types = (array) $this->keycloak->config('token.allowed_types', ['Bearer']);
        if (isset($claims['typ']) && $types !== [] && ! in_array($claims['typ'], $types, true)) {
            throw new TokenValidationException("Token type [{$claims['typ']}] is not accepted.");
        }

        if ($this->keycloak->config('token.verify_issuer', true)
            && ! in_array(rtrim((string) ($claims['iss'] ?? ''), '/'), $realm->issuers, true)) {
            throw new TokenValidationException('Token issuer ['.($claims['iss'] ?? '').'] is not trusted.');
        }

        if ($realm->audience !== []) {
            $presented = [...(array) ($claims['aud'] ?? []), ...(isset($claims['azp']) ? [$claims['azp']] : [])];

            if (array_intersect($realm->audience, $presented) === []) {
                throw new TokenValidationException('Token audience is not accepted.');
            }
        }
    }

    /** @return array<string, mixed> */
    protected function header(string $jwt): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new TokenValidationException('Malformed token.');
        }

        $header = json_decode(KeycloakToken::base64UrlDecode($parts[0]), true);

        if (! is_array($header)) {
            throw new TokenValidationException('Malformed token header.');
        }

        return $header;
    }
}
