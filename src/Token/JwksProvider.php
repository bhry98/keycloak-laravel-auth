<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Token;

use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Throwable;

/**
 * Downloads and caches realm public keys (JWKS).
 *
 * Keys live in the configured cache store and are additionally memoized
 * in-process, so the hot path (validating a token) never touches the
 * network and rarely touches the cache.
 */
class JwksProvider
{
    /** @var array<string, array{jwks: array<string, mixed>, keys: array<string, Key>}> */
    protected array $memo = [];

    /** @var array<string, array<string, mixed>> Fixed key sets (testing). */
    protected array $fakes = [];

    public function __construct(protected KeycloakManager $keycloak) {}

    /**
     * Parsed keys of a realm, indexed by kid.
     *
     * @return array<string, Key>
     */
    public function keys(RealmConfig $realm): array
    {
        return $this->load($realm)['keys'];
    }

    /**
     * Raw JWKS document of a realm.
     *
     * @return array<string, mixed>
     */
    public function jwks(RealmConfig $realm): array
    {
        return $this->load($realm)['jwks'];
    }

    /**
     * Re-download the keys when a token uses an unknown kid (key rotation),
     * at most once per cooldown window so bad tokens cannot hammer Keycloak.
     *
     * @return array<string, Key>
     */
    public function refresh(RealmConfig $realm): array
    {
        if (isset($this->fakes[$realm->fingerprint()])) {
            return $this->keys($realm);
        }

        $cooldown = (int) $this->keycloak->config('token.jwks_refresh_cooldown', 30);
        $lock = $this->cacheKey($realm).':cooldown';

        if ($cooldown > 0 && ! $this->keycloak->cache()->add($lock, 1, $cooldown)) {
            return $this->keys($realm);
        }

        $jwks = $this->download($realm);
        $this->keycloak->cache()->put($this->cacheKey($realm), $jwks, $this->ttl());

        return $this->remember($realm, $jwks)['keys'];
    }

    public function forget(RealmConfig $realm): void
    {
        unset($this->memo[$realm->fingerprint()]);
        $this->keycloak->cache()->forget($this->cacheKey($realm));
        $this->keycloak->cache()->forget($this->cacheKey($realm).':cooldown');
    }

    /** @param  array<string, mixed>  $jwks */
    public function fake(RealmConfig $realm, array $jwks): void
    {
        $this->fakes[$realm->fingerprint()] = $jwks;
        unset($this->memo[$realm->fingerprint()]);
    }

    public function flushMemo(): void
    {
        $this->memo = [];
    }

    public function cacheKey(RealmConfig $realm): string
    {
        return $this->keycloak->cachePrefix().':jwks:'.md5($realm->baseUrl.'|'.$realm->realm);
    }

    /** @return array{jwks: array<string, mixed>, keys: array<string, Key>} */
    protected function load(RealmConfig $realm): array
    {
        $id = $realm->fingerprint();

        if (isset($this->memo[$id])) {
            return $this->memo[$id];
        }

        if (isset($this->fakes[$id])) {
            return $this->remember($realm, $this->fakes[$id]);
        }

        $jwks = $this->keycloak->cache()->remember($this->cacheKey($realm), $this->ttl(), fn () => $this->download($realm));

        return $this->remember($realm, $jwks);
    }

    /**
     * @param  array<string, mixed>  $jwks
     * @return array{jwks: array<string, mixed>, keys: array<string, Key>}
     */
    protected function remember(RealmConfig $realm, array $jwks): array
    {
        return $this->memo[$realm->fingerprint()] = ['jwks' => $jwks, 'keys' => $this->parse($jwks)];
    }

    /**
     * @param  array<string, mixed>  $jwks
     * @return array<string, Key>
     */
    protected function parse(array $jwks): array
    {
        $keys = [];

        foreach ((array) ($jwks['keys'] ?? []) as $jwk) {
            // Keycloak also publishes encryption keys (use=enc); they can't verify signatures.
            if (! is_array($jwk) || ($jwk['use'] ?? 'sig') !== 'sig' || ! isset($jwk['kid'])) {
                continue;
            }

            try {
                $key = JWK::parseKey($jwk, $jwk['alg'] ?? 'RS256');
            } catch (Throwable) {
                continue;
            }

            if ($key !== null) {
                $keys[(string) $jwk['kid']] = $key;
            }
        }

        return $keys;
    }

    /** @return array<string, mixed> */
    protected function download(RealmConfig $realm): array
    {
        try {
            $response = $this->keycloak->http()->get($realm->openIdUrl('certs'));
        } catch (Throwable $e) {
            throw new TokenValidationException("Unable to reach Keycloak to download the realm keys: {$e->getMessage()}", 0, $e);
        }

        $jwks = $response->json();

        if ($response->failed() || ! is_array($jwks) || ! isset($jwks['keys'])) {
            throw TokenValidationException::fromResponse("Unable to download the keys of realm [{$realm->realm}]", $response);
        }

        return $jwks;
    }

    protected function ttl(): int
    {
        return max(60, (int) $this->keycloak->config('token.jwks_ttl', 86400));
    }
}
