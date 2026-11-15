<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Support;

/**
 * Resolved settings of one configured guard (realm + client).
 */
final class RealmConfig
{
    /**
     * @param  array<int, string>  $scopes
     * @param  array<int, string>  $audience
     * @param  array<int, string>  $issuers
     * @param  array<string, mixed>  $extra
     */
    public function __construct(
        public readonly string $name,
        public readonly string $baseUrl,
        public readonly string $realm,
        public readonly string $clientId,
        public readonly string $clientSecret,
        public readonly string $redirect,
        public readonly array $scopes,
        public readonly array $audience,
        public readonly array $issuers,
        public readonly array $extra = [],
    ) {}

    /**
     * @param  array<string, mixed>  $guard
     * @param  array<string, mixed>  $root
     */
    public static function fromArray(string $name, array $guard, array $root): self
    {
        $pick = static fn (string $key, mixed $default = '') => ($guard[$key] ?? null) !== null && $guard[$key] !== ''
            ? $guard[$key]
            : ($root[$key] ?? $default);

        $baseUrl = rtrim((string) $pick('base_url'), '/');
        $realm = trim((string) $pick('realm'), '/');

        $issuers = (array) ($guard['issuer'] ?? $root['token']['issuer'] ?? []);
        $issuers = array_values(array_filter(array_map(
            static fn ($issuer) => str_contains((string) $issuer, '/realms/')
                ? rtrim((string) $issuer, '/')
                : rtrim((string) $issuer, '/').'/realms/'.$realm,
            $issuers,
        )));
        $issuers[] = $baseUrl.'/realms/'.$realm;

        $audience = $guard['audience'] ?? null;
        $audience = is_string($audience) ? explode(',', $audience) : (array) $audience;

        return new self(
            name: $name,
            baseUrl: $baseUrl,
            realm: $realm,
            clientId: (string) $pick('client_id'),
            clientSecret: (string) $pick('client_secret'),
            redirect: (string) $pick('redirect'),
            scopes: array_values((array) ($guard['scopes'] ?? ['openid', 'email', 'profile'])),
            audience: array_values(array_filter(array_map('trim', $audience))),
            issuers: array_values(array_unique($issuers)),
            extra: $guard,
        );
    }

    public function realmUrl(): string
    {
        return $this->baseUrl.'/realms/'.rawurlencode($this->realm);
    }

    public function openIdUrl(string $endpoint): string
    {
        return $this->realmUrl().'/protocol/openid-connect/'.ltrim($endpoint, '/');
    }

    public function adminUrl(string $path = ''): string
    {
        return $this->baseUrl.'/admin/realms/'.rawurlencode($this->realm).($path === '' ? '' : '/'.ltrim($path, '/'));
    }

    /** Stable key identifying this realm + client, for cache keys. */
    public function fingerprint(): string
    {
        return md5($this->baseUrl.'|'.$this->realm.'|'.$this->clientId);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->extra[$key] ?? $default;
    }
}
