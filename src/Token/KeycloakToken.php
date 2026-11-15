<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Token;

use BackedEnum;
use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Support\Arr;
use JsonSerializable;
use UnitEnum;

/**
 * An access token issued by Keycloak, with helpers for its claims.
 *
 * @phpstan-consistent-constructor
 *
 * @implements Arrayable<string, mixed>
 */
class KeycloakToken implements Arrayable, JsonSerializable
{
    /**
     * @param  array<string, mixed>  $claims
     * @param  array<int, string>  $clients  Clients whose roles count for hasRole()
     */
    public function __construct(
        protected array $claims,
        protected string $jwt = '',
        protected string $guard = 'web',
        protected array $clients = [],
    ) {
        if ($this->clients === []) {
            $this->clients = $this->azp() !== null ? [$this->azp()] : [];
        }
    }

    /**
     * Read the claims of a JWT WITHOUT verifying its signature.
     * Only use on tokens you received directly from Keycloak (back-channel).
     *
     * @param  array<int, string>  $clients
     */
    public static function fromJwtUnverified(string $jwt, string $guard = 'web', array $clients = []): static
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new TokenValidationException('Malformed JWT.');
        }

        $claims = json_decode(self::base64UrlDecode($parts[1]), true);

        if (! is_array($claims)) {
            throw new TokenValidationException('Malformed JWT payload.');
        }

        return new static($claims, $jwt, $guard, $clients);
    }

    public static function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;

        if ($remainder !== 0) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        return (string) base64_decode(strtr($value, '-_', '+/'), true);
    }

    /* ---------------------------------------------------------------
     | Raw access
     * ------------------------------------------------------------- */

    public function claim(string $key, mixed $default = null): mixed
    {
        return Arr::get($this->claims, $key, $default);
    }

    public function has(string $key): bool
    {
        return Arr::has($this->claims, $key);
    }

    /** @return array<string, mixed> */
    public function claims(): array
    {
        return $this->claims;
    }

    public function jwt(): string
    {
        return $this->jwt;
    }

    public function __toString(): string
    {
        return $this->jwt;
    }

    public function guard(): string
    {
        return $this->guard;
    }

    public function __get(string $name): mixed
    {
        return $this->claims[$name] ?? null;
    }

    public function __isset(string $name): bool
    {
        return isset($this->claims[$name]);
    }

    /* ---------------------------------------------------------------
     | Identity
     * ------------------------------------------------------------- */

    public function subject(): ?string
    {
        $sub = $this->claims['sub'] ?? null;

        return is_string($sub) && $sub !== '' ? $sub : null;
    }

    /** Alias of subject(): the Keycloak user id. */
    public function id(): ?string
    {
        return $this->subject();
    }

    public function email(): ?string
    {
        return $this->claims['email'] ?? null;
    }

    public function username(): ?string
    {
        return $this->claims['preferred_username'] ?? null;
    }

    public function name(): ?string
    {
        $name = $this->claims['name'] ?? trim(($this->claims['given_name'] ?? '').' '.($this->claims['family_name'] ?? ''));

        return $name !== '' ? $name : null;
    }

    public function firstName(): ?string
    {
        return $this->claims['given_name'] ?? null;
    }

    public function lastName(): ?string
    {
        return $this->claims['family_name'] ?? null;
    }

    public function emailVerified(): bool
    {
        return (bool) ($this->claims['email_verified'] ?? false);
    }

    /** The client the token was issued to. */
    public function azp(): ?string
    {
        return $this->claims['azp'] ?? null;
    }

    public function issuer(): ?string
    {
        return $this->claims['iss'] ?? null;
    }

    /** @return array<int, string> */
    public function audience(): array
    {
        return array_values((array) ($this->claims['aud'] ?? []));
    }

    public function sessionId(): ?string
    {
        return $this->claims['sid'] ?? $this->claims['session_state'] ?? null;
    }

    /** True for tokens obtained with the client-credentials grant (machine-to-machine). */
    public function isServiceAccount(): bool
    {
        return str_starts_with((string) $this->username(), 'service-account-')
            || (isset($this->claims['client_id']) && ! isset($this->claims['email']));
    }

    /* ---------------------------------------------------------------
     | Lifetime
     * ------------------------------------------------------------- */

    public function expiresAt(): ?CarbonImmutable
    {
        return isset($this->claims['exp']) ? CarbonImmutable::createFromTimestamp((int) $this->claims['exp']) : null;
    }

    public function issuedAt(): ?CarbonImmutable
    {
        return isset($this->claims['iat']) ? CarbonImmutable::createFromTimestamp((int) $this->claims['iat']) : null;
    }

    /** Seconds until expiry (negative when expired, PHP_INT_MAX when no exp). */
    public function expiresIn(): int
    {
        return isset($this->claims['exp']) ? (int) $this->claims['exp'] - time() : PHP_INT_MAX;
    }

    public function isExpired(int $leeway = 0): bool
    {
        return $this->expiresIn() + $leeway <= 0;
    }

    /* ---------------------------------------------------------------
     | Roles, scopes and groups
     * ------------------------------------------------------------- */

    /** @return array<int, string> */
    public function realmRoles(): array
    {
        return array_values((array) ($this->claims['realm_access']['roles'] ?? []));
    }

    /**
     * Roles of one client, or (no argument) of the guard client(s) merged.
     *
     * @return array<int, string>
     */
    public function clientRoles(?string $client = null): array
    {
        $clients = $client !== null ? [$client] : $this->clients;
        $roles = [];

        foreach ($clients as $name) {
            foreach ((array) ($this->claims['resource_access'][$name]['roles'] ?? []) as $role) {
                $roles[] = $role;
            }
        }

        return array_values(array_unique($roles));
    }

    /**
     * Every role of every client, keyed by client id.
     *
     * @return array<string, array<int, string>>
     */
    public function allClientRoles(): array
    {
        return array_map(
            static fn ($access) => array_values((array) ($access['roles'] ?? [])),
            (array) ($this->claims['resource_access'] ?? []),
        );
    }

    /**
     * Realm roles + guard client roles.
     *
     * @return array<int, string>
     */
    public function roles(): array
    {
        return array_values(array_unique([...$this->realmRoles(), ...$this->clientRoles()]));
    }

    /**
     * True when the token has the role as a realm role or a guard-client role.
     * Use "client-id:role" to check a role of a specific client.
     */
    public function hasRole(string|BackedEnum|UnitEnum $role): bool
    {
        $role = self::normalize($role);

        if (in_array($role, $this->roles(), true)) {
            return true;
        }

        if (str_contains($role, ':')) {
            [$client, $clientRole] = explode(':', $role, 2);

            return in_array($clientRole, $this->clientRoles($client), true);
        }

        return false;
    }

    /** @param  iterable<string|BackedEnum|UnitEnum>|string|BackedEnum|UnitEnum  $roles */
    public function hasAnyRole(iterable|string|BackedEnum|UnitEnum $roles): bool
    {
        foreach (self::list($roles) as $role) {
            if ($this->hasRole($role)) {
                return true;
            }
        }

        return false;
    }

    /** @param  iterable<string|BackedEnum|UnitEnum>|string|BackedEnum|UnitEnum  $roles */
    public function hasAllRoles(iterable|string|BackedEnum|UnitEnum $roles): bool
    {
        foreach (self::list($roles) as $role) {
            if (! $this->hasRole($role)) {
                return false;
            }
        }

        return true;
    }

    public function hasRealmRole(string|BackedEnum|UnitEnum $role): bool
    {
        return in_array(self::normalize($role), $this->realmRoles(), true);
    }

    public function hasClientRole(string|BackedEnum|UnitEnum $role, ?string $client = null): bool
    {
        return in_array(self::normalize($role), $this->clientRoles($client), true);
    }

    /** @return array<int, string> */
    public function scopes(): array
    {
        $scope = $this->claims['scope'] ?? '';

        return is_array($scope) ? array_values($scope) : array_values(array_filter(explode(' ', (string) $scope)));
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes(), true);
    }

    /** @param  iterable<string>|string  $scopes */
    public function hasAnyScope(iterable|string $scopes): bool
    {
        foreach (self::list($scopes) as $scope) {
            if ($this->hasScope((string) $scope)) {
                return true;
            }
        }

        return false;
    }

    /** @param  iterable<string>|string  $scopes */
    public function hasAllScopes(iterable|string $scopes): bool
    {
        foreach (self::list($scopes) as $scope) {
            if (! $this->hasScope((string) $scope)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Group paths from the `groups` claim (needs a "Group Membership" mapper).
     *
     * @return array<int, string>
     */
    public function groups(): array
    {
        return array_values((array) ($this->claims['groups'] ?? []));
    }

    /** Accepts "/parent/child", "child" or "parent/child". */
    public function inGroup(string $group): bool
    {
        $wanted = '/'.trim($group, '/');

        foreach ($this->groups() as $path) {
            $path = '/'.trim((string) $path, '/');

            if ($path === $wanted || str_ends_with($path, $wanted)) {
                return true;
            }
        }

        return false;
    }

    /* ---------------------------------------------------------------
     | Serialization
     * ------------------------------------------------------------- */

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return $this->claims;
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->claims;
    }

    public static function normalize(mixed $value): string
    {
        return match (true) {
            $value instanceof BackedEnum => (string) $value->value,
            $value instanceof UnitEnum => $value->name,
            default => (string) $value,
        };
    }

    /**
     * @param  iterable<mixed>|string|BackedEnum|UnitEnum  $values
     * @return array<int, string>
     */
    protected static function list(iterable|string|BackedEnum|UnitEnum $values): array
    {
        if (is_string($values)) {
            return array_values(array_filter(array_map('trim', explode(',', $values))));
        }

        if (! is_iterable($values)) {
            return [self::normalize($values)];
        }

        $list = [];
        foreach ($values as $value) {
            $list[] = self::normalize($value);
        }

        return $list;
    }
}
