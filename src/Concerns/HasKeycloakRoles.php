<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Concerns;

use BackedEnum;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use UnitEnum;

/**
 * Role / scope / group checks for a user model, backed by the Keycloak
 * token of the current request (bearer token or web session).
 *
 * Add it to your User model: `use HasKeycloakRoles;`
 */
trait HasKeycloakRoles
{
    /** The current request's token, when it belongs to this user. */
    public function keycloakToken(): ?KeycloakToken
    {
        $token = app(KeycloakManager::class)->token();

        if ($token === null) {
            return null;
        }

        $id = $this->getAttributeValueSafely('keycloak_id');

        return $id === null || $id === $token->subject() ? $token : null;
    }

    public function hasRole(string|BackedEnum|UnitEnum $role): bool
    {
        return (bool) $this->keycloakToken()?->hasRole($role);
    }

    /** @param  iterable<string|BackedEnum|UnitEnum>|string|BackedEnum|UnitEnum  $roles */
    public function hasAnyRole(iterable|string|BackedEnum|UnitEnum $roles): bool
    {
        return (bool) $this->keycloakToken()?->hasAnyRole($roles);
    }

    /** @param  iterable<string|BackedEnum|UnitEnum>|string|BackedEnum|UnitEnum  $roles */
    public function hasAllRoles(iterable|string|BackedEnum|UnitEnum $roles): bool
    {
        return (bool) $this->keycloakToken()?->hasAllRoles($roles);
    }

    public function hasRealmRole(string|BackedEnum|UnitEnum $role): bool
    {
        return (bool) $this->keycloakToken()?->hasRealmRole($role);
    }

    public function hasClientRole(string|BackedEnum|UnitEnum $role, ?string $client = null): bool
    {
        return (bool) $this->keycloakToken()?->hasClientRole($role, $client);
    }

    public function hasScope(string $scope): bool
    {
        return (bool) $this->keycloakToken()?->hasScope($scope);
    }

    public function inGroup(string $group): bool
    {
        return (bool) $this->keycloakToken()?->inGroup($group);
    }

    /** @return array<int, string> */
    public function keycloakRoles(): array
    {
        return $this->keycloakToken()?->roles() ?? [];
    }

    /** @return array<int, string> */
    public function keycloakRealmRoles(): array
    {
        return $this->keycloakToken()?->realmRoles() ?? [];
    }

    /** @return array<int, string> */
    public function keycloakClientRoles(?string $client = null): array
    {
        return $this->keycloakToken()?->clientRoles($client) ?? [];
    }

    /** @return array<int, string> */
    public function keycloakGroups(): array
    {
        return $this->keycloakToken()?->groups() ?? [];
    }

    protected function getAttributeValueSafely(string $key): ?string
    {
        if (method_exists($this, 'getAttribute')) {
            $value = $this->getAttribute($key);

            return $value === null ? null : (string) $value;
        }

        return null;
    }
}
