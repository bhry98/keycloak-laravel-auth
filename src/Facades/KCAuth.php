<?php

namespace Bhry98\KeycloakAuth\Facades;

use BackedEnum;
use Bhry98\KeycloakAuth\KeycloakManager;
use Illuminate\Support\Facades\Auth;
use UnitEnum;

/**
 * The Auth facade plus Keycloak role helpers (1.x API).
 */
class KCAuth extends Auth
{
    /** @return array<int, string> */
    public static function userRoles(): array
    {
        return array_values(array_unique(array_merge(self::userRealmRoles(), self::userClientRoles())));
    }

    /** @return array<int, string> */
    public static function userRealmRoles(): array
    {
        return app(KeycloakManager::class)->token()?->realmRoles()
            ?? (array) data_get(self::user(), 'realm_roles', []);
    }

    /** @return array<int, string> */
    public static function userClientRoles(): array
    {
        return app(KeycloakManager::class)->token()?->clientRoles()
            ?? (array) data_get(self::user(), 'client_roles', []);
    }

    /**
     * True when the user has at least one of the roles.
     *
     * @param  array<int, string|BackedEnum|UnitEnum>  $roles
     */
    public static function hasAccess(array $roles, bool $inClientRoleOnly = false): bool
    {
        $normalized = array_map(
            fn ($role) => $role instanceof BackedEnum ? (string) $role->value : ($role instanceof UnitEnum ? $role->name : (string) $role),
            $roles,
        );

        $granted = $inClientRoleOnly ? self::userClientRoles() : self::userRoles();

        return array_intersect($normalized, $granted) !== [];
    }
}
