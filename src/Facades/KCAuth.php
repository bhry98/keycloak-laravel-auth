<?php

namespace Bhry98\KeycloakAuth\Facades;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;

class KCAuth extends Auth
{
    /**
     * @return array
     *
     * this function get all users roles from keycloak
     *
     * @author Bhr Abdelrahman
     */
    public static function userRoles(): array
    {
        return array_merge(self::userRealmRoles(), self::userClientRoles());
    }

    /**
     * @return array
     *
     * this function get all users Realm roles from keycloak
     *
     * @author Bhr Abdelrahman
     */
    public static function userRealmRoles(): array
    {
        return self::user()?->realm_roles ?? [];
    }

    /**
     * @return array
     *
     * this function get all users Client roles from keycloak
     *
     * @author Bhr Abdelrahman
     */
    public static function userClientRoles(): array
    {
        return self::user()?->client_roles ?? [];
    }


    /**
     * @param array $roles
     * @param bool $inClientRoleOnly
     * @return bool
     *
     * this function check if user hase ability access From `self::userRoles` function
     *
     * @author Bhr Abdelrahman
     */
    public static function hasAccess(array $roles, bool $inClientRoleOnly = false): bool
    {
        $normalized = array_map(function ($role) {
            return $role instanceof \BackedEnum
                ? $role->value
                : ($role instanceof \UnitEnum ? $role->name : $role);
        }, $roles);
        if ($inClientRoleOnly) {
            return !empty(array_intersect($normalized, self::userClientRoles()));
        }
        return !empty(array_intersect($normalized, self::userRoles()));
    }
}