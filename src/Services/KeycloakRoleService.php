<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\Helpers\KeycloakBaseService;

/**
 * 1.x realm-role service. Without ::guard() it manages the admin guard's
 * realm, like 1.x did. New code: Keycloak::roles($guard) / Keycloak::users($guard).
 */
class KeycloakRoleService extends KeycloakBaseService
{
    protected function defaultGuard(): string
    {
        return array_key_exists('admin', (array) config('bhry98-keycloak.guard', [])) ? 'admin' : '__root';
    }

    public function createRole(string $roleName, ?string $description = null): bool
    {
        return $this->admin()->roles()->create($roleName, $description);
    }

    public function deleteRole(string $roleName): bool
    {
        return $this->admin()->roles()->delete($roleName);
    }

    /** @return array<int, array<string, mixed>> */
    public function getAllRoles(): array
    {
        return $this->admin()->roles()->all();
    }

    public function assignRoleToUser(string $userId, string $roleName): bool
    {
        return $this->admin()->users()->assignRealmRoles($userId, [$roleName]);
    }

    public function removeRoleFromUser(string $userId, string $roleName): bool
    {
        return $this->admin()->users()->removeRealmRoles($userId, [$roleName]);
    }

    public function assignRoleToGroup(string $groupId, string $roleName): bool
    {
        return $this->admin()->groups()->assignRealmRoles($groupId, [$roleName]);
    }

    public function removeRoleFromGroup(string $groupId, string $roleName): bool
    {
        return $this->admin()->groups()->removeRealmRoles($groupId, [$roleName]);
    }
}
