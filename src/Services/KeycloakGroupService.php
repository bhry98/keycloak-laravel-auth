<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\Helpers\KeycloakBaseService;

/**
 * 1.x group service. New code: Keycloak::groups($guard).
 */
class KeycloakGroupService extends KeycloakBaseService
{
    /** @return array<int, array<string, mixed>> */
    public function getAllGroups(): array
    {
        return $this->admin()->groups()->all();
    }

    public function createGroup(string $name): bool
    {
        return $this->admin()->groups()->create($name) !== '';
    }

    public function deleteGroup(string $groupId): bool
    {
        return $this->admin()->groups()->delete($groupId);
    }

    public function addUserToGroup(string $userId, string $groupId): bool
    {
        return $this->admin()->users()->joinGroup($userId, $groupId);
    }

    public function removeUserFromGroup(string $userId, string $groupId): bool
    {
        return $this->admin()->users()->leaveGroup($userId, $groupId);
    }
}
