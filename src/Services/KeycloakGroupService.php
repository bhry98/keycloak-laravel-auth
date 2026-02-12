<?php

namespace Bhry98\KeycloakAuth\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Exception;

class KeycloakGroupService
{
    protected string $baseUrl;
    protected string $realm;
    protected string $adminRealm;
    protected string $adminClientId;
    protected string $adminClientSecret;

    public function __construct()
    {
        $this->baseUrl = config('bhry98-keycloak.base_url');
        $this->realm = config('bhry98-keycloak.realm');
        $this->adminRealm = config('bhry98-keycloak.guard.admin.realm');
        $this->adminClientId = config('bhry98-keycloak.guard.admin.client_id');
        $this->adminClientSecret = config('bhry98-keycloak.guard.admin.client_secret');
    }

    protected function getAdminToken(): ?string
    {
        return Cache::remember('keycloak_admin_token', 55, function () {
            $response = Http::asForm()->post("{$this->baseUrl}/realms/{$this->adminRealm}/protocol/openid-connect/token", [
                'client_id' => $this->adminClientId,
                'client_secret' => $this->adminClientSecret,
                'grant_type' => 'client_credentials',
            ]);
            return $response->json('access_token');
        });
    }

    /**
     * Get all groups in the realm
     *
     * @return array
     * @throws Exception
     */
    public function getAllGroups(): array
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->realm}/groups");

        if ($response->failed()) {
            throw new Exception('Failed to fetch groups: ' . $response->body());
        }

        return $response->json(); // Each group will have 'id', 'name', 'path', 'subGroups'
    }
    /**
     * Create a new group
     */
    public function createGroup(string $name): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->post("{$this->baseUrl}/admin/realms/{$this->realm}/groups", [
                'name' => $name
            ]);

        if ($response->failed()) {
            throw new Exception("Failed to create group: " . $response->body());
        }
dd($response->json());

        return $response->json();
    }

    /**
     * Delete a group by ID
     */
    public function deleteGroup(string $groupId): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->realm}/groups/{$groupId}");

        return $response->ok();
    }

    /**
     * Add a user to a group
     */
    public function addUserToGroup(string $userId, string $groupId): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->put("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$userId}/groups/{$groupId}");

        return $response->ok();
    }

    /**
     * Remove a user from a group
     */
    public function removeUserFromGroup(string $userId, string $groupId): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$userId}/groups/{$groupId}");

        return $response->ok();
    }
}
