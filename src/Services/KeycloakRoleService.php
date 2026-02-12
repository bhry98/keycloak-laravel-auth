<?php

namespace Bhry98\KeycloakAuth\Services;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Arr;
use Exception;
use Illuminate\Http\Client\ConnectionException;

class KeycloakRoleService
{
    protected string $baseUrl;
    protected string $realm;
    protected string $adminRealm;
    protected string $adminClientId;
    protected string $adminClientSecret;

    public function __construct()
    {
        $this->baseUrl = config('bhry98-keycloak.base_url');
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
     * Create a new realm role
     */
    public function createRole(string $roleName, ?string $description = null): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->post("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles", [
                'name' => $roleName,
                'description' => $description,
            ]);
        if ($response->failed()) {
            throw new Exception("Failed to create role: " . $response->body());
        }
        return true;
    }

    /**
     * Delete a realm role
     */
    public function deleteRole(string $roleName): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles/{$roleName}");
        return $response->ok();
    }

    /**
     * Assign a role to a user
     */
    public function assignRoleToUser(string $userId, string $roleName): bool
    {
        $token = $this->getAdminToken();

        // Get role details
        $role = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles/{$roleName}")
            ->json();

        $response = Http::withToken($token)
            ->post("{$this->baseUrl}/admin/realms/{$this->adminRealm}/users/{$userId}/role-mappings/realm", [
                $role
            ]);

        return $response->ok();
    }

    /**
     * Remove a role from a user
     */
    public function removeRoleFromUser(string $userId, string $roleName): bool
    {
        $token = $this->getAdminToken();

        // Get role details
        $role = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles/{$roleName}")
            ->json();

        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->adminRealm}/users/{$userId}/role-mappings/realm", [
                $role
            ]);

        return $response->ok();
    }

    /**
     * Assign a role to a group
     * @throws ConnectionException
     */
    public function assignRoleToGroup(string $groupId, string $roleName): bool
    {
        $token = $this->getAdminToken();

        $role = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles/{$roleName}")
            ->json();
//dd("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles/{$roleName}",$role);
        $response = Http::withToken($token)
            ->post("{$this->baseUrl}/admin/realms/{$this->adminRealm}/groups/{$groupId}/role-mappings/realm", [
                $role
            ]);
dd($response->json());
        return $response->ok();
    }

    /**
     * Remove a role from a group
     * @throws ConnectionException
     */
    public function removeRoleFromGroup(string $groupId, string $roleName): bool
    {
        $token = $this->getAdminToken();

        $role = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->adminRealm}/roles/{$roleName}")
            ->json();

        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->adminRealm}/groups/{$groupId}/role-mappings/realm", [
                $role
            ]);

        return $response->ok();
    }
}
