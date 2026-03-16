<?php

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\Helpers\KeycloakBaseService;
use Bhry98\KeycloakAuth\Models\KCUserModel;
use Exception;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Http;

class KeycloakUsersService extends KeycloakBaseService
{
    /* =========================================================
     *  PUBLIC API
     * ========================================================= */

    /**
     * Create new user
     */
    public function create(array $data): KCUserModel
    {
        $token = $this->getAdminToken();

        $payload = $this->buildPayload($data);

        $response = Http::withToken($token)
            ->post("{$this->baseUrl}/admin/realms/{$this->realm}/users", $payload);

        if ($response->failed()) {
            throw new Exception("Failed to create user: " . $response->body());
        }

        $location = $response->header('Location');
        $id = basename($location);

        return $this->syncById($id, Arr::get($data, 'type'));
    }

    /**
     * Update user
     */
    public function update(string $id, array $data): KCUserModel
    {
        $this->updateKeycloakUser($id, $data);

        return $this->syncById($id, Arr::get($data, 'type'));
    }

    /**
     * Create or Update
     */
    public function createOrUpdate(array $data): KCUserModel
    {
        $email = Arr::get($data, 'email');

        if (!$email) {
            throw new Exception("Email is required.");
        }

        $existing = $this->findByEmail($email);

        if ($existing) {
            return $this->update($existing['id'], $data);
        }

        return $this->create($data);
    }

    /**
     * Delete user
     */
    public function delete(string $id): bool
    {
        $token = $this->getAdminToken();

        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$id}");

        return $response->ok();
    }

    /**
     * Reset password
     */
    public function resetPassword(string $id, string $password, bool $temporary = false): KCUserModel
    {
        $token = $this->getAdminToken();

        $response = Http::withToken($token)
            ->put("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$id}/reset-password", [
                'type' => 'password',
                'value' => $password,
                'temporary' => $temporary,
            ]);

        if ($response->failed()) {
            throw new Exception("Failed to reset password: " . $response->body());
        }

        return $this->syncById($id);
    }

    /**
     * Enable / Disable user
     */
    public function setStatus(string $id, bool $enabled): KCUserModel
    {
        $this->updateKeycloakUser($id, ['enabled' => $enabled]);

        return $this->syncById($id);
    }

    /* =========================================================
     *  INTERNAL METHODS
     * ========================================================= */

    protected function updateKeycloakUser(string $id, array $data): void
    {
        $token = $this->getAdminToken();

        $payload = $this->buildPayload($data);

        $response = Http::withToken($token)
            ->put("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$id}", $payload);

        if ($response->failed()) {
            throw new Exception("Failed to update user: " . $response->body());
        }
    }

    protected function buildPayload(array $data): array
    {
        $payload = [
            'username'  => Arr::get($data, 'username'),
            'email'     => Arr::get($data, 'email'),
            'firstName' => Arr::get($data, 'first_name'),
            'lastName'  => Arr::get($data, 'last_name'),
            'enabled'   => Arr::boolean($data, 'enabled', true),
        ];

        if (Arr::has($data, 'password')) {
            $payload['credentials'] = [
                [
                    'type'      => 'password',
                    'value'     => Arr::get($data, 'password'),
                    'temporary' => Arr::get($data, 'temp_password', false),
                ],
            ];
        }

        return array_filter($payload, fn ($v) => !is_null($v));
    }

    protected function findByEmail(string $email): ?array
    {
        $token = $this->getAdminToken();

        $response = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->realm}/users", [
                'email' => $email,
            ]);

        if ($response->failed()) {
            throw new Exception("Failed to search user: " . $response->body());
        }

        return $response->json()[0] ?? null;
    }

    protected function syncById(string $id, ?string $type = null): KCUserModel
    {
        $kcUser = $this->fetchKeycloakUserById($id);

        return $this->syncFromKeycloakData($kcUser, $type);
    }

    protected function fetchKeycloakUserById(string $id): array
    {
        $token = $this->getAdminToken();

        $response = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$id}");

        if ($response->failed()) {
            throw new Exception("Failed to fetch user: " . $response->body());
        }

        return $response->json();
    }

    protected function syncFromKeycloakData(array $kcUser, ?string $type = null): KCUserModel
    {
        return KCUserModel::query()->updateOrCreate(
            ['email' => $kcUser['email']],
            [
                'email'            => $kcUser['email'],
                'username'         => $kcUser['username'],
                'keycloak_id'      => $kcUser['id'],
                'keycloak_realm'   => $this->realm,
                'first_name'       => Arr::get($kcUser, 'firstName'),
                'last_name'        => Arr::get($kcUser, 'lastName'),
                'name'             => trim(
                    Arr::get($kcUser, 'firstName') . ' ' . Arr::get($kcUser, 'lastName')
                ),
                'email_verified'   => Arr::get($kcUser, 'emailVerified', false),
                'account_enable'   => Arr::get($kcUser, 'enabled', true),
                'type'             => $type,
            ]
        )->refresh();
    }
}