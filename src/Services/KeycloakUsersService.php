<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\Exceptions\KeycloakException;
use Bhry98\KeycloakAuth\Helpers\KeycloakBaseService;
use Bhry98\KeycloakAuth\Models\KCUserModel;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;

/**
 * 1.x users service: manages a Keycloak user AND keeps the local users
 * table in sync. For raw Admin API access use Keycloak::users($guard).
 *
 *     KeycloakUsersService::guard('web')->create([...]);
 */
class KeycloakUsersService extends KeycloakBaseService
{
    /** @param  array<string, mixed>  $data */
    public function create(array $data): KCUserModel
    {
        $id = $this->admin()->users()->create($data);

        return $this->syncById($id, Arr::get($data, 'type'));
    }

    /** @param  array<string, mixed>  $data */
    public function update(string $id, array $data): KCUserModel
    {
        $this->admin()->users()->update($id, $data);

        return $this->syncById($id, Arr::get($data, 'type'));
    }

    /** @param  array<string, mixed>  $data */
    public function createOrUpdate(array $data): KCUserModel
    {
        $email = Arr::get($data, 'email');

        if (! $email) {
            throw new KeycloakException('Email is required.');
        }

        $existing = $this->findByEmail($email);

        return $existing ? $this->update($existing['id'], $data) : $this->create($data);
    }

    public function delete(string $id): bool
    {
        return $this->admin()->users()->delete($id);
    }

    public function resetPassword(string $id, string $password, bool $temporary = false): KCUserModel
    {
        $this->admin()->users()->resetPassword($id, $password, $temporary);

        return $this->syncById($id);
    }

    public function setStatus(string $id, bool $enabled): KCUserModel
    {
        $this->admin()->users()->update($id, ['enabled' => $enabled]);

        return $this->syncById($id);
    }

    /** @return array<string, mixed>|null */
    public function findByEmail(string $email): ?array
    {
        return $this->admin()->users()->findByEmail($email);
    }

    /** @return array<string, mixed>|null */
    public function find(string $id): ?array
    {
        return $this->admin()->users()->find($id);
    }

    public function syncById(string $id, ?string $type = null): KCUserModel
    {
        return $this->syncFromKeycloakData($this->admin()->users()->findOrFail($id), $type);
    }

    /** @param  array<string, mixed>  $kcUser */
    protected function syncFromKeycloakData(array $kcUser, ?string $type = null): KCUserModel
    {
        /** @var class-string<Model> $model */
        $model = config('bhry98-keycloak.users_model', KCUserModel::class);

        $attributes = array_filter([
            'email' => $kcUser['email'] ?? null,
            'username' => $kcUser['username'] ?? null,
            'keycloak_id' => $kcUser['id'],
            'keycloak_realm' => $this->realm,
            'first_name' => $kcUser['firstName'] ?? null,
            'last_name' => $kcUser['lastName'] ?? null,
            'name' => trim(($kcUser['firstName'] ?? '').' '.($kcUser['lastName'] ?? '')) ?: ($kcUser['username'] ?? ''),
            'email_verified' => (bool) ($kcUser['emailVerified'] ?? false),
            'account_enable' => (bool) ($kcUser['enabled'] ?? true),
            'type' => $type,
        ], fn ($v) => $v !== null);

        $user = $model::query()->where('keycloak_id', $kcUser['id'])->first()
            ?? (isset($attributes['email']) ? $model::query()->where('email', $attributes['email'])->first() : null)
            ?? new $model;

        $user->forceFill($attributes)->save();

        /** @var KCUserModel $user */
        return $user->refresh();
    }
}
