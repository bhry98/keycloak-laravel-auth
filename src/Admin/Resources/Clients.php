<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin\Resources;

use Bhry98\KeycloakAuth\Admin\AdminClient;
use Bhry98\KeycloakAuth\Exceptions\AdminApiException;

/**
 * Clients of the target realm and their roles.
 *
 * Every method takes the human `clientId` (e.g. "my-app"); the internal
 * UUID lookup is cached, so it costs one request per client per day.
 */
class Clients extends Resource
{
    /** @var array<string, string> */
    protected array $uuids = [];

    /** @var array<string, array<string, mixed>> */
    protected array $roleCache = [];

    /**
     * @param  array<string, mixed>  $query  clientId, search, first, max
     * @return array<int, array<string, mixed>>
     */
    public function all(array $query = []): array
    {
        return (array) $this->client->get('clients', $query);
    }

    /** @return array<string, mixed>|null */
    public function findByClientId(string $clientId): ?array
    {
        return $this->all(['clientId' => $clientId])[0] ?? null;
    }

    /** Internal UUID of a client (cached). */
    public function uuid(string $clientId): string
    {
        if (isset($this->uuids[$clientId])) {
            return $this->uuids[$clientId];
        }

        $keycloak = $this->client->keycloak();
        $key = $keycloak->cachePrefix().':client_uuid:'.md5($this->client->realmName().'|'.$clientId);

        $uuid = $keycloak->cache()->get($key);

        if (! is_string($uuid) || $uuid === '') {
            $uuid = (string) ($this->findByClientId($clientId)['id'] ?? '');

            if ($uuid === '') {
                throw new AdminApiException("Keycloak client [{$clientId}] not found in realm [{$this->client->realmName()}].", 404);
            }

            $keycloak->cache()->put($key, $uuid, 86400);
        }

        return $this->uuids[$clientId] = $uuid;
    }

    /** @return array<string, mixed> */
    public function find(string $clientId): array
    {
        return (array) $this->client->get('clients/'.self::seg($this->uuid($clientId)));
    }

    /**
     * Create a client and return its UUID.
     *
     * @param  array<string, mixed>  $representation  ClientRepresentation (clientId is required)
     */
    public function create(array $representation): string
    {
        $response = $this->client->post('clients', $representation);

        return (string) AdminClient::createdId($response);
    }

    /** @param  array<string, mixed>  $data */
    public function update(string $clientId, array $data): bool
    {
        $this->client->put('clients/'.self::seg($this->uuid($clientId)), [...$this->find($clientId), ...$data]);

        return true;
    }

    public function delete(string $clientId): bool
    {
        $this->client->delete('clients/'.self::seg($this->uuid($clientId)));
        unset($this->uuids[$clientId]);

        return true;
    }

    public function secret(string $clientId): ?string
    {
        return $this->client->get('clients/'.self::seg($this->uuid($clientId)).'/client-secret')['value'] ?? null;
    }

    public function regenerateSecret(string $clientId): ?string
    {
        return $this->client->post('clients/'.self::seg($this->uuid($clientId)).'/client-secret')->json('value');
    }

    /**
     * The user behind a client's service account.
     *
     * @return array<string, mixed>
     */
    public function serviceAccountUser(string $clientId): array
    {
        return (array) $this->client->get('clients/'.self::seg($this->uuid($clientId)).'/service-account-user');
    }

    /** @return array<int, array<string, mixed>> */
    public function sessions(string $clientId, int $first = 0, int $max = 100): array
    {
        return (array) $this->client->get('clients/'.self::seg($this->uuid($clientId)).'/user-sessions', ['first' => $first, 'max' => $max]);
    }

    /* ---------------------------------------------------------------
     | Client roles
     * ------------------------------------------------------------- */

    /** @return array<int, array<string, mixed>> */
    public function roles(string $clientId): array
    {
        return (array) $this->client->get('clients/'.self::seg($this->uuid($clientId)).'/roles');
    }

    /** @return array<string, mixed> */
    public function role(string $clientId, string $role): array
    {
        return $this->roleCache[$clientId.'|'.$role] ??= (array) $this->client->get(
            'clients/'.self::seg($this->uuid($clientId)).'/roles/'.self::seg($role)
        );
    }

    public function createRole(string $clientId, string $role, ?string $description = null): bool
    {
        $this->client->post('clients/'.self::seg($this->uuid($clientId)).'/roles', array_filter([
            'name' => $role,
            'description' => $description,
        ], fn ($v) => $v !== null));

        return true;
    }

    public function deleteRole(string $clientId, string $role): bool
    {
        $this->client->delete('clients/'.self::seg($this->uuid($clientId)).'/roles/'.self::seg($role));
        unset($this->roleCache[$clientId.'|'.$role]);

        return true;
    }

    /** @return array<int, array<string, mixed>> */
    public function roleUsers(string $clientId, string $role, int $first = 0, int $max = 100): array
    {
        return (array) $this->client->get(
            'clients/'.self::seg($this->uuid($clientId)).'/roles/'.self::seg($role).'/users',
            ['first' => $first, 'max' => $max],
        );
    }
}
