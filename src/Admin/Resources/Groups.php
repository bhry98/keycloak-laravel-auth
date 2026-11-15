<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin\Resources;

use Bhry98\KeycloakAuth\Admin\AdminClient;
use Bhry98\KeycloakAuth\Exceptions\AdminApiException;
use Illuminate\Support\LazyCollection;

class Groups extends Resource
{
    /**
     * Top-level groups. Filters: search, q, exact, first, max, briefRepresentation.
     *
     * @param  array<string, mixed>  $query
     * @return array<int, array<string, mixed>>
     */
    public function all(array $query = []): array
    {
        return (array) $this->client->get('groups', $query);
    }

    /** @return array<int, array<string, mixed>> */
    public function search(string $term, bool $exact = false): array
    {
        return $this->all(['search' => $term, 'exact' => $exact ? 'true' : 'false']);
    }

    /** @param  array<string, mixed>  $query */
    public function count(array $query = []): int
    {
        return (int) ($this->client->get('groups/count', $query)['count'] ?? 0);
    }

    /** @return array<string, mixed>|null */
    public function find(string $id): ?array
    {
        return $this->nullOn404('groups/'.self::seg($id));
    }

    /**
     * Find by full path, e.g. "/company/engineering".
     *
     * @return array<string, mixed>|null
     */
    public function findByPath(string $path): ?array
    {
        $segments = array_map('rawurlencode', array_filter(explode('/', trim($path, '/')), fn (string $s) => $s !== ''));

        return $this->nullOn404('group-by-path/'.implode('/', $segments));
    }

    /**
     * Create a top-level group and return its id.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function create(string $name, array $attributes = []): string
    {
        $response = $this->client->post('groups', $this->representation($name, $attributes));

        return (string) AdminClient::createdId($response);
    }

    /**
     * Create a sub-group and return its id.
     *
     * @param  array<string, mixed>  $attributes
     */
    public function createChild(string $parentId, string $name, array $attributes = []): string
    {
        $response = $this->client->post('groups/'.self::seg($parentId).'/children', $this->representation($name, $attributes));

        return (string) (AdminClient::createdId($response) ?? $response->json('id'));
    }

    /**
     * @param  array<string, mixed>  $query  first, max, briefRepresentation
     * @return array<int, array<string, mixed>>
     */
    public function children(string $id, array $query = []): array
    {
        return (array) $this->client->get('groups/'.self::seg($id).'/children', $query);
    }

    /** @param  array<string, mixed>  $data */
    public function update(string $id, array $data): bool
    {
        $current = $this->find($id) ?? throw new AdminApiException("Keycloak group [{$id}] not found.", 404);
        unset($current['subGroups']);

        $this->client->put('groups/'.self::seg($id), [...$current, ...$data]);

        return true;
    }

    public function delete(string $id): bool
    {
        $this->client->delete('groups/'.self::seg($id));

        return true;
    }

    /* ---------------------------------------------------------------
     | Members
     * ------------------------------------------------------------- */

    /** @return array<int, array<string, mixed>> */
    public function members(string $id, int $first = 0, int $max = 100, bool $brief = true): array
    {
        return (array) $this->client->get('groups/'.self::seg($id).'/members', [
            'first' => $first,
            'max' => $max,
            'briefRepresentation' => $brief ? 'true' : 'false',
        ]);
    }

    /** @return LazyCollection<int, array<string, mixed>> */
    public function cursorMembers(string $id, int $chunk = 100): LazyCollection
    {
        return $this->paginate('groups/'.self::seg($id).'/members', ['briefRepresentation' => 'true'], $chunk);
    }

    public function addUser(string $groupId, string $userId): bool
    {
        return $this->client->users()->joinGroup($userId, $groupId);
    }

    public function removeUser(string $groupId, string $userId): bool
    {
        return $this->client->users()->leaveGroup($userId, $groupId);
    }

    /* ---------------------------------------------------------------
     | Roles
     * ------------------------------------------------------------- */

    /** @return array<int, array<string, mixed>> */
    public function realmRoles(string $id, bool $effective = false): array
    {
        return (array) $this->client->get('groups/'.self::seg($id).'/role-mappings/realm'.($effective ? '/composite' : ''));
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function assignRealmRoles(string $id, array|string $roles): bool
    {
        $this->client->post('groups/'.self::seg($id).'/role-mappings/realm', $this->realmRoleRepresentations($roles));

        return true;
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function removeRealmRoles(string $id, array|string $roles): bool
    {
        $this->client->delete('groups/'.self::seg($id).'/role-mappings/realm', $this->realmRoleRepresentations($roles));

        return true;
    }

    /** @return array<int, array<string, mixed>> */
    public function clientRoles(string $id, string $clientId): array
    {
        $uuid = $this->client->clients()->uuid($clientId);

        return (array) $this->client->get('groups/'.self::seg($id).'/role-mappings/clients/'.self::seg($uuid));
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function assignClientRoles(string $id, string $clientId, array|string $roles): bool
    {
        $uuid = $this->client->clients()->uuid($clientId);
        $this->client->post('groups/'.self::seg($id).'/role-mappings/clients/'.self::seg($uuid), $this->clientRoleRepresentations($clientId, $roles));

        return true;
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function removeClientRoles(string $id, string $clientId, array|string $roles): bool
    {
        $uuid = $this->client->clients()->uuid($clientId);
        $this->client->delete('groups/'.self::seg($id).'/role-mappings/clients/'.self::seg($uuid), $this->clientRoleRepresentations($clientId, $roles));

        return true;
    }

    /**
     * @param  array<string, mixed>  $attributes
     * @return array<string, mixed>
     */
    protected function representation(string $name, array $attributes): array
    {
        return array_filter([
            'name' => $name,
            'attributes' => $attributes ? array_map(fn ($v) => array_values(array_map('strval', (array) $v)), $attributes) : null,
        ], fn ($v) => $v !== null);
    }

    /** @return array<string, mixed>|null */
    protected function nullOn404(string $path): ?array
    {
        $response = $this->client->send('GET', $path, throw: false);

        if ($response->status() === 404) {
            return null;
        }

        if ($response->failed()) {
            throw AdminApiException::fromResponse("Keycloak admin GET [{$path}] failed", $response);
        }

        return $response->json();
    }
}
