<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin\Resources;

use Bhry98\KeycloakAuth\Exceptions\AdminApiException;

/**
 * Realm roles of the target realm. For client roles see Clients.
 */
class Roles extends Resource
{
    /** @var array<string, array<string, mixed>> */
    protected array $found = [];

    /**
     * @param  array<string, mixed>  $query  search, first, max, briefRepresentation
     * @return array<int, array<string, mixed>>
     */
    public function all(array $query = []): array
    {
        return (array) $this->client->get('roles', $query);
    }

    /** @return array<int, string> */
    public function names(): array
    {
        return array_column($this->all(['briefRepresentation' => 'true']), 'name');
    }

    /**
     * Role representation by name (memoized for the lifetime of this object).
     *
     * @return array<string, mixed>
     */
    public function find(string $name): array
    {
        return $this->found[$name] ??= (array) $this->client->get('roles/'.self::seg($name));
    }

    public function exists(string $name): bool
    {
        if (isset($this->found[$name])) {
            return true;
        }

        $response = $this->client->send('GET', 'roles/'.self::seg($name), throw: false);

        if ($response->status() === 404) {
            return false;
        }

        if ($response->failed()) {
            throw AdminApiException::fromResponse('Keycloak admin GET role failed', $response);
        }

        $this->found[$name] = (array) $response->json();

        return true;
    }

    /** @param  array<string, mixed>  $attributes */
    public function create(string $name, ?string $description = null, array $attributes = []): bool
    {
        $this->client->post('roles', array_filter([
            'name' => $name,
            'description' => $description,
            'attributes' => $attributes ? array_map(fn ($v) => array_values((array) $v), $attributes) : null,
        ], fn ($v) => $v !== null));

        return true;
    }

    /** Create the role unless it already exists. Returns true when it was created. */
    public function firstOrCreate(string $name, ?string $description = null): bool
    {
        return $this->exists($name) ? false : $this->create($name, $description);
    }

    /** @param  array<string, mixed>  $data */
    public function update(string $name, array $data): bool
    {
        $this->client->put('roles/'.self::seg($name), [...$this->find($name), ...$data]);
        unset($this->found[$name]);

        return true;
    }

    public function delete(string $name): bool
    {
        $this->client->delete('roles/'.self::seg($name));
        unset($this->found[$name]);

        return true;
    }

    /**
     * Users that have the role directly.
     *
     * @return array<int, array<string, mixed>>
     */
    public function users(string $name, int $first = 0, int $max = 100): array
    {
        return (array) $this->client->get('roles/'.self::seg($name).'/users', ['first' => $first, 'max' => $max]);
    }

    /** @return array<int, array<string, mixed>> */
    public function groups(string $name, int $first = 0, int $max = 100): array
    {
        return (array) $this->client->get('roles/'.self::seg($name).'/groups', ['first' => $first, 'max' => $max]);
    }

    /**
     * Make the role a composite of other realm roles.
     *
     * @param  array<int, string>|string  $roles
     */
    public function addComposites(string $name, array|string $roles): bool
    {
        $this->client->post('roles/'.self::seg($name).'/composites', $this->realmRoleRepresentations($roles));

        return true;
    }

    /** @return array<int, array<string, mixed>> */
    public function composites(string $name): array
    {
        return (array) $this->client->get('roles/'.self::seg($name).'/composites');
    }
}
