<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin\Resources;

use Bhry98\KeycloakAuth\Admin\AdminClient;
use Generator;
use Illuminate\Support\LazyCollection;

abstract class Resource
{
    public function __construct(protected AdminClient $client) {}

    protected static function seg(string $value): string
    {
        return rawurlencode($value);
    }

    /**
     * Iterate a paginated listing without loading everything in memory.
     *
     * @param  array<string, mixed>  $query
     * @return LazyCollection<int, array<string, mixed>>
     */
    protected function paginate(string $path, array $query, int $chunk): LazyCollection
    {
        return LazyCollection::make(function () use ($path, $query, $chunk): Generator {
            $first = (int) ($query['first'] ?? 0);

            do {
                $page = (array) $this->client->get($path, [...$query, 'first' => $first, 'max' => $chunk]);

                foreach ($page as $item) {
                    yield $item;
                }

                $first += $chunk;
            } while (count($page) === $chunk);
        });
    }

    /**
     * Role names (or representations) => role representations.
     *
     * @param  array<int, string|array<string, mixed>>|string  $roles
     * @return array<int, array<string, mixed>>
     */
    protected function realmRoleRepresentations(array|string $roles): array
    {
        return array_map(
            fn ($role) => is_array($role) ? $role : $this->client->roles()->find((string) $role),
            array_values((array) $roles),
        );
    }

    /**
     * @param  array<int, string|array<string, mixed>>|string  $roles
     * @return array<int, array<string, mixed>>
     */
    protected function clientRoleRepresentations(string $clientId, array|string $roles): array
    {
        return array_map(
            fn ($role) => is_array($role) ? $role : $this->client->clients()->role($clientId, (string) $role),
            array_values((array) $roles),
        );
    }
}
