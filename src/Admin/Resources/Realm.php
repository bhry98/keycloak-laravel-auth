<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin\Resources;

/**
 * Realm-level information and audit events.
 */
class Realm extends Resource
{
    /** @return array<string, mixed> */
    public function get(): array
    {
        return (array) $this->client->get('');
    }

    /**
     * Login events (requires "Save events" in the realm settings).
     *
     * @param  array<string, mixed>  $query  type, user, client, dateFrom, dateTo, ipAddress, first, max
     * @return array<int, array<string, mixed>>
     */
    public function events(array $query = []): array
    {
        return (array) $this->client->get('events', $query);
    }

    /**
     * @param  array<string, mixed>  $query  operationTypes, resourceTypes, authUser, dateFrom, dateTo, first, max
     * @return array<int, array<string, mixed>>
     */
    public function adminEvents(array $query = []): array
    {
        return (array) $this->client->get('admin-events', $query);
    }

    /**
     * Active session counts per client.
     *
     * @return array<int, array<string, mixed>>
     */
    public function clientSessionStats(): array
    {
        return (array) $this->client->get('client-session-stats');
    }

    /** Sign every user of the realm out. */
    public function logoutAll(): bool
    {
        $this->client->post('logout-all');

        return true;
    }
}
