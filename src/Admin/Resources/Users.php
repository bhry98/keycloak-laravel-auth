<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin\Resources;

use Bhry98\KeycloakAuth\Admin\AdminClient;
use Bhry98\KeycloakAuth\Exceptions\AdminApiException;
use Illuminate\Support\Arr;
use Illuminate\Support\LazyCollection;

/**
 * Users of the target realm. Methods return Keycloak's JSON representations as arrays.
 */
class Users extends Resource
{
    /** snake_case input keys => Keycloak UserRepresentation keys. */
    protected const MAP = [
        'username' => 'username',
        'email' => 'email',
        'first_name' => 'firstName',
        'firstName' => 'firstName',
        'last_name' => 'lastName',
        'lastName' => 'lastName',
        'enabled' => 'enabled',
        'email_verified' => 'emailVerified',
        'emailVerified' => 'emailVerified',
        'attributes' => 'attributes',
        'groups' => 'groups',
        'required_actions' => 'requiredActions',
        'requiredActions' => 'requiredActions',
        'credentials' => 'credentials',
        'federation_link' => 'federationLink',
    ];

    /* ---------------------------------------------------------------
     | Read
     * ------------------------------------------------------------- */

    /**
     * Search / list users. Common filters: search, username, email, firstName,
     * lastName, enabled, emailVerified, exact, q ("attr:value"), first, max,
     * briefRepresentation.
     *
     * @param  array<string, mixed>  $query
     * @return array<int, array<string, mixed>>
     */
    public function all(array $query = []): array
    {
        return (array) $this->client->get('users', $query);
    }

    /** @return array<int, array<string, mixed>> */
    public function search(string $term, int $first = 0, int $max = 100): array
    {
        return $this->all(['search' => $term, 'first' => $first, 'max' => $max]);
    }

    /**
     * Lazily walk every matching user, page by page.
     *
     * @param  array<string, mixed>  $query
     * @return LazyCollection<int, array<string, mixed>>
     */
    public function cursor(array $query = [], int $chunk = 100): LazyCollection
    {
        return $this->paginate('users', $query, $chunk);
    }

    /** @param  array<string, mixed>  $query */
    public function count(array $query = []): int
    {
        return (int) $this->client->get('users/count', $query);
    }

    /** @return array<string, mixed>|null */
    public function find(string $id): ?array
    {
        $response = $this->client->send('GET', 'users/'.self::seg($id), throw: false);

        if ($response->status() === 404) {
            return null;
        }

        if ($response->failed()) {
            throw AdminApiException::fromResponse('Keycloak admin GET user failed', $response);
        }

        return $response->json();
    }

    /** @return array<string, mixed> */
    public function findOrFail(string $id): array
    {
        return $this->find($id) ?? throw new AdminApiException("Keycloak user [{$id}] not found.", 404);
    }

    /** @return array<string, mixed>|null */
    public function findByEmail(string $email): ?array
    {
        return $this->all(['email' => $email, 'exact' => 'true'])[0] ?? null;
    }

    /** @return array<string, mixed>|null */
    public function findByUsername(string $username): ?array
    {
        return $this->all(['username' => $username, 'exact' => 'true'])[0] ?? null;
    }

    /**
     * Find users by a custom attribute.
     *
     * @return array<int, array<string, mixed>>
     */
    public function findByAttribute(string $attribute, string $value): array
    {
        return $this->all(['q' => "{$attribute}:{$value}", 'exact' => 'true']);
    }

    /* ---------------------------------------------------------------
     | Write
     * ------------------------------------------------------------- */

    /**
     * Create a user and return its id.
     *
     * Accepts snake_case (first_name, last_name, email_verified, ...) or
     * Keycloak's camelCase keys, plus `password` / `temp_password`.
     *
     * @param  array<string, mixed>  $data
     */
    public function create(array $data): string
    {
        $payload = $this->payload($data);
        $payload['enabled'] ??= true;

        $response = $this->client->post('users', $payload);

        return AdminClient::createdId($response)
            ?? (string) ($this->findByUsername((string) ($payload['username'] ?? $payload['email'] ?? ''))['id'] ?? '');
    }

    /**
     * Partial update: only the keys you pass are changed.
     *
     * @param  array<string, mixed>  $data
     */
    public function update(string $id, array $data): bool
    {
        $this->client->put('users/'.self::seg($id), $this->payload($data));

        return true;
    }

    public function delete(string $id): bool
    {
        $this->client->delete('users/'.self::seg($id));

        return true;
    }

    public function enable(string $id): bool
    {
        return $this->update($id, ['enabled' => true]);
    }

    public function disable(string $id): bool
    {
        return $this->update($id, ['enabled' => false]);
    }

    public function resetPassword(string $id, string $password, bool $temporary = false): bool
    {
        $this->client->put('users/'.self::seg($id).'/reset-password', [
            'type' => 'password',
            'value' => $password,
            'temporary' => $temporary,
        ]);

        return true;
    }

    /**
     * Merge custom attributes into the user's existing ones (null removes a key).
     *
     * @param  array<string, mixed>  $attributes
     */
    public function setAttributes(string $id, array $attributes): bool
    {
        $user = $this->findOrFail($id);
        $current = (array) ($user['attributes'] ?? []);

        foreach ($attributes as $key => $value) {
            if ($value === null) {
                unset($current[$key]);
            } else {
                $current[$key] = array_values(array_map('strval', (array) $value));
            }
        }

        // Keycloak >= 24 (user profile) requires the core fields with the attributes.
        return $this->update($id, [
            ...Arr::only($user, ['username', 'email', 'firstName', 'lastName']),
            'attributes' => $current,
        ]);
    }

    /* ---------------------------------------------------------------
     | E-mails & required actions
     * ------------------------------------------------------------- */

    public function sendVerifyEmail(string $id, ?string $redirectUri = null, ?string $clientId = null): bool
    {
        $query = array_filter(['redirect_uri' => $redirectUri, 'client_id' => $clientId ?? ($redirectUri ? $this->client->keycloak()->realm()->clientId : null)]);
        $path = 'users/'.self::seg($id).'/send-verify-email'.($query ? '?'.http_build_query($query) : '');

        $this->client->put($path);

        return true;
    }

    /**
     * Send an "execute actions" e-mail, e.g. ['UPDATE_PASSWORD'], ['VERIFY_EMAIL'],
     * ['CONFIGURE_TOTP'], ['UPDATE_PROFILE'].
     *
     * @param  array<int, string>  $actions
     */
    public function executeActionsEmail(string $id, array $actions, ?int $lifespan = null, ?string $redirectUri = null, ?string $clientId = null): bool
    {
        $query = array_filter([
            'lifespan' => $lifespan,
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId ?? ($redirectUri ? $this->client->keycloak()->realm()->clientId : null),
        ]);
        $path = 'users/'.self::seg($id).'/execute-actions-email'.($query ? '?'.http_build_query($query) : '');

        $this->client->put($path, array_values($actions));

        return true;
    }

    public function sendResetPasswordEmail(string $id, ?int $lifespan = null, ?string $redirectUri = null): bool
    {
        return $this->executeActionsEmail($id, ['UPDATE_PASSWORD'], $lifespan, $redirectUri);
    }

    /* ---------------------------------------------------------------
     | Sessions & credentials
     * ------------------------------------------------------------- */

    /** @return array<int, array<string, mixed>> */
    public function sessions(string $id): array
    {
        return (array) $this->client->get('users/'.self::seg($id).'/sessions');
    }

    /** Sign the user out of every session. */
    public function logout(string $id): bool
    {
        $this->client->post('users/'.self::seg($id).'/logout');

        return true;
    }

    /** @return array<int, array<string, mixed>> */
    public function credentials(string $id): array
    {
        return (array) $this->client->get('users/'.self::seg($id).'/credentials');
    }

    public function deleteCredential(string $id, string $credentialId): bool
    {
        $this->client->delete('users/'.self::seg($id).'/credentials/'.self::seg($credentialId));

        return true;
    }

    /** @return array<int, array<string, mixed>> */
    public function federatedIdentities(string $id): array
    {
        return (array) $this->client->get('users/'.self::seg($id).'/federated-identity');
    }

    /* ---------------------------------------------------------------
     | Groups
     * ------------------------------------------------------------- */

    /** @return array<int, array<string, mixed>> */
    public function groups(string $id, bool $brief = true): array
    {
        return (array) $this->client->get('users/'.self::seg($id).'/groups', ['briefRepresentation' => $brief ? 'true' : 'false']);
    }

    public function joinGroup(string $id, string $groupId): bool
    {
        $this->client->put('users/'.self::seg($id).'/groups/'.self::seg($groupId));

        return true;
    }

    public function leaveGroup(string $id, string $groupId): bool
    {
        $this->client->delete('users/'.self::seg($id).'/groups/'.self::seg($groupId));

        return true;
    }

    /* ---------------------------------------------------------------
     | Roles
     * ------------------------------------------------------------- */

    /**
     * Realm roles assigned directly ($effective = include composite & group roles).
     *
     * @return array<int, array<string, mixed>>
     */
    public function realmRoles(string $id, bool $effective = false): array
    {
        return (array) $this->client->get('users/'.self::seg($id).'/role-mappings/realm'.($effective ? '/composite' : ''));
    }

    /** @return array<int, string> */
    public function realmRoleNames(string $id, bool $effective = true): array
    {
        return array_column($this->realmRoles($id, $effective), 'name');
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function assignRealmRoles(string $id, array|string $roles): bool
    {
        $this->client->post('users/'.self::seg($id).'/role-mappings/realm', $this->realmRoleRepresentations($roles));

        return true;
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function removeRealmRoles(string $id, array|string $roles): bool
    {
        $this->client->delete('users/'.self::seg($id).'/role-mappings/realm', $this->realmRoleRepresentations($roles));

        return true;
    }

    /**
     * @param  string  $clientId  the client's clientId (e.g. "my-app"), not its UUID
     * @return array<int, array<string, mixed>>
     */
    public function clientRoles(string $id, string $clientId, bool $effective = false): array
    {
        $uuid = $this->client->clients()->uuid($clientId);

        return (array) $this->client->get('users/'.self::seg($id).'/role-mappings/clients/'.self::seg($uuid).($effective ? '/composite' : ''));
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function assignClientRoles(string $id, string $clientId, array|string $roles): bool
    {
        $uuid = $this->client->clients()->uuid($clientId);
        $this->client->post('users/'.self::seg($id).'/role-mappings/clients/'.self::seg($uuid), $this->clientRoleRepresentations($clientId, $roles));

        return true;
    }

    /** @param  array<int, string|array<string, mixed>>|string  $roles */
    public function removeClientRoles(string $id, string $clientId, array|string $roles): bool
    {
        $uuid = $this->client->clients()->uuid($clientId);
        $this->client->delete('users/'.self::seg($id).'/role-mappings/clients/'.self::seg($uuid), $this->clientRoleRepresentations($clientId, $roles));

        return true;
    }

    /* ---------------------------------------------------------------
     | Payload
     * ------------------------------------------------------------- */

    /**
     * @param  array<string, mixed>  $data
     * @return array<string, mixed>
     */
    public function payload(array $data): array
    {
        $payload = [];

        foreach (self::MAP as $input => $key) {
            if (array_key_exists($input, $data) && $data[$input] !== null) {
                $payload[$key] = $data[$input];
            }
        }

        if (isset($payload['enabled'])) {
            $payload['enabled'] = filter_var($payload['enabled'], FILTER_VALIDATE_BOOLEAN);
        }

        if (isset($payload['emailVerified'])) {
            $payload['emailVerified'] = filter_var($payload['emailVerified'], FILTER_VALIDATE_BOOLEAN);
        }

        if (isset($payload['attributes'])) {
            $payload['attributes'] = array_map(
                static fn ($value) => array_values(array_map('strval', (array) $value)),
                (array) $payload['attributes'],
            );
        }

        if (isset($data['password']) && $data['password'] !== '') {
            $payload['credentials'] = [[
                'type' => 'password',
                'value' => (string) $data['password'],
                'temporary' => (bool) ($data['temp_password'] ?? $data['temporary_password'] ?? false),
            ]];
        }

        return $payload;
    }
}
