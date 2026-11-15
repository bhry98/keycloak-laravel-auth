<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Admin;

use Bhry98\KeycloakAuth\Admin\Resources\Clients;
use Bhry98\KeycloakAuth\Admin\Resources\Groups;
use Bhry98\KeycloakAuth\Admin\Resources\Realm;
use Bhry98\KeycloakAuth\Admin\Resources\Roles;
use Bhry98\KeycloakAuth\Admin\Resources\Users;
use Bhry98\KeycloakAuth\Exceptions\AdminApiException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Illuminate\Http\Client\Response;
use Throwable;

/**
 * Keycloak Admin REST API client for one target realm.
 *
 * The admin access token is obtained with the client credentials of the
 * `admin.guard` guard, cached for its real lifetime and shared by every
 * request / resource. A 401 answer refreshes it and retries once.
 */
class AdminClient
{
    /** @var array<string, object> */
    protected array $resources = [];

    public function __construct(
        protected KeycloakManager $keycloak,
        protected RealmConfig $target,
        protected RealmConfig $credentials,
    ) {}

    public function users(): Users
    {
        return $this->resources['users'] ??= new Users($this);
    }

    public function roles(): Roles
    {
        return $this->resources['roles'] ??= new Roles($this);
    }

    public function groups(): Groups
    {
        return $this->resources['groups'] ??= new Groups($this);
    }

    public function clients(): Clients
    {
        return $this->resources['clients'] ??= new Clients($this);
    }

    public function realm(): Realm
    {
        return $this->resources['realm'] ??= new Realm($this);
    }

    /** Name of the realm being managed. */
    public function realmName(): string
    {
        return $this->target->realm;
    }

    public function keycloak(): KeycloakManager
    {
        return $this->keycloak;
    }

    /* ---------------------------------------------------------------
     | Raw requests (paths are relative to /admin/realms/{realm})
     * ------------------------------------------------------------- */

    /** @param  array<string, mixed>  $query */
    public function get(string $path, array $query = []): mixed
    {
        return $this->send('GET', $path, $query)->json();
    }

    /** @param  array<mixed>  $data */
    public function post(string $path, array $data = []): Response
    {
        return $this->send('POST', $path, $data);
    }

    /** @param  array<mixed>  $data */
    public function put(string $path, array $data = []): Response
    {
        return $this->send('PUT', $path, $data);
    }

    /** @param  array<mixed>  $data */
    public function delete(string $path, array $data = []): Response
    {
        return $this->send('DELETE', $path, $data);
    }

    /**
     * @param  array<mixed>  $data  query string for GET, JSON body otherwise
     *
     * @throws AdminApiException
     */
    public function send(string $method, string $path, array $data = [], bool $throw = true): Response
    {
        $response = $this->attempt($method, $path, $data, false);

        if ($response->status() === 401) {
            $response = $this->attempt($method, $path, $data, true);
        }

        if ($throw && $response->failed()) {
            throw AdminApiException::fromResponse("Keycloak admin {$method} [{$path}] failed", $response);
        }

        return $response;
    }

    /** The cached admin access token. */
    public function token(bool $fresh = false): string
    {
        $key = $this->keycloak->cachePrefix().':admin_token:'.$this->credentials->fingerprint();
        $cache = $this->keycloak->cache();

        if (! $fresh && is_string($token = $cache->get($key)) && $token !== '') {
            return $token;
        }

        $result = $this->keycloak->oidc($this->credentials)->clientCredentials();
        $token = (string) $result['access_token'];
        $ttl = (int) ($result['expires_in'] ?? 60) - (int) $this->keycloak->config('admin.token_expiry_margin', 30);

        if ($ttl > 0) {
            $cache->put($key, $token, $ttl);
        }

        return $token;
    }

    public function forgetToken(): void
    {
        $this->keycloak->cache()->forget($this->keycloak->cachePrefix().':admin_token:'.$this->credentials->fingerprint());
    }

    /** @param  array<mixed>  $data */
    protected function attempt(string $method, string $path, array $data, bool $freshToken): Response
    {
        $url = $this->target->adminUrl($path);
        $request = $this->keycloak->http()->withToken($this->token($freshToken))->acceptJson();

        try {
            return match ($method) {
                'GET' => $request->get($url, $data),
                'POST' => $request->post($url, $data),
                'PUT' => $request->put($url, $data),
                'DELETE' => $request->delete($url, $data),
                default => $request->send($method, $url, ['json' => $data]),
            };
        } catch (Throwable $e) {
            throw new AdminApiException("Keycloak admin {$method} [{$path}] failed: {$e->getMessage()}", 0, $e);
        }
    }

    /** Id of the resource created by a POST (from its Location header). */
    public static function createdId(Response $response): ?string
    {
        $location = $response->header('Location');

        return $location !== '' ? basename(parse_url($location, PHP_URL_PATH) ?: $location) : null;
    }
}
