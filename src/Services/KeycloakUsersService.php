<?php

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\Models\KCUserModel;
use Exception;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class KeycloakUsersService
{
    protected string $baseUrl;
    protected string $realm;
    protected string $clientId;
    protected string $clientSecret;
    protected string $adminRealm;
    protected string $adminClientId;
    protected string $adminClientSecret;

    public function __construct()
    {
        $this->baseUrl = config('bhry98-keycloak.base_url');
        $this->adminRealm = config('bhry98-keycloak.guard.admin.realm');
        $this->adminClientId = config('bhry98-keycloak.guard.admin.client_id');
        $this->adminClientSecret = config('bhry98-keycloak.guard.admin.client_secret');//"M3ppX6hPRMeAKRDkuS5f1xS9tO80dXvj";

//        $this->realm = config('bhry98-keycloak.realm');
//        $this->clientId = config('bhry98-keycloak.client_id');
//        $this->clientSecret = config('bhry98-keycloak.client_secret');

    }

    public static function guard(string $guard = 'web'): static
    {
        return (new static())->make($guard);
    }

    public function make(string $guard): static
    {
        if (in_array($guard, array_keys(config('bhry98-keycloak.guard', [])))) {
            $this->realm = config("bhry98-keycloak.guard.{$guard}.realm");
            $this->clientId = config("bhry98-keycloak.guard.{$guard}.client_id");
            $this->clientSecret = config("bhry98-keycloak.guard.{$guard}.client_secret");
        } else {
            $this->realm = config('bhry98-keycloak.realm');
            $this->clientId = config('bhry98-keycloak.client_id');
            $this->clientSecret = config('bhry98-keycloak.client_secret');
        }
        return $this;
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
     * @throws ConnectionException
     * @throws Exception
     */
    public function createUser(array $data): int
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->post("{$this->baseUrl}/admin/realms/{$this->realm}/users", [
                'username' => $data['username'],
                'email' => $data['email'],
                'firstName' => $data['first_name'] ?? '',
                'lastName' => $data['last_name'] ?? '',
                'enabled' => true,
                'credentials' => [
                    [
                        'type' => 'password',
                        'value' => $data['password'],
                        'temporary' => false,
                    ],
                ],
            ]);
        if ($response->failed()) {
            throw new \Exception('Failed to create user: ' . $response->body());
        }
        return $response->status();
    }

    /**
     * @throws ConnectionException
     */
    public function getUserByEmail(string $email)
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->realm}/users", ['email' => $email]);
        return $response->json();
    }

    /**
     * @throws ConnectionException
     * @throws Exception
     */
    public function syncUserFromKCByEmail(?string $email, ?string $type = null): ?KCUserModel
    {
        if (!$email) return null;
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->get("{$this->baseUrl}/admin/realms/{$this->realm}/users", ['email' => $email]);
        if ($response->failed()) {
            throw new \Exception('Failed to sync user from KC by email: ' . $response->body());
        }
        $data = $response->json()[0] ?? null;
        if (!$data) return null;
        $localUser = KCUserModel::query()
            ->updateOrCreate(
                ['email' => Arr::get($data, 'email')],
                [
//                    'global_id' => Arr::get($data, 'global_id'),
                    "keycloak_id" => Arr::get($data, 'id'),
                    "keycloak_realm" => $this->realm,
                    "first_name" => Arr::get($data, 'firstName'),
                    "last_name" => Arr::get($data, 'lastName'),
                    "name" => trim(Arr::get($data, 'firstName') . " " . Arr::get($data, 'lastName'), " "),
                    "email" => Arr::get($data, 'email'),
                    "email_verified" => Arr::get($data, 'emailVerified'),
                    "type" => $type,
                ]
            );
        return $localUser->refresh();
    }

    /**
     * @throws ConnectionException
     */
    public function updateUser(string $id, array $data): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->put("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$id}", $data);
        return $response->ok();
    }

    /**
     * @throws ConnectionException
     */
    public function deleteUser(string $id): bool
    {
        $token = $this->getAdminToken();
        $response = Http::withToken($token)
            ->delete("{$this->baseUrl}/admin/realms/{$this->realm}/users/{$id}");
        return $response->ok();
    }

    /**
     * @throws ConnectionException
     * @throws Exception
     */
    public function syncAllUsers(?string $defaultType = null): void
    {
        $token = $this->getAdminToken();
        $users = [];
        $first = 0;
        $max = 50;
        do {
            $response = Http::withToken($token)
                ->get("{$this->baseUrl}/admin/realms/{$this->realm}/users", [
                    'first' => $first,
                    'max' => $max,
                ]);
//            dd(
//                $token,
//                "{$this->baseUrl}/admin/realms/{$this->realm}/users"
//            );
            if ($response->failed()) {
                throw new Exception("Failed to fetch users: " . $response->body());
            }
            $pageUsers = $response->json();
            $count = count($pageUsers);
            if ($count === 0) {
                break;
            }
//            dd($pageUsers[0]['email']);
//            break;
            foreach ($pageUsers as $kcUser) {
                $email = Arr::get($kcUser, 'email');
                if (empty($email)) {
                    logger()->warning('Skipped user with no email', ['user' => $kcUser]);
                    continue;
                }
                KCUserModel::query()->updateOrCreate(
                    [
                        'email' => $kcUser['email']
                    ],
                    [
                        'email' => $kcUser['email'],
//                        'global_id' => Arr::get($kcUser, 'global_id'),
                        'keycloak_id' => $kcUser['id'],
                        "keycloak_realm" => $this->realm,
                        "first_name" => Arr::get($kcUser, 'firstName'),
                        "last_name" => Arr::get($kcUser, 'lastName'),
                        "name" => trim(Arr::get($kcUser, 'firstName') . " " . Arr::get($kcUser, 'lastName'), " "),
                        "email_verified" => Arr::get($kcUser, 'emailVerified', default: false),
                        "account_enable" => Arr::get($kcUser, 'enabled', default: true),
                        'username' => Arr::get($kcUser, 'username'),
                        "type" => $defaultType,
                    ]
                );
            }
            $users = array_merge($users, $pageUsers);
            $first += $max;
        } while ($count === $max);
        logger()->info('✅ Synced users from Keycloak', ['total' => count($users)]);
    }
}
