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

    public static function guard(string $guard): static
    {
        return (new static())->make($guard);
    }

    public function make(string $guard): static
    {
        if (in_array($guard, ['api', 'admin', 'web'])) {
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
        Cache::delete("keycloak_admin_token");
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
    public function syncAllUsers(): void
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
                        "keycloak_id" => $kcUser['id'],
                        "first_name" => Arr::get($kcUser, 'firstName'),
                        "last_name" => Arr::get($kcUser, 'lastName'),
                        "name" => trim(Arr::get($kcUser, 'firstName') . " " . Arr::get($kcUser, 'lastName'), " "),
                        "email_verified" => Arr::get($kcUser, 'emailVerified', default: false),
                        "account_enable" => Arr::get($kcUser, 'enabled', default: true),
                        'username' => Arr::get($kcUser, 'username'),
                    ]
                );
            }
            $users = array_merge($users, $pageUsers);
            $first += $max;
        } while ($count === $max);
        logger()->info('✅ Synced users from Keycloak', ['total' => count($users)]);
    }
}
