<?php

namespace Bhry98\KeycloakAuth\Helpers;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class KeycloakBaseService
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
}
