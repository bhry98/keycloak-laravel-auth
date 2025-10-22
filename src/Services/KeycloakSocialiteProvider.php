<?php

namespace Bhry98\KeycloakAuth\Services;

use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\User;
use Laravel\Socialite\Two\ProviderInterface;

class KeycloakSocialiteProvider extends AbstractProvider implements ProviderInterface
{
    protected $scopeSeparator = ' ';
    protected $scopes = ['openid', 'email', 'profile'];

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase(
            config('bhry98-keycloak.base_url') . '/realms/' . config('bhry98-keycloak.realm') . '/protocol/openid-connect/auth',
            $state
        );
    }

    protected function getTokenUrl(): string
    {
        return config('bhry98-keycloak.base_url') . '/realms/' . config('bhry98-keycloak.realm') . '/protocol/openid-connect/token';
    }

    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get(
            config('bhry98-keycloak.base_url') . '/realms/' . config('bhry98-keycloak.realm') . '/protocol/openid-connect/userinfo',
            ['headers' => ['Authorization' => 'Bearer ' . $token]]
        );

        return json_decode($response->getBody()->getContents(), true);
    }

    protected function mapUserToObject(array $user): User
    {
        return (new User())->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => $user['preferred_username'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['picture'] ?? null,
        ]);
    }

    protected function getTokenFields($code): array
    {
        return array_merge(parent::getTokenFields($code), [
            'client_secret' => config('bhry98-keycloak.client_secret'),
        ]);
    }
}
