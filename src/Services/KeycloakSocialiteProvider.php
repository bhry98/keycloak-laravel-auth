<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User;

/**
 * Socialite driver for Keycloak (registered as "keycloak.{guard}").
 */
class KeycloakSocialiteProvider extends AbstractProvider implements ProviderInterface
{
    protected $scopeSeparator = ' ';

    protected $scopes = ['openid', 'email', 'profile'];

    protected string $guard = 'web';

    /** @var array<string, mixed> */
    protected array $lastTokenResponse = [];

    public function setGuard(string $guard): static
    {
        $this->guard = $guard;
        $this->scopes = $this->realmConfig()->scopes ?: $this->scopes;

        return $this;
    }

    public function guardName(): string
    {
        return $this->guard;
    }

    /**
     * Full token-endpoint answer of the last code exchange (includes id_token).
     *
     * @return array<string, mixed>
     */
    public function lastTokenResponse(): array
    {
        return $this->lastTokenResponse;
    }

    /**
     * Exchange the code through the package OIDC client (shared timeouts,
     * retries and Http::fake() support) and keep the full answer.
     *
     * @return array<string, mixed>
     */
    public function getAccessTokenResponse($code)
    {
        return $this->lastTokenResponse = app(KeycloakManager::class)->oidc($this->guard)->token($this->getTokenFields($code));
    }

    protected function realmConfig(): RealmConfig
    {
        return app(KeycloakManager::class)->realm($this->guard);
    }

    /** @deprecated kept for 1.x subclasses */
    protected function guardConfig(string $key): mixed
    {
        return config("bhry98-keycloak.guard.{$this->guard}.{$key}");
    }

    protected function realm(): string
    {
        return $this->realmConfig()->realm;
    }

    protected function base(): string
    {
        return $this->realmConfig()->baseUrl;
    }

    protected function getAuthUrl($state): string
    {
        return $this->buildAuthUrlFromBase($this->realmConfig()->openIdUrl('auth'), $state);
    }

    protected function getTokenUrl(): string
    {
        return $this->realmConfig()->openIdUrl('token');
    }

    /** @return array<string, mixed> */
    protected function getUserByToken($token)
    {
        return app(KeycloakManager::class)->oidc($this->guard)->userInfo((string) $token);
    }

    /** @param  array<string, mixed>  $user */
    protected function mapUserToObject(array $user): User
    {
        return (new User)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => $user['preferred_username'] ?? null,
            'name' => $user['name'] ?? null,
            'email' => $user['email'] ?? null,
            'avatar' => $user['picture'] ?? null,
        ]);
    }

    /** @return array<string, mixed> */
    protected function getTokenFields($code): array
    {
        return array_merge(parent::getTokenFields($code), array_filter([
            'client_secret' => $this->clientSecret ?: $this->realmConfig()->clientSecret,
        ]));
    }
}
