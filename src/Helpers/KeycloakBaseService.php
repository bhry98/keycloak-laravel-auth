<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Helpers;

use Bhry98\KeycloakAuth\Admin\AdminClient;
use Bhry98\KeycloakAuth\KeycloakManager;

/**
 * Base of the 1.x admin services. New code should use Keycloak::admin().
 */
class KeycloakBaseService
{
    protected string $baseUrl;

    protected string $realm;

    protected string $clientId;

    protected string $clientSecret;

    protected string $adminRealm;

    protected string $adminClientId;

    protected string $adminClientSecret;

    protected ?string $guardName = null;

    public function __construct()
    {
        $admin = $this->keycloak()->realm((string) config('bhry98-keycloak.admin.guard', 'admin'));

        $this->baseUrl = $admin->baseUrl;
        $this->adminRealm = $admin->realm;
        $this->adminClientId = $admin->clientId;
        $this->adminClientSecret = $admin->clientSecret;

        $this->make($this->defaultGuard());
    }

    public static function guard(string $guard = 'web'): static
    {
        return (new static)->make($guard);
    }

    public function make(string $guard): static
    {
        $known = array_key_exists($guard, (array) config('bhry98-keycloak.guard', []));
        $this->guardName = $known ? $guard : '__root';

        $realm = $this->keycloak()->realm($this->guardName);
        $this->realm = $realm->realm;
        $this->clientId = $realm->clientId;
        $this->clientSecret = $realm->clientSecret;

        return $this;
    }

    /** The guard targeted when ::guard() is not called. */
    protected function defaultGuard(): string
    {
        return '__root';
    }

    protected function admin(): AdminClient
    {
        return $this->keycloak()->admin((string) $this->guardName);
    }

    protected function getAdminToken(): ?string
    {
        return $this->admin()->token();
    }

    protected function keycloak(): KeycloakManager
    {
        return app(KeycloakManager::class);
    }
}
