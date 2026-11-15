<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Testing;

use Bhry98\KeycloakAuth\Auth\WebSession;
use Bhry98\KeycloakAuth\KeycloakManager;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Add to your TestCase:
 *
 *     $this->actingAsKeycloakUser(['roles' => ['admin']])->getJson('/api/orders');
 */
trait InteractsWithKeycloak
{
    protected function fakeKeycloak(): FakeKeycloak
    {
        $keycloak = $this->app->make(KeycloakManager::class);

        return $keycloak->faked() ?? $keycloak->fake();
    }

    /**
     * Send the next requests with a signed bearer token.
     *
     * @param  array<string, mixed>  $claims
     */
    public function actingAsKeycloakUser(array $claims = [], ?string $guard = 'api'): static
    {
        return $this->withToken($this->fakeKeycloak()->token($claims, $guard));
    }

    /** @param  array<string, mixed>  $claims */
    public function keycloakToken(array $claims = [], ?string $guard = 'api'): string
    {
        return $this->fakeKeycloak()->token($claims, $guard);
    }

    /**
     * Log a user in through a fake browser SSO session (for `keycloak.web` routes).
     *
     * @param  array<string, mixed>  $claims
     */
    public function actingAsKeycloakWebUser(Authenticatable $user, array $claims = [], string $guard = 'web'): static
    {
        $tokens = $this->fakeKeycloak()->tokenResponse([
            'sub' => $user->keycloak_id ?? (string) $user->getAuthIdentifier(),
            'email' => $user->email ?? null,
            ...$claims,
        ], $guard);

        $this->actingAs($user);

        return $this->withSession([
            WebSession::ACCESS => $tokens['access_token'],
            WebSession::REFRESH => $tokens['refresh_token'],
            WebSession::ID => $tokens['id_token'],
            WebSession::EXPIRES_AT => time() + (int) $tokens['expires_in'],
            WebSession::GUARD => $guard,
        ]);
    }
}
