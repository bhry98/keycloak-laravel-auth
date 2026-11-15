<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Auth;

use Bhry98\KeycloakAuth\Events\TokenValidated;
use Bhry98\KeycloakAuth\Events\TokenValidationFailed;
use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;

/**
 * Stateless bearer-token guard (`'driver' => 'keycloak'` in config/auth.php).
 *
 *     'guards' => [
 *         'api' => ['driver' => 'keycloak', 'keycloak' => 'api'],
 *     ],
 */
class KeycloakGuard implements Guard
{
    use GuardHelpers;

    protected ?KeycloakToken $token = null;

    protected bool $resolved = false;

    public function __construct(
        protected KeycloakManager $keycloak,
        protected ?Request $request,
        protected string $keycloakGuard = 'api',
        protected ?bool $provision = null,
    ) {}

    public function user(): ?Authenticatable
    {
        if ($this->user !== null || $this->resolved) {
            return $this->user;
        }

        $this->resolved = true;

        $jwt = $this->request?->bearerToken();

        if (! $jwt) {
            return null;
        }

        $token = $this->validateToken($jwt);

        if ($token === null) {
            return null;
        }

        $this->token = $token;
        $this->keycloak->setToken($token, $this->request);

        return $this->user = $this->keycloak->provisioner()->resolve($token, $this->provision);
    }

    /**
     * Check a token without logging anyone in: validate(['token' => $jwt]).
     *
     * @param  array<string, mixed>  $credentials
     */
    public function validate(array $credentials = []): bool
    {
        $jwt = $credentials['token'] ?? $credentials['access_token'] ?? null;

        return is_string($jwt) && $this->keycloak->check($jwt, $this->keycloakGuard) !== null;
    }

    /** The verified token of the authenticated request. */
    public function token(): ?KeycloakToken
    {
        $this->user();

        return $this->token;
    }

    public function hasRole(string $role): bool
    {
        return (bool) $this->token()?->hasRole($role);
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;
        $this->user = null;
        $this->token = null;
        $this->resolved = false;

        return $this;
    }

    public function forgetUser(): static
    {
        $this->user = null;
        $this->token = null;
        $this->resolved = false;

        return $this;
    }

    public function keycloakGuard(): string
    {
        return $this->keycloakGuard;
    }

    protected function validateToken(string $jwt): ?KeycloakToken
    {
        try {
            $token = $this->keycloak->validate($jwt, $this->keycloakGuard);
        } catch (TokenValidationException $e) {
            TokenValidationFailed::dispatch($e, $this->keycloakGuard, $this->request);

            return null;
        }

        TokenValidated::dispatch($token, $this->keycloakGuard);

        return $token;
    }
}
