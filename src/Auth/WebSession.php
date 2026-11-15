<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Auth;

use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Contracts\Session\Session;
use Throwable;

/**
 * Keycloak tokens stored in the Laravel session (browser SSO).
 */
class WebSession
{
    public const ACCESS = 'keycloak_token';

    public const REFRESH = 'keycloak_refresh_token';

    public const ID = 'keycloak_id_token';

    public const EXPIRES_AT = 'keycloak_expires_at';

    public const GUARD = 'keycloak_guard';

    public function __construct(
        protected KeycloakManager $keycloak,
        protected Session $session,
    ) {}

    /**
     * Store a token-endpoint answer.
     *
     * @param  array<string, mixed>  $tokens  access_token, refresh_token, id_token, expires_in
     */
    public function store(string $guard, array $tokens): KeycloakToken
    {
        $access = (string) $tokens['access_token'];
        $token = $this->keycloak->decode($access, $guard);
        $expiresIn = (int) ($tokens['expires_in'] ?? max(0, $token->expiresIn()));

        $this->session->put([
            self::ACCESS => $access,
            self::REFRESH => $tokens['refresh_token'] ?? $this->session->get(self::REFRESH),
            self::ID => $tokens['id_token'] ?? $this->session->get(self::ID),
            self::EXPIRES_AT => time() + $expiresIn,
            self::GUARD => $guard,
            // 1.x keys
            'keycloak_expires_in' => $expiresIn,
            'keycloak_realm_roles' => $token->realmRoles(),
            'keycloak_client_roles' => $token->clientRoles(),
        ]);

        $this->keycloak->setToken($token);

        return $token;
    }

    public function accessToken(): ?string
    {
        $token = $this->session->get(self::ACCESS);

        return is_string($token) && $token !== '' ? $token : null;
    }

    public function refreshToken(): ?string
    {
        $token = $this->session->get(self::REFRESH);

        return is_string($token) && $token !== '' ? $token : null;
    }

    public function idToken(): ?string
    {
        $token = $this->session->get(self::ID);

        return is_string($token) && $token !== '' ? $token : null;
    }

    public function guard(): ?string
    {
        $guard = $this->session->get(self::GUARD);

        return is_string($guard) && $guard !== '' ? $guard : null;
    }

    /** Unix time the access token expires at. */
    public function expiresAt(): ?int
    {
        $expiresAt = $this->session->get(self::EXPIRES_AT);

        if (is_numeric($expiresAt)) {
            return (int) $expiresAt;
        }

        // Sessions created by 1.x only stored the token.
        $access = $this->accessToken();

        if ($access === null) {
            return null;
        }

        try {
            return (int) KeycloakToken::fromJwtUnverified($access)->claim('exp');
        } catch (Throwable) {
            return null;
        }
    }

    public function clear(): void
    {
        $this->session->forget([
            self::ACCESS, self::REFRESH, self::ID, self::EXPIRES_AT, self::GUARD,
            'keycloak_expires_in', 'keycloak_realm_roles', 'keycloak_client_roles',
        ]);
    }
}
