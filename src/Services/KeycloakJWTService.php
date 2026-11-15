<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Services;

use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\KeycloakManager;
use stdClass;

/**
 * 1.x JWT service. New code: Keycloak::validate($jwt, $guard).
 */
class KeycloakJWTService
{
    public function __construct(protected ?string $guard = null) {}

    /** @return array<string, mixed>|null Claims, or null when the token is invalid. */
    public function validateAndDecode(string $token): ?array
    {
        return $this->keycloak()->check($token, $this->guard)?->claims();
    }

    /**
     * @throws TokenValidationException
     */
    public function decodeToken(string $token): stdClass
    {
        return json_decode((string) json_encode($this->keycloak()->validate($token, $this->guard)->claims()));
    }

    protected function keycloak(): KeycloakManager
    {
        return app(KeycloakManager::class);
    }
}
