<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Auth;

use Bhry98\KeycloakAuth\Concerns\HasKeycloakRoles;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Support\Arrayable;
use JsonSerializable;

/**
 * A user built from token claims only: no database row, no query.
 *
 * Claims are readable as properties: $user->email, $user->preferred_username, ...
 *
 * @implements Arrayable<string, mixed>
 */
class KeycloakUser implements Arrayable, Authenticatable, JsonSerializable
{
    use HasKeycloakRoles;

    public function __construct(protected KeycloakToken $token) {}

    public function token(): KeycloakToken
    {
        return $this->token;
    }

    public function keycloakToken(): ?KeycloakToken
    {
        return $this->token;
    }

    public function getKey(): ?string
    {
        return $this->token->subject();
    }

    public function getAuthIdentifierName(): string
    {
        return 'sub';
    }

    public function getAuthIdentifier(): mixed
    {
        return $this->token->subject();
    }

    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    public function getAuthPassword(): string
    {
        return '';
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken($value): void {}

    public function getRememberTokenName(): string
    {
        return '';
    }

    public function __get(string $name): mixed
    {
        return match ($name) {
            'id', 'keycloak_id' => $this->token->subject(),
            'username' => $this->token->username(),
            'first_name' => $this->token->firstName(),
            'last_name' => $this->token->lastName(),
            'name' => $this->token->name(),
            default => $this->token->claim($name),
        };
    }

    public function __isset(string $name): bool
    {
        return $this->__get($name) !== null;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'id' => $this->token->subject(),
            'username' => $this->token->username(),
            'email' => $this->token->email(),
            'name' => $this->token->name(),
            'first_name' => $this->token->firstName(),
            'last_name' => $this->token->lastName(),
            'email_verified' => $this->token->emailVerified(),
            'realm_roles' => $this->token->realmRoles(),
            'client_roles' => $this->token->clientRoles(),
        ];
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
