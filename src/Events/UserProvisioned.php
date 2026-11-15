<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Events;

use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A local user row was created or updated from Keycloak claims.
 */
class UserProvisioned
{
    use Dispatchable;

    public function __construct(public Authenticatable $user, public KeycloakToken $token, public bool $created) {}
}
