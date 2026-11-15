<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Events;

use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A user finished the browser SSO login.
 */
class UserLoggedIn
{
    use Dispatchable;

    public function __construct(public Authenticatable $user, public KeycloakToken $token, public string $guard) {}
}
