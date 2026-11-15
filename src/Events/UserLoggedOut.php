<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Events;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A user logged out through the package logout route.
 */
class UserLoggedOut
{
    use Dispatchable;

    public function __construct(public ?Authenticatable $user, public string $guard) {}
}
