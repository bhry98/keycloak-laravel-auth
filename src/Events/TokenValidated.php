<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Events;

use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * A bearer token was verified.
 */
class TokenValidated
{
    use Dispatchable;

    public function __construct(public KeycloakToken $token, public string $guard) {}
}
