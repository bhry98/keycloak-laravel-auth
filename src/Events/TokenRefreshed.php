<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Events;

use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Foundation\Events\Dispatchable;

/**
 * The web session's access token was refreshed with the refresh token.
 */
class TokenRefreshed
{
    use Dispatchable;

    public function __construct(public KeycloakToken $token, public string $guard) {}
}
