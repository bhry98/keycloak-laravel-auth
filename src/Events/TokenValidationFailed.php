<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Events;

use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Http\Request;

/**
 * A bearer token was rejected.
 */
class TokenValidationFailed
{
    use Dispatchable;

    public function __construct(public TokenValidationException $exception, public string $guard, public ?Request $request = null) {}
}
