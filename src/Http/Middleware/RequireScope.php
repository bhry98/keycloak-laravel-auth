<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\KeycloakManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `keycloak.scope:orders:read,orders:write` - the token must carry at least one of the scopes.
 */
class RequireScope
{
    public function __construct(protected KeycloakManager $keycloak) {}

    public function handle(Request $request, Closure $next, string ...$scopes): Response
    {
        $token = $this->keycloak->token($request);

        if ($token === null) {
            abort(401, 'Unauthenticated.');
        }

        if ($scopes !== [] && ! $token->hasAnyScope($scopes)) {
            abort(403, 'This action requires one of the scopes: '.implode(', ', $scopes).'.');
        }

        return $next($request);
    }
}
