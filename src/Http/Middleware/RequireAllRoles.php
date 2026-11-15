<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\KeycloakManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `keycloak.roles:admin,auditor` - the token must have every listed role.
 */
class RequireAllRoles
{
    public function __construct(protected KeycloakManager $keycloak) {}

    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $token = $this->keycloak->token($request);

        if ($token === null) {
            abort(401, 'Unauthenticated.');
        }

        if (! $token->hasAllRoles($roles)) {
            abort(403, 'This action requires the roles: '.implode(', ', $roles).'.');
        }

        return $next($request);
    }
}
