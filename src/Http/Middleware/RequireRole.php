<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\KeycloakManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `keycloak.role:admin,editor` - the token must have at least one of the
 * roles (realm role, guard-client role, or "client-id:role").
 *
 * Run it after `keycloak.api` / `keycloak.web` / `auth:<keycloak guard>`.
 */
class RequireRole
{
    public function __construct(protected KeycloakManager $keycloak) {}

    public function handle(Request $request, Closure $next, string ...$roles): Response
    {
        $token = $this->keycloak->token($request);

        if ($token === null) {
            abort(401, 'Unauthenticated.');
        }

        if ($roles !== [] && ! $token->hasAnyRole($roles)) {
            abort(403, 'This action requires one of the roles: '.implode(', ', $roles).'.');
        }

        return $next($request);
    }
}
