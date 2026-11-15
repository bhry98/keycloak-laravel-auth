<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\KeycloakManager;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `keycloak.permission:invoice#read` - ask Keycloak Authorization Services
 * (UMA) whether the token grants every listed "resource#scope" permission.
 * Decisions are cached for `token.introspection_cache_ttl` seconds.
 */
class RequirePermission
{
    public function __construct(protected KeycloakManager $keycloak) {}

    public function handle(Request $request, Closure $next, string ...$permissions): Response
    {
        $token = $this->keycloak->token($request);

        if ($token === null) {
            abort(401, 'Unauthenticated.');
        }

        if (! $this->keycloak->oidc($token->guard())->checkPermission($token->jwt(), $permissions)) {
            abort(403, 'Permission denied.');
        }

        return $next($request);
    }
}
