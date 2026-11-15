<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 1.x middleware: verifies the bearer token, syncs the local user and
 * exposes the claims as $request->input('auth_user').
 *
 * @deprecated Use `keycloak.api` (or the `keycloak` auth guard) instead.
 */
class VerifyKeycloakTokenForAgent extends KeycloakApiMiddleware
{
    public function handle(Request $request, Closure $next, ?string $guard = 'web'): Response
    {
        return parent::handle($request, $next, $guard);
    }

    protected function authenticate(Request $request, KeycloakToken $token): bool
    {
        $request->merge(['auth_user' => $token->claims()]);

        return parent::authenticate($request, $token);
    }
}
