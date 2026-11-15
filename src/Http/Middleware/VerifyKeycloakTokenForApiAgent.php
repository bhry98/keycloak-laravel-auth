<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 1.x middleware for service-to-service calls: verifies the bearer token and
 * exposes its claims as $request->input('auth_user'). No user is resolved.
 *
 * @deprecated Use `keycloak.api` (or the `keycloak` auth guard) instead.
 */
class VerifyKeycloakTokenForApiAgent extends KeycloakApiMiddleware
{
    public function handle(Request $request, Closure $next, ?string $guard = 'api'): Response
    {
        return parent::handle($request, $next, $guard);
    }

    protected function authenticate(Request $request, KeycloakToken $token): bool
    {
        $this->keycloak->setToken($token, $request);
        $request->attributes->set('keycloak_user', $token->claims());
        $request->merge(['auth_user' => $token->claims()]);

        return true;
    }
}
