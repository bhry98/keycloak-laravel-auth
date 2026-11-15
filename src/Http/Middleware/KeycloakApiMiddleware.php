<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\Events\TokenValidated;
use Bhry98\KeycloakAuth\Events\TokenValidationFailed;
use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Closure;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `keycloak.api[:guard]` - authenticate a request by its bearer token.
 *
 * The token is verified offline (cached JWKS). The resulting user is
 * available through $request->user() / auth()->user() and the token
 * through Keycloak::token().
 */
class KeycloakApiMiddleware
{
    public function __construct(
        protected KeycloakManager $keycloak,
        protected AuthFactory $auth,
    ) {}

    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $guard = $this->guardName($guard);
        $jwt = $request->bearerToken();

        if (! $jwt) {
            return $this->unauthorized('Missing or invalid Authorization header');
        }

        try {
            $token = $this->keycloak->validate($jwt, $guard);
        } catch (TokenValidationException $e) {
            TokenValidationFailed::dispatch($e, $guard, $request);

            return $this->unauthorized('Invalid or expired token', $e->getMessage());
        }

        TokenValidated::dispatch($token, $guard);

        if (! $this->authenticate($request, $token)) {
            return $this->unauthorized('Unauthenticated');
        }

        return $next($request);
    }

    /** Attach the token and user to the request; false rejects the request. */
    protected function authenticate(Request $request, KeycloakToken $token): bool
    {
        $this->keycloak->setToken($token, $request);

        // Kept for 1.x compatibility.
        $request->attributes->set('keycloak_user', $token->claims());

        $user = $this->keycloak->provisioner()->resolve($token);

        if ($user === null) {
            return false;
        }

        $this->auth->guard()->setUser($user);
        $request->setUserResolver(fn (?string $name = null) => $name === null ? $user : $this->auth->guard($name)->user());

        return true;
    }

    protected function guardName(?string $guard): string
    {
        if ($guard !== null && $guard !== '') {
            return $guard;
        }

        return in_array('api', $this->keycloak->guards(), true) ? 'api' : $this->keycloak->defaultGuard();
    }

    protected function unauthorized(string $error, ?string $reason = null): JsonResponse
    {
        $body = ['error' => $error];

        if ($reason !== null && config('app.debug')) {
            $body['message'] = $reason;
        }

        return new JsonResponse($body, 401, ['WWW-Authenticate' => 'Bearer']);
    }
}
