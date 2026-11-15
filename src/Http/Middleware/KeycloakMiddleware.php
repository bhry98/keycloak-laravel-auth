<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\Auth\WebSession;
use Bhry98\KeycloakAuth\Events\TokenRefreshed;
use Bhry98\KeycloakAuth\Exceptions\KeycloakException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * `keycloak.web[:guard]` - browser SSO session.
 *
 * Unauthenticated visitors are sent to the Keycloak login page. For
 * logged-in users the access token is checked locally on every request
 * (no network) and silently refreshed with the refresh token shortly before
 * it expires. Set `web.validation` to "introspect" to also ask Keycloak
 * (cached) whether the session is still active.
 */
class KeycloakMiddleware
{
    public function __construct(protected KeycloakManager $keycloak) {}

    public function handle(Request $request, Closure $next, ?string $guard = null): Response
    {
        $session = new WebSession($this->keycloak, $request->session());
        $guard = $guard ?: ($session->guard() ?? $this->keycloak->defaultGuard());
        $authGuard = $this->keycloak->realm($guard)->get('auth_guard');
        $auth = auth()->guard($authGuard);

        if (! $auth->check() || $session->accessToken() === null) {
            return $this->toLogin($request, $guard);
        }

        $expiresAt = $session->expiresAt() ?? 0;
        $margin = (int) $this->keycloak->config('web.refresh_margin', 15);

        if ($expiresAt - $margin <= time()) {
            if (! $this->refresh($session, $guard)) {
                return $this->toLogin($request, $guard);
            }
        } elseif ($this->keycloak->config('web.validation', 'local') === 'introspect'
            && ! $this->isActive($guard, (string) $session->accessToken())) {
            return $this->toLogin($request, $guard);
        } else {
            $this->keycloak->token($request);
        }

        return $next($request);
    }

    protected function refresh(WebSession $session, string $guard): bool
    {
        $refreshToken = $session->refreshToken();

        if ($refreshToken === null || ! $this->keycloak->config('web.refresh_tokens', true)) {
            return false;
        }

        try {
            $tokens = $this->keycloak->oidc($guard)->refresh($refreshToken);
        } catch (KeycloakException) {
            return false;
        }

        TokenRefreshed::dispatch($session->store($guard, $tokens), $guard);

        return true;
    }

    protected function isActive(string $guard, string $accessToken): bool
    {
        try {
            return $this->keycloak->oidc($guard)->isActive($accessToken);
        } catch (KeycloakException) {
            return false;
        }
    }

    protected function toLogin(Request $request, string $guard): Response
    {
        $authGuard = $this->keycloak->realm($guard)->get('auth_guard');

        if (auth()->guard($authGuard)->check()) {
            auth()->guard($authGuard)->logout();
        }

        (new WebSession($this->keycloak, $request->session()))->clear();

        if ($request->expectsJson()) {
            return new JsonResponse(['error' => 'Unauthenticated.'], 401);
        }

        if ($request->isMethod('GET')) {
            $request->session()->put('redirect_to', $request->fullUrl());
        }

        return $this->keycloak->socialite($guard)->redirect();
    }
}
