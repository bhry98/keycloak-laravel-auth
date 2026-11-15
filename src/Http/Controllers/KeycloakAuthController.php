<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Http\Controllers;

use Bhry98\KeycloakAuth\Auth\WebSession;
use Bhry98\KeycloakAuth\Events\UserLoggedIn;
use Bhry98\KeycloakAuth\Events\UserLoggedOut;
use Bhry98\KeycloakAuth\Exceptions\OidcException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User;
use Symfony\Component\HttpFoundation\RedirectResponse as SymfonyRedirect;

class KeycloakAuthController extends Controller
{
    public function __construct(protected KeycloakManager $keycloak) {}

    /** GET /auth/keycloak/login/{guard?} */
    public function redirect(Request $request, ?string $guard = null): SymfonyRedirect|RedirectResponse
    {
        $guard ??= $this->keycloak->defaultGuard();

        $target = $request->query('redirect');
        if (is_string($target) && $this->isLocalUrl($target)) {
            $request->session()->put('redirect_to', $target);
        }

        return $this->keycloak->socialite($guard)->redirect();
    }

    /** GET /auth/keycloak/callback/{guard?} */
    public function callback(Request $request, ?string $guard = null): RedirectResponse
    {
        $guard ??= $this->keycloak->defaultGuard();

        if ($request->has('error')) {
            abort(401, (string) ($request->query('error_description') ?: $request->query('error')));
        }

        $driver = $this->keycloak->socialite($guard);

        try {
            /** @var User $socialiteUser */
            $socialiteUser = $driver->user();
        } catch (InvalidStateException|ClientException|OidcException $e) {
            // Stale / replayed callback (back button, expired session, used code): start over.
            report($e);

            return redirect()->route($this->routeName('login'), ['guard' => $guard]);
        }

        $tokens = $driver->lastTokenResponse() ?: [
            'access_token' => $socialiteUser->token,
            'refresh_token' => $socialiteUser->refreshToken,
            'expires_in' => $socialiteUser->expiresIn,
        ];

        // Access-token claims (roles, groups) + userinfo claims (profile).
        $access = $this->keycloak->decode((string) $tokens['access_token'], $guard);
        $identity = new KeycloakToken(
            [...$access->claims(), ...array_filter((array) $socialiteUser->getRaw(), fn ($v) => $v !== null)],
            $access->jwt(),
            $guard,
            $this->keycloak->roleClients($this->keycloak->realm($guard), $access->claims()),
        );

        $user = $this->keycloak->provisioner()->resolve($identity, true);

        abort_if($user === null, 403, 'No local account for this Keycloak user.');

        $authGuard = $this->keycloak->realm($guard)->get('auth_guard');
        auth()->guard($authGuard)->login($user);
        $request->session()->regenerate();

        (new WebSession($this->keycloak, $request->session()))->store($guard, $tokens);

        UserLoggedIn::dispatch($user, $identity, $guard);

        $redirectTo = $request->session()->pull('redirect_to');

        if (is_string($redirectTo) && $redirectTo !== '') {
            return redirect($redirectTo);
        }

        return redirect()->intended((string) $this->keycloak->config('web.home', '/'));
    }

    /** GET /auth/keycloak/logout/{guard?} */
    public function logout(Request $request, ?string $guard = null): RedirectResponse
    {
        $session = new WebSession($this->keycloak, $request->session());
        $guard ??= $session->guard() ?? $this->keycloak->defaultGuard();
        $realm = $this->keycloak->realm($guard);
        $idToken = $session->idToken();

        $auth = auth()->guard($realm->get('auth_guard'));
        $user = $auth->user();

        if ($user !== null) {
            $auth->logout();
        }

        $session->clear();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        UserLoggedOut::dispatch($user, $guard);

        $redirectTo = $realm->get('redirect_after_logout') ?: $this->keycloak->config('redirect_after_logout') ?: url('/');

        return redirect()->away($this->keycloak->oidc($guard)->logoutUrl($idToken, (string) $redirectTo));
    }

    protected function routeName(string $name): string
    {
        return (string) $this->keycloak->config('routes.name', 'keycloak.').$name;
    }

    protected function isLocalUrl(string $url): bool
    {
        if (str_starts_with($url, '/') && ! str_starts_with($url, '//')) {
            return true;
        }

        return parse_url($url, PHP_URL_HOST) === request()->getHost();
    }
}
