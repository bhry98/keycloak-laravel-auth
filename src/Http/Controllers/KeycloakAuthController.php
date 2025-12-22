<?php

namespace Bhry98\KeycloakAuth\Http\Controllers;

use Exception;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Http\RedirectResponse as IlluminateResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Session;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Symfony\Component\HttpFoundation\RedirectResponse;

class KeycloakAuthController extends Controller
{
    public function redirect(string $guard = "web"): RedirectResponse|IlluminateResponse
    {
        return Socialite::driver("keycloak.$guard")->redirect();
    }

    /**
     * @throws Exception
     */
    public function callback(Request $request, string $guard = "web"): IlluminateResponse
    {
        try {
            $socialiteUser = Socialite::driver("keycloak.$guard")->user();
            $userModel = config('bhry98-keycloak.users_model');
            $realm = config("bhry98-keycloak.guard.$guard.realm");
            $user = $userModel::updateOrCreate(
                ['email' => $socialiteUser->getEmail()],
                [
                    "keycloak_id" => $socialiteUser->getId(),
                    "keycloak_realm" => $realm,
                    "first_name" => Arr::get($socialiteUser->user, 'given_name'),
                    "last_name" => Arr::get($socialiteUser->user, 'family_name'),
                    "name" => $socialiteUser->getName(),
                    "email" => $socialiteUser->getEmail(),
                    "avatar" => $socialiteUser->getAvatar(),
                    "locale" => Arr::get($socialiteUser->user ?? [], 'local', 'en'),
                    "email_verified" => Arr::get($socialiteUser->user, 'email_verified'),
                ]
            );
            $tokenParts = explode(".", $socialiteUser->token);
            $payload = json_decode(base64_decode($tokenParts[1]), true);
            $realmRoles = Arr::get($payload, "realm_access.roles", []);
            $clientRoles = Arr::get($payload, "resource_access." . Arr::get($payload, "azp", 'account') . ".roles", []);
            Auth::login($user);
            Session::put(
                [
                    'keycloak_token' => $socialiteUser->token,
                    'keycloak_refresh_token' => $socialiteUser->refreshToken,
                    'keycloak_expires_in' => $socialiteUser->expiresIn,
                    'keycloak_realm_roles' => $realmRoles,
                    'keycloak_client_roles' => $clientRoles,
                ]);
            if (session()->has('redirect_to')) {
                return redirect(session('redirect_to'));
            }
            return redirect()->intended();

        } catch (\Exception $exception) {
            logger()->error($exception);
            if ($exception instanceof InvalidStateException) {
                Cache::clear();
                return redirect(route('keycloak.login', ['guard' => $guard]));
            } elseif ($exception instanceof ClientException) {
                return redirect(route('keycloak.login', ['guard' => $guard]));
            } else {
                throw $exception;
            }
        }
    }
    public function logout(string $guard = "web"): IlluminateResponse
    {
        Auth::logout();
        Session::flush();
        $logoutUrl = config('bhry98-keycloak.base_url')
            . '/realms/'
            . config("bhry98-keycloak.guard.$guard.realm")
            . '/protocol/openid-connect/logout';
        return redirect()->away($logoutUrl);
    }
}
