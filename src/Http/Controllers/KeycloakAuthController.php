<?php

namespace Bhry98\KeycloakAuth\Http\Controllers;

use Exception;
use GuzzleHttp\Exception\ClientException;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Cache;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Http\Request;
use Laravel\Socialite\Two\InvalidStateException;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Illuminate\Http\RedirectResponse as IlluminateResponse;

class KeycloakAuthController extends Controller
{
    public function redirect(): RedirectResponse|IlluminateResponse
    {
        return Socialite::driver('keycloak')->redirect();
    }

    /**
     * @throws Exception
     */
    public function callback(Request $request): IlluminateResponse
    {
        try {
            $socialiteUser = Socialite::driver('keycloak')->user();
            $userModel = config('bhry98-keycloak.users_model');
            $user = $userModel::updateOrCreate(
                ['email' => $socialiteUser->getEmail()],
                [
                    "keycloak_id" => $socialiteUser->getId(),
                    "first_name" => $socialiteUser->user ? $socialiteUser->user['given_name'] : null,
                    "last_name" => $socialiteUser->user ? $socialiteUser->user['family_name'] : null,
                    "name" => $socialiteUser->getName(),
                    "email" => $socialiteUser->getEmail(),
                    "avatar" => $socialiteUser->getAvatar(),
                    "locale" => $socialiteUser->user ? $socialiteUser->user['locale'] : null,
                    "email_verified" => $socialiteUser->user ? $socialiteUser->user['email_verified'] : null,
                ]
            );

            Auth::login($user);
            Session::put('keycloak_token', $socialiteUser->token);
            if (session()->has('redirect_to')) {
                return redirect(session('redirect_to'));
            }
            return redirect()->intended(config('bhry98-keycloak.redirect', '/'));

        } catch (\Exception $exception) {
            logger()->error($exception);
            if ($exception instanceof InvalidStateException) {
                Cache::clear();
                return redirect(route('keycloak.login'));
            } elseif ($exception instanceof ClientException) {
                return redirect(route('keycloak.login'));
            } else {
                throw $exception;
            }
        }
    }

    public function logout(): IlluminateResponse
    {
        Auth::logout();
        Session::flush();
        $logoutUrl = config('bhry98-keycloak.base_url') . '/realms/' . config('bhry98-keycloak.realm') . '/protocol/openid-connect/logout';
        return redirect()->away($logoutUrl);
    }
}
