<?php

namespace Bhry98\KeycloakAuth\Http\Controllers;

use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Session;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Illuminate\Http\RedirectResponse as IlluminateResponse;

class KeycloakAuthController extends Controller
{
    public function redirect(): RedirectResponse|IlluminateResponse
    {
        return Socialite::driver('keycloak')->redirect();
    }

    public function callback(Request $request): IlluminateResponse
    {
        $socialiteUser = Socialite::driver('keycloak')->user();

        $userModel = config('auth.providers.users.model');
        $user = $userModel::updateOrCreate(
            ['email' => $socialiteUser->getEmail()],
            [
                'name' => $socialiteUser->getName() ?? $socialiteUser->getNickname(),
                'email_verified_at' => now(),
                'password' => Hash::make(Str::random(32)), // 🔒 dummy password
            ]
        );

        Auth::login($user);
        Session::put('keycloak_token', $socialiteUser->token);
        if (session()->has('redirect_to')) {
            return redirect(session('redirect_to'));
        }
        return redirect()->intended(config('bhry98-keycloak.redirect', '/'));
    }

    public function logout(): IlluminateResponse
    {
        Auth::logout();
        Session::flush();
        $logoutUrl = config('bhry98-keycloak.base_url') . '/realms/' . config('bhry98-keycloak.realm') . '/protocol/openid-connect/logout';
        return redirect()->away($logoutUrl);
    }
}
