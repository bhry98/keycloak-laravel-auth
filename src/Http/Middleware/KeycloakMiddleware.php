<?php

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;

class KeycloakMiddleware
{
    public function handle($request, Closure $next)
    {
        if (auth()->check()) {
            $token = session('keycloak_token');
            if (!$token) {
                auth()->logout();
                session(['redirect_to' => request()->fullUrl()]);
                return Socialite::driver('keycloak')->redirect();
            }
            // Call Keycloak introspection endpoint
            $response = Http::asForm()->post(
                env('KEYCLOAK_BASE_URL') . '/realms/' . env('KEYCLOAK_REALM') . '/protocol/openid-connect/token/introspect',
                [
                    'client_id' => env('KEYCLOAK_CLIENT_ID'),
                    'client_secret' => env('KEYCLOAK_CLIENT_SECRET'),
                    'token' => $token,
                ]
            );
            $result = $response->json();
            if (!$response->ok() || empty($result['active'])) {
                // Token expired → log out user from Laravel
                auth()->logout();
                $request->session()->invalidate();
                $request->session()->regenerateToken();
                auth()->logout();
                session(['redirect_to' => request()->fullUrl()]);
                return redirect()->route('keycloak.login');
            }
            return $next($request);
        } else {
            session()->flush();
            auth()->logout();
            session(['redirect_to' => request()->fullUrl()]);
            return Socialite::driver('keycloak')->redirect();
        }
    }
}

