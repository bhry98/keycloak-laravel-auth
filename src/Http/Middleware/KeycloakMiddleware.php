<?php

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Facades\Socialite;

class KeycloakMiddleware
{

    /**
     * @throws ConnectionException
     */
    public function handle($request, Closure $next,$guard = 'web')
    {
        $clientId = config("bhry98-keycloak.guard.$guard.client_id");
        $clientSecret = config("bhry98-keycloak.guard.$guard.client_secret");
        $realm = config("bhry98-keycloak.guard.$guard.realm");
        $baseUrl = config('bhry98-keycloak.base_url');
        if (auth()->check()) {
            $token = session('keycloak_token');
            if (!$token) {
                auth()->logout();
                session(['redirect_to' => request()->fullUrl()]);
                return Socialite::driver("keycloak.$guard")->redirect();
            }
            // Call Keycloak introspection endpoint
            $response = Http::asForm()->post(
                "$baseUrl/realms/$realm/protocol/openid-connect/token/introspect",
                [
                    'client_id' => $clientId,
                    'client_secret' => $clientSecret,
                    'token' => $token,
                ]
            );
            $result = $response->json();
            if (!$response->ok() || empty($result['active'])) {
                // Token expired → log out user from Laravel
                auth()->logout();
                $request->session()->invalidate();
                $request->session()->regenerateToken();
                session(['redirect_to' => request()->fullUrl()]);
                return redirect()->route('keycloak.login', ['guard' => $guard]);
            }
            return $next($request);
        } else {
            session()->flush();
            auth()->logout();
            session(['redirect_to' => request()->fullUrl()]);
            return Socialite::driver("keycloak.$guard")
                ->redirect();
        }
    }
}

