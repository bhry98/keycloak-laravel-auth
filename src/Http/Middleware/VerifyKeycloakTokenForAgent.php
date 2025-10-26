<?php

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Bhry98\KeycloakAuth\Services\KeycloakJWTService;
use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;

class VerifyKeycloakTokenForAgent
{
    public function handle(Request $request, Closure $next)
    {
        $authHeader = $request->header('Authorization');

        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return response()->json(['error' => 'Missing Bearer Token'], 401);
        }

        $token = substr($authHeader, 7);

        try {
            $decoded = (new KeycloakJWTService)->decodeToken($token);
            // Attach decoded user
            $request->merge(['auth_user' => (array)$decoded]);
            $userModel = config('auth.providers.users.model');
            $user = $userModel::updateOrCreate(
                ['email' => $decoded->email],
                [
                    'name' => $decoded->name,
                    'email_verified_at' => now(),
                    'password' => Hash::make(Str::random(32)), // dummy password
                ]
            );

            Auth::login($user);
            Session::put('keycloak_token', $token);
            return $next($request);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Invalid or expired token',
                'message' => $e->getMessage(),
            ], 401);
        }
        return $next($request);
    }


}