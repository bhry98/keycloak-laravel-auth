<?php

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Bhry98\KeycloakAuth\Services\KeycloakJWTService;
use Symfony\Component\HttpFoundation\Response;

class KeycloakApiMiddleware
{
    protected KeycloakJWTService $jwtService;

    public function __construct(KeycloakJWTService $jwtService)
    {
        $this->jwtService = $jwtService;
    }

    public function handle(Request $request, Closure $next): Response
    {
        $authorization = $request->header('Authorization');

        if (!$authorization || !str_starts_with($authorization, 'Bearer ')) {
            return response()->json(['error' => 'Missing or invalid Authorization header'], 401);
        }

        $token = substr($authorization, 7);

        $user = $this->jwtService->validateAndDecode($token);
        if (!$user) {
            return response()->json(['error' => 'Invalid or expired token'], 401);
        }

        // Optionally set user in request (if you map it to DB)
        $request->attributes->set('keycloak_user', $user);

        return $next($request);
    }
}
