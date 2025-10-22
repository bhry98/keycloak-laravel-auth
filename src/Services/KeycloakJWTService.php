<?php

namespace Bhry98\KeycloakAuth\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Illuminate\Support\Facades\Http;

class KeycloakJWTService
{
    public function validateAndDecode(string $token): ?array
    {
        try {
            $realm = config('bhry98-keycloak.realm');
            $url = rtrim(config('bhry98-keycloak.base_url'), '/') . "/realms/{$realm}/protocol/openid-connect/certs";

            $keys = cache()->remember("keycloak_jwks_{$realm}", 3600, function () use ($url) {
                return Http::get($url)->json();
            });

            $decoded = JWT::decode($token, JWK::parseKeySet($keys));
            return (array) $decoded;
        } catch (\Throwable $e) {
            report($e);
            return null;
        }
    }
}
