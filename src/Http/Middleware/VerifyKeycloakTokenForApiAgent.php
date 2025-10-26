<?php

namespace Bhry98\KeycloakAuth\Http\Middleware;

use Closure;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class VerifyKeycloakTokenForApiAgent
{
    public function handle(Request $request, Closure $next)
    {
        $authHeader = $request->header('Authorization');

        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return response()->json(['error' => 'Missing Bearer Token'], 401);
        }

        $token = substr($authHeader, 7);

        try {
            $publicKey = $this->getKeycloakPublicKey();

            $decoded = JWT::decode($token, new Key($publicKey, 'RS256'));

            // Attach decoded user to request
            $request->merge(['auth_user' => (array)$decoded]);
        } catch (\Exception $e) {
            return response()->json([
                'error' => 'Invalid or expired token',
                'message' => $e->getMessage(),
            ], 401);
        }

        return $next($request);
    }

    /**
     * Get Keycloak public key (cached)
     */
    protected function getKeycloakPublicKey(): string
    {
        return Cache::remember('keycloak_public_key', 3600, function () {
            $realmUrl = config('services.keycloak.realm_url', 'https://sso.valleysoft-eg.com/realms/ERP');

            $response = Http::get("{$realmUrl}/protocol/openid-connect/certs");

            if ($response->failed()) {
                throw new \Exception('Failed to fetch JWKS keys from Keycloak');
            }

            $jwks = $response->json();
            $keyData = $jwks['keys'][0] ?? null;

            if (!$keyData) {
                throw new \Exception('No JWKS keys found');
            }

            return $this->convertJwkToPem($keyData);
        });
    }

    /**
     * Convert a JWK key to PEM format (without phpseclib)
     */
    protected function convertJwkToPem(array $keyData): string
    {
        $modulus = $this->base64UrlDecode($keyData['n']);
        $exponent = $this->base64UrlDecode($keyData['e']);

        $modulusHex = $this->binToHex($modulus);
        $exponentHex = $this->binToHex($exponent);

        $modulusEncoded = $this->encodeLength(strlen($modulusHex) / 2) . $modulusHex;
        $exponentEncoded = $this->encodeLength(strlen($exponentHex) / 2) . $exponentHex;

        $rsaPublicKey = "30" . $this->encodeLength((strlen($modulusEncoded . $exponentEncoded) / 2) + 2)
            . "02" . $modulusEncoded
            . "02" . $exponentEncoded;

        $rsaPublicKeyDer = hex2bin($rsaPublicKey);
        $rsaPublicKeyPem = "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($rsaPublicKeyDer), 64, "\n") .
            "-----END PUBLIC KEY-----";

        return $rsaPublicKeyPem;
    }

    private function base64UrlDecode($data)
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function binToHex($data)
    {
        $hex = bin2hex($data);
        if (ord($data[0]) > 0x7f) {
            $hex = '00' . $hex;
        }
        return $hex;
    }

    private function encodeLength($length)
    {
        if ($length <= 0x7f) {
            return sprintf("%02x", $length);
        }
        $temp = ltrim(sprintf("%x", $length), '0');
        if (strlen($temp) % 2 != 0) {
            $temp = '0' . $temp;
        }
        $len = strlen($temp) / 2;
        return sprintf("%02x", 0x80 + $len) . $temp;
    }
}