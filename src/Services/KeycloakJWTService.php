<?php

namespace Bhry98\KeycloakAuth\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;
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
            return (array)$decoded;
        } catch (\Throwable $e) {
            report($e);
            return null;
        }
    }


    /**
     * @throws \Exception
     */
    public function decodeToken(string $token): \stdClass
    {
        $jwks = $this->getJwks();
        $header = $this->decodeJwtHeader($token);

        $kid = $header['kid'] ?? null;
        if (!$kid) {
            throw new \Exception('Token header missing key ID (kid)');
        }
        $jwk = collect($jwks['keys'])->firstWhere('kid', $kid);
        if (!$jwk) {
            throw new \Exception("Unable to find matching JWK for kid={$kid}");
        }

        $publicKeyPem = $this->jwkToPem($jwk);
        return JWT::decode($token, new Key($publicKeyPem, $jwk['alg'] ?? 'RS256'));
    }

    protected function getJwks()
    {
        Cache::delete('keycloak_jwks');
        return Cache::remember('keycloak_jwks', 3600, function () {
            $realmUrl = trim(config('bhry98-keycloak.base_url'), '/') . '/realms/' . trim(config('bhry98-keycloak.realm'));
            $response = Http::get("{$realmUrl}/protocol/openid-connect/certs");
            if ($response->failed()) {
                throw new \Exception('Failed to fetch JWKS keys from Keycloak');
            }

            return $response->json();
        });
    }

    protected function decodeJwtHeader(string $jwt)
    {
        $segments = explode('.', $jwt);
        if (count($segments) < 2) {
            throw new \Exception('Invalid JWT token');
        }

        return json_decode(base64_decode(strtr($segments[0], '-_', '+/')), true);
    }

    /**
     * Convert JWK to PEM (clean version)
     */
    protected function jwkToPem(array $jwk): string
    {
        $n = $this->base64UrlDecode($jwk['n']);
        $e = $this->base64UrlDecode($jwk['e']);

        $components = [
            'modulus' => $this->encodeDerInteger($n),
            'publicExponent' => $this->encodeDerInteger($e),
        ];

        $sequence = $this->encodeDerSequence($components['modulus'] . $components['publicExponent']);
        $bitstring = "\x03" . $this->encodeDerLength(strlen($sequence) + 1) . "\x00" . $sequence;

        $rsaAlgorithmIdentifier = "\x30\x0D\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00";
        $rsaPublicKey = "\x30" . $this->encodeDerLength(strlen($rsaAlgorithmIdentifier . $bitstring)) . $rsaAlgorithmIdentifier . $bitstring;

        return "-----BEGIN PUBLIC KEY-----\n" .
            chunk_split(base64_encode($rsaPublicKey), 64, "\n") .
            "-----END PUBLIC KEY-----";
    }

    private function base64UrlDecode($data): false|string
    {
        return base64_decode(strtr($data, '-_', '+/'));
    }

    private function encodeDerInteger($x): string
    {
        $x = ltrim($x, "\x00");
        if (ord($x[0]) > 0x7f) {
            $x = "\x00" . $x;
        }

        return "\x02" . $this->encodeDerLength(strlen($x)) . $x;
    }

    private function encodeDerSequence($x): string
    {
        return "\x30" . $this->encodeDerLength(strlen($x)) . $x;
    }

    private function encodeDerLength($length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $temp = ltrim(pack('N', $length), "\x00");
        return chr(0x80 | strlen($temp)) . $temp;
    }
}
