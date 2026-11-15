<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Oidc;

use Bhry98\KeycloakAuth\Exceptions\OidcException;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Illuminate\Http\Client\Response;
use Throwable;

/**
 * OpenID Connect / OAuth2 endpoints of one realm + client.
 *
 * Token-endpoint methods return Keycloak's JSON answer as an array:
 * access_token, expires_in, refresh_token, refresh_expires_in, id_token,
 * token_type, scope, session_state.
 */
class OidcClient
{
    public function __construct(
        protected KeycloakManager $keycloak,
        protected RealmConfig $realm,
    ) {}

    public function realm(): RealmConfig
    {
        return $this->realm;
    }

    /* ---------------------------------------------------------------
     | Grants
     * ------------------------------------------------------------- */

    /**
     * Resource-owner password grant ("Direct access grants" must be enabled on the client).
     *
     * @param  array<string, mixed>  $extra
     * @return array<string, mixed>
     */
    public function password(string $username, string $password, ?string $scope = null, array $extra = []): array
    {
        return $this->token([
            'grant_type' => 'password',
            'username' => $username,
            'password' => $password,
            'scope' => $scope ?? implode(' ', $this->realm->scopes),
            ...$extra,
        ]);
    }

    /**
     * Client-credentials grant (service account must be enabled on the client).
     *
     * @return array<string, mixed>
     */
    public function clientCredentials(?string $scope = null): array
    {
        return $this->token(array_filter([
            'grant_type' => 'client_credentials',
            'scope' => $scope,
        ]));
    }

    /** @return array<string, mixed> */
    public function refresh(string $refreshToken): array
    {
        return $this->token([
            'grant_type' => 'refresh_token',
            'refresh_token' => $refreshToken,
        ]);
    }

    /**
     * Exchange an authorization code (custom frontends that handle the redirect themselves).
     *
     * @return array<string, mixed>
     */
    public function code(string $code, string $redirectUri, ?string $codeVerifier = null): array
    {
        return $this->token(array_filter([
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ]));
    }

    /**
     * OAuth 2.0 Token Exchange (RFC 8693): trade a user token for one meant for another client.
     *
     * @param  array<string, mixed>  $extra
     * @return array<string, mixed>
     */
    public function exchange(string $subjectToken, ?string $audience = null, array $extra = []): array
    {
        return $this->token(array_filter([
            'grant_type' => 'urn:ietf:params:oauth:grant-type:token-exchange',
            'subject_token' => $subjectToken,
            'subject_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'requested_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'audience' => $audience,
            ...$extra,
        ]));
    }

    /**
     * A cached client-credentials access token, for calling other services.
     * Re-used until shortly before it expires.
     */
    public function serviceToken(?string $scope = null): string
    {
        $key = $this->keycloak->cachePrefix().':service_token:'.$this->realm->fingerprint().':'.md5((string) $scope);
        $cache = $this->keycloak->cache();

        $cached = $cache->get($key);
        if (is_string($cached) && $cached !== '') {
            return $cached;
        }

        $response = $this->clientCredentials($scope);
        $token = (string) $response['access_token'];
        $ttl = (int) ($response['expires_in'] ?? 60) - (int) $this->keycloak->config('admin.token_expiry_margin', 30);

        if ($ttl > 0) {
            $cache->put($key, $token, $ttl);
        }

        return $token;
    }

    public function forgetServiceToken(?string $scope = null): void
    {
        $this->keycloak->cache()->forget(
            $this->keycloak->cachePrefix().':service_token:'.$this->realm->fingerprint().':'.md5((string) $scope)
        );
    }

    /* ---------------------------------------------------------------
     | Token & session endpoints
     * ------------------------------------------------------------- */

    /**
     * RFC 7662 introspection. Set $cache to re-use the answer for
     * `token.introspection_cache_ttl` seconds (never past the token expiry).
     *
     * @return array<string, mixed>
     */
    public function introspect(string $token, bool $cache = false): array
    {
        $ttl = (int) $this->keycloak->config('token.introspection_cache_ttl', 30);
        $key = $this->keycloak->cachePrefix().':introspect:'.$this->realm->fingerprint().':'.hash('sha256', $token);

        if ($cache && $ttl > 0 && is_array($hit = $this->keycloak->cache()->get($key))) {
            return $hit;
        }

        $result = $this->json($this->post('token/introspect', ['token' => $token]), 'Token introspection failed');

        if ($cache && $ttl > 0) {
            if (! empty($result['active']) && isset($result['exp'])) {
                $ttl = min($ttl, (int) $result['exp'] - time());
            }

            if ($ttl > 0) {
                $this->keycloak->cache()->put($key, $result, $ttl);
            }
        }

        return $result;
    }

    public function isActive(string $token, bool $cache = true): bool
    {
        return (bool) ($this->introspect($token, $cache)['active'] ?? false);
    }

    /** @return array<string, mixed> */
    public function userInfo(string $accessToken): array
    {
        try {
            $response = $this->keycloak->http()->withToken($accessToken)->get($this->realm->openIdUrl('userinfo'));
        } catch (Throwable $e) {
            throw new OidcException("Keycloak userinfo request failed: {$e->getMessage()}", 0, $e);
        }

        return $this->json($response, 'Userinfo request failed');
    }

    /** Back-channel logout: ends the Keycloak session of this refresh token. */
    public function logout(string $refreshToken): bool
    {
        $response = $this->post('logout', ['refresh_token' => $refreshToken]);

        if ($response->failed()) {
            throw OidcException::fromResponse('Logout failed', $response);
        }

        return true;
    }

    public function revoke(string $token, string $hint = 'refresh_token'): bool
    {
        $response = $this->post('revoke', ['token' => $token, 'token_type_hint' => $hint]);

        if ($response->failed()) {
            throw OidcException::fromResponse('Token revocation failed', $response);
        }

        return true;
    }

    /**
     * Front-channel logout URL (redirect the browser here).
     */
    public function logoutUrl(?string $idToken = null, ?string $redirectTo = null): string
    {
        $query = array_filter([
            'client_id' => $this->realm->clientId,
            'id_token_hint' => $idToken,
            'post_logout_redirect_uri' => $redirectTo,
        ]);

        return $this->realm->openIdUrl('logout').($query ? '?'.http_build_query($query) : '');
    }

    /* ---------------------------------------------------------------
     | Authorization services (UMA)
     * ------------------------------------------------------------- */

    /**
     * Ask Keycloak Authorization Services whether the user may access
     * "resource#scope" permissions. Answers are cached briefly.
     *
     * @param  array<int, string>|string  $permissions  e.g. "invoice#read" or ["invoice#read", "report"]
     */
    public function checkPermission(string $accessToken, array|string $permissions, ?string $audience = null): bool
    {
        $permissions = array_values((array) $permissions);
        $audience ??= $this->realm->clientId;
        $ttl = (int) $this->keycloak->config('token.introspection_cache_ttl', 30);
        $key = $this->keycloak->cachePrefix().':uma:'.$this->realm->fingerprint().':'.hash('sha256', $accessToken.'|'.$audience.'|'.implode(',', $permissions));

        if ($ttl > 0 && is_bool($hit = $this->keycloak->cache()->get($key))) {
            return $hit;
        }

        $response = $this->umaRequest($accessToken, $audience, $permissions, 'decision');

        if ($response->status() === 403 || $response->status() === 401) {
            $result = false;
        } elseif ($response->failed()) {
            throw OidcException::fromResponse('Permission check failed', $response);
        } else {
            $result = (bool) $response->json('result', false);
        }

        if ($ttl > 0) {
            $this->keycloak->cache()->put($key, $result, $ttl);
        }

        return $result;
    }

    /**
     * Every permission the user is granted on the resource server.
     *
     * @return array<int, array{rsid?: string, rsname?: string, scopes?: array<int, string>}>
     */
    public function permissions(string $accessToken, ?string $audience = null): array
    {
        $response = $this->umaRequest($accessToken, $audience ?? $this->realm->clientId, [], 'permissions');

        if ($response->status() === 403) {
            return [];
        }

        return $this->json($response, 'Permission listing failed');
    }

    /* ---------------------------------------------------------------
     | Discovery
     * ------------------------------------------------------------- */

    /**
     * The realm's `.well-known/openid-configuration`, cached for a day.
     *
     * @return array<string, mixed>
     */
    public function discovery(): array
    {
        return $this->keycloak->cache()->remember(
            $this->keycloak->cachePrefix().':discovery:'.md5($this->realm->realmUrl()),
            86400,
            function () {
                $response = $this->keycloak->http()->get($this->realm->realmUrl().'/.well-known/openid-configuration');

                return $this->json($response, 'Discovery document request failed');
            },
        );
    }

    /* ---------------------------------------------------------------
     | Internals
     * ------------------------------------------------------------- */

    /**
     * @param  array<string, mixed>  $params
     * @return array<string, mixed>
     */
    public function token(array $params): array
    {
        $result = $this->json($this->post('token', $params), 'Token request failed');

        if (! isset($result['access_token'])) {
            throw new OidcException('Keycloak token endpoint returned no access_token.');
        }

        return $result;
    }

    /**
     * @param  array<int, string>  $permissions
     */
    protected function umaRequest(string $accessToken, string $audience, array $permissions, string $mode): Response
    {
        $body = http_build_query(['grant_type' => 'urn:ietf:params:oauth:grant-type:uma-ticket', 'audience' => $audience, 'response_mode' => $mode]);
        foreach ($permissions as $permission) {
            $body .= '&permission='.rawurlencode($permission);
        }

        try {
            return $this->keycloak->http()
                ->withToken($accessToken)
                ->withBody($body, 'application/x-www-form-urlencoded')
                ->post($this->realm->openIdUrl('token'));
        } catch (Throwable $e) {
            throw new OidcException("Keycloak permission request failed: {$e->getMessage()}", 0, $e);
        }
    }

    /** @param  array<string, mixed>  $params */
    protected function post(string $endpoint, array $params): Response
    {
        $params['client_id'] = $this->realm->clientId;

        if ($this->realm->clientSecret !== '') {
            $params['client_secret'] = $this->realm->clientSecret;
        }

        try {
            return $this->keycloak->http()->asForm()->post($this->realm->openIdUrl($endpoint), $params);
        } catch (Throwable $e) {
            throw new OidcException("Keycloak request to [{$endpoint}] failed: {$e->getMessage()}", 0, $e);
        }
    }

    /** @return array<mixed> */
    protected function json(Response $response, string $context): array
    {
        if ($response->failed()) {
            throw OidcException::fromResponse($context, $response);
        }

        $json = $response->json();

        return is_array($json) ? $json : [];
    }
}
