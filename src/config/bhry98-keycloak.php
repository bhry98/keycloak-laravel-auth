<?php

use Bhry98\KeycloakAuth\Models\KCUserModel;

return [

    /*
    |--------------------------------------------------------------------------
    | Keycloak server
    |--------------------------------------------------------------------------
    |
    | The base URL of your Keycloak server (without "/realms/..."). Every
    | "guard" below can override it with its own `base_url` if you talk to
    | more than one Keycloak instance.
    |
    */

    'base_url' => env('KEYCLOAK_BASE_URL', 'https://keycloak-domain'),

    /*
    | Fallback realm / client credentials. Used by every guard that does not
    | define its own value, and by code that does not ask for a guard.
    */
    'realm' => env('KEYCLOAK_REALM', ''),
    'client_id' => env('KEYCLOAK_CLIENT_ID', 'laravel-app'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', ''),
    'redirect' => env('KEYCLOAK_REDIRECT_URI', '/auth/keycloak/callback'),
    'redirect_after_logout' => env('KEYCLOAK_RED_AFTER_LOGOUT', env('APP_URL')),

    /*
    | The guard used when you don't pass one: Keycloak::oidc(), Keycloak::token(),
    | the `keycloak.web` middleware, the login routes, ...
    */
    'default_guard' => env('KEYCLOAK_DEFAULT_GUARD', 'web'),

    /*
    |--------------------------------------------------------------------------
    | Guards (realm + client pairs)
    |--------------------------------------------------------------------------
    |
    | A "guard" is a named Keycloak realm + client. Add as many as you need
    | (e.g. one per frontend, per tenant realm, per microservice).
    |
    | Supported keys per guard: base_url, realm, client_id, client_secret,
    | redirect, scopes, issuer, audience, auth_guard, redirect_after_logout.
    |
    | The "admin" guard holds the service-account credentials used to call
    | the Keycloak Admin REST API (see `admin.guard` below). Give its client
    | the "realm-management" roles you need (manage-users, view-users, ...).
    |
    */

    'guard' => [
        'web' => [
            'client_id' => env('KC_WEB_CLIENT_ID', env('KEYCLOAK_CLIENT_ID', 'laravel-app')),
            'client_secret' => env('KC_WEB_CLIENT_SECRET', env('KEYCLOAK_CLIENT_SECRET', '')),
            'realm' => env('KC_WEB_REALM', env('KEYCLOAK_REALM', '')),
            'redirect' => env('KC_WEB_REDIRECT_URI', env('KEYCLOAK_REDIRECT_URI', '')),
            'scopes' => ['openid', 'email', 'profile'],
        ],

        'api' => [
            'client_id' => env('KC_API_CLIENT_ID', env('KEYCLOAK_CLIENT_ID', 'laravel-app')),
            'client_secret' => env('KC_API_CLIENT_SECRET', env('KEYCLOAK_CLIENT_SECRET', '')),
            'realm' => env('KC_API_REALM', env('KEYCLOAK_REALM', '')),
            'redirect' => env('KC_API_REDIRECT_URI', env('KEYCLOAK_REDIRECT_URI', '')),
            // Require one of these values in the token's `aud`/`azp` claim (null = don't check).
            'audience' => env('KC_API_AUDIENCE'),
        ],

        'admin' => [
            'client_id' => env('KC_ADMIN_CLIENT_ID', env('KEYCLOAK_CLIENT_ID', 'laravel-app')),
            'client_secret' => env('KC_ADMIN_CLIENT_SECRET', env('KEYCLOAK_CLIENT_SECRET', '')),
            'realm' => env('KC_ADMIN_REALM', env('KEYCLOAK_REALM', 'master')),
            'redirect' => env('KC_ADMIN_REDIRECT_URI', env('KEYCLOAK_REDIRECT_URI', '')),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Admin REST API
    |--------------------------------------------------------------------------
    */

    'admin' => [
        // Guard whose client credentials are used to obtain the admin token.
        'guard' => env('KEYCLOAK_ADMIN_GUARD', 'admin'),
        // Seconds subtracted from the admin token lifetime before it is refreshed.
        'token_expiry_margin' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Access token validation
    |--------------------------------------------------------------------------
    |
    | Tokens are verified offline against the realm's JWKS (public keys),
    | which are cached. No call to Keycloak is made per request.
    |
    */

    'token' => [
        // Clock skew tolerance (seconds) for exp / nbf / iat.
        'leeway' => (int) env('KEYCLOAK_TOKEN_LEEWAY', 30),

        // Accepted signing algorithms. Never add "none" or HMAC algorithms here.
        'allowed_algs' => ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512', 'ES256', 'ES384', 'ES512', 'EdDSA'],

        // Accepted `typ` claim values (Keycloak access tokens use "Bearer").
        'allowed_types' => ['Bearer'],

        // Verify the `iss` claim. Set KEYCLOAK_ISSUER when the public URL your
        // clients use differs from KEYCLOAK_BASE_URL (Docker, Kubernetes, ...).
        'verify_issuer' => (bool) env('KEYCLOAK_VERIFY_ISSUER', true),
        'issuer' => env('KEYCLOAK_ISSUER'),

        // How long the realm public keys are cached (seconds).
        'jwks_ttl' => (int) env('KEYCLOAK_JWKS_TTL', 86400),

        // Minimum seconds between forced JWKS re-downloads when a token is
        // signed with an unknown key id (key rotation).
        'jwks_refresh_cooldown' => 30,

        // Cache of token introspection / UMA permission results (seconds).
        'introspection_cache_ttl' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Web (browser) SSO
    |--------------------------------------------------------------------------
    */

    'web' => [
        // Use PKCE on the authorization code flow (recommended).
        'pkce' => (bool) env('KEYCLOAK_PKCE', true),

        // How `keycloak.web` checks the session on each request:
        //   "local"      - check the access token expiry locally (fast, no network)
        //   "introspect" - ask Keycloak (cached for `token.introspection_cache_ttl`)
        'validation' => env('KEYCLOAK_WEB_VALIDATION', 'local'),

        // Silently refresh the access token with the refresh token when it expires.
        'refresh_tokens' => true,

        // Refresh this many seconds before the access token actually expires.
        'refresh_margin' => 15,

        // Where to send the user after login when there is no intended URL.
        'home' => env('KEYCLOAK_HOME', '/'),
    ],

    /*
    |--------------------------------------------------------------------------
    | User provisioning (sync Keycloak users into your database)
    |--------------------------------------------------------------------------
    |
    | When enabled, a local user row is created/updated from the token claims
    | on login and on API calls. When disabled, API requests get a stateless
    | `KeycloakUser` built from the token, with no database access at all.
    |
    */

    'users_model' => KCUserModel::class,

    'provisioning' => [
        'enabled' => (bool) env('KEYCLOAK_PROVISIONING', true),

        // Skip the database write when the user's claims did not change for this long (seconds).
        'sync_ttl' => 300,

        // column => claim (dot notation supported).
        'attributes' => [
            'keycloak_id' => 'sub',
            'email' => 'email',
            'username' => 'preferred_username',
            'first_name' => 'given_name',
            'last_name' => 'family_name',
            'name' => 'name',
            'avatar' => 'picture',
            'locale' => 'locale',
            'email_verified' => 'email_verified',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Roles
    |--------------------------------------------------------------------------
    */

    'roles' => [
        // Client roles are read from resource_access.{client}. null = the
        // guard's client_id plus the token's `azp`.
        'clients' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | Infrastructure
    |--------------------------------------------------------------------------
    */

    'cache' => [
        // Any store from config/cache.php. null = the default store.
        'store' => env('KEYCLOAK_CACHE_STORE'),
        'prefix' => 'bhry98_keycloak',
    ],

    'http' => [
        'timeout' => 10,
        'connect_timeout' => 5,
        // Retries on connection errors only (never on 4xx answers).
        'retries' => 2,
        'retry_delay' => 100, // milliseconds
        'verify' => (bool) env('KEYCLOAK_VERIFY_SSL', true),
    ],

    'routes' => [
        'enabled' => true,
        'prefix' => 'auth/keycloak',
        'middleware' => ['web'],
        'name' => 'keycloak.',
    ],

    // Auto-run the bundled users migrations. Disable and publish them
    // (tag "bhry98-keycloak-migrations") to customise.
    'migrations' => [
        'auto_load' => true,
    ],

    // Register the `keycloak-role` / `keycloak-scope` gates and the
    // @keycloakRole Blade directive.
    'gates' => true,
];
