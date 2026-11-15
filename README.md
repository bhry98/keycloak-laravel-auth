# Keycloak Laravel Auth

[![Tests](https://github.com/bhry98/keycloak-laravel-auth/actions/workflows/tests.yml/badge.svg)](https://github.com/bhry98/keycloak-laravel-auth/actions/workflows/tests.yml)
[![Latest Version](https://img.shields.io/packagist/v/bhry98/keycloak-laravel-auth.svg)](https://packagist.org/packages/bhry98/keycloak-laravel-auth)
[![License](https://img.shields.io/packagist/l/bhry98/keycloak-laravel-auth.svg)](LICENSE)

Complete **Keycloak** integration for **Laravel 11, 12 and 13**: browser SSO, a stateless JWT API guard,
roles / scopes / UMA permissions, service-to-service tokens and a full Admin REST API client. It's
built to be fast: tokens are verified offline against cached realm keys, so authenticating an API request
makes no network call.

📖 **Documentation: <https://bhry98.github.io/packages/keycloak-laravel-auth/>**

```php
// routes/api.php: protect APIs with offline-verified bearer tokens
Route::middleware(['keycloak.api', 'keycloak.role:admin'])->get('/orders', OrderController::class);

// Anywhere: read the current token
Keycloak::token()->hasRole('billing:invoice-viewer');

// Call another microservice with a cached service-account token
Http::withKeycloakToken('api')->get('https://orders.internal/api/orders');

// Manage users, roles and groups through the Admin API
$id = Keycloak::users()->create(['username' => 'jane', 'email' => 'jane@example.com', 'password' => 'S3cret!']);
Keycloak::users()->assignRealmRoles($id, ['editor']);
```

## Features

| | |
|---|---|
| **Browser SSO** | Authorization-code flow with PKCE via Socialite, silent token refresh, proper RP-initiated logout. |
| **API authentication** | `keycloak.api` middleware **and** a `keycloak` auth-guard driver; offline JWT verification (signature, `exp`, `iss`, `aud`, `typ`, algorithm allow-list), automatic key-rotation handling. |
| **Authorization** | `keycloak.role`, `keycloak.roles`, `keycloak.scope`, `keycloak.permission` (UMA) middleware, `keycloak-role` gates, `@keycloakRole` Blade directive, `HasKeycloakRoles` trait. |
| **Users** | Optional user provisioning into your database (write skipped while claims are unchanged), or fully stateless `KeycloakUser`s. |
| **Service-to-service** | Cached client-credentials tokens, `Http::withKeycloakToken()`, `Http::withKeycloakUserToken()`, token exchange. |
| **OIDC client** | Password, refresh, client-credentials, code and token-exchange grants; introspection (cached), userinfo, logout, revoke, discovery. |
| **Admin REST API** | Users, realm roles, client roles, groups, clients, sessions, events, required-action e-mails, lazy pagination. Admin token cached for its real lifetime with automatic retry on 401. |
| **Multi-realm** | Any number of named guards (realm + client pairs). |
| **Developer tools** | `Keycloak::fake()` / `actingAsKeycloakUser()` test helpers, `keycloak:check`, `keycloak:decode`, `keycloak:clear-cache`, events for every step. |

## Installation

```bash
composer require bhry98/keycloak-laravel-auth
php artisan keycloak:install
php artisan migrate
```

```env
KEYCLOAK_BASE_URL=https://sso.example.com
KEYCLOAK_REALM=my-realm
KEYCLOAK_CLIENT_ID=my-laravel-app
KEYCLOAK_CLIENT_SECRET=secret
KEYCLOAK_REDIRECT_URI="${APP_URL}/auth/keycloak/callback/web"
```

```bash
php artisan keycloak:check   # verifies discovery, realm keys and client credentials
```

## Quick start

```php
// Web SSO: guests are sent to Keycloak, tokens are refreshed silently
Route::middleware(['web', 'keycloak.web'])->group(function () {
    Route::get('/dashboard', DashboardController::class);
});

// API: config/auth.php -> 'guards' => ['api' => ['driver' => 'keycloak', 'keycloak' => 'api']]
Route::middleware('auth:api')->get('/me', fn (Request $request) => $request->user());
```

Testing your app:

```php
use Bhry98\KeycloakAuth\Testing\InteractsWithKeycloak;

$this->actingAsKeycloakUser(['roles' => ['admin']])
    ->getJson('/api/orders')
    ->assertOk();
```

See the [documentation](https://bhry98.github.io/packages/keycloak-laravel-auth/) for every feature,
configuration option and the [upgrade guide from 1.x](https://bhry98.github.io/packages/keycloak-laravel-auth/upgrade/).

## Testing

```bash
composer test
composer analyse
```

## License

MIT © [Bhr Abdelrahman](https://github.com/bhry98)
