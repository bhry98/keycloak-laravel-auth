# Changelog

## 2.0.0 - 2026-11-15

A rewrite focused on completeness, performance and correctness. The 1.x public API keeps working;
see the [upgrade guide](https://bhry98.github.io/packages/keycloak-laravel-auth/upgrade/).

### Added
- `Keycloak` facade / `KeycloakManager` as the single entry point.
- `keycloak` auth-guard driver for stateless bearer-token APIs.
- Offline JWT verification with cached JWKS, key-rotation handling, issuer / audience / type / algorithm checks.
- `KeycloakToken` with role, client-role, scope and group helpers.
- `keycloak.role`, `keycloak.roles`, `keycloak.scope` and `keycloak.permission` (UMA) middleware.
- `keycloak-role`, `keycloak-roles`, `keycloak-scope`, `keycloak-group` gates and `@keycloakRole` / `@keycloakScope` Blade directives.
- `HasKeycloakRoles` trait for user models and a stateless `KeycloakUser`.
- OIDC client: password, refresh, client-credentials, code and token-exchange grants, introspection, userinfo, logout, revoke, discovery, UMA permissions.
- Cached service-account tokens and the `Http::withKeycloakToken()` / `Http::withKeycloakUserToken()` macros.
- Admin API resources: users, realm roles, groups, clients (with client roles) and realm events.
- `keycloak:install`, `keycloak:check`, `keycloak:decode` and `keycloak:clear-cache` commands.
- Events: `TokenValidated`, `TokenValidationFailed`, `UserLoggedIn`, `UserLoggedOut`, `TokenRefreshed`, `UserProvisioned`.
- Testing helpers: `Keycloak::fake()`, `InteractsWithKeycloak` (`actingAsKeycloakUser()`, `actingAsKeycloakWebUser()`).
- PKCE for the browser login, configurable routes, cache store and HTTP timeouts / retries.
- Laravel 11, 12 and 13 support; test suite and CI.

### Changed
- `keycloak.web` checks the token locally and refreshes it with the refresh token, instead of calling
  introspection on every request. Opt back in with `KEYCLOAK_WEB_VALIDATION=introspect` (now cached).
- `keycloak.api` now resolves the user, so `$request->user()` works.
- The admin token is cached for its real lifetime (was a fixed 55 seconds) and refreshed on 401.
- Logout uses RP-initiated logout (`id_token_hint` + `post_logout_redirect_uri`) so users come back to your app.
- The users migration adds the Keycloak columns when a `users` table already exists, instead of failing.
- API user provisioning skips the database write while claims are unchanged.

### Fixed
- Leftover `dd()` calls in `KeycloakRoleService::assignRoleToGroup()` and `KeycloakGroupService::createGroup()`.
- `firebase/php-jwt` was used but not required.
- `VerifyKeycloakTokenForApiAgent` built a wrong certificates URL and always used the first key.
- An invalid OAuth state cleared the whole application cache (`Cache::clear()`).
- `KeycloakRoleService::guard('web')` managed the admin realm instead of the guard's realm.
- Session fixation: the session is regenerated after login.

### Removed
- The `creativeorange/gravatar` dependency (Gravatar URLs are built directly).
