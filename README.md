# 🛡️ Bhry98 Keycloak Auth for Laravel

A modern **Laravel authentication package** that integrates **Keycloak** using **Laravel Socialite** for both **API** and **Filament panel** authentication.

> Built for enterprise-grade Laravel apps needing Keycloak SSO integration.

---

## 🚀 Features

- ✅ Keycloak authentication using **Socialite**
- ✅ Works for **APIs** (JWT-based) and **Filament panels**
- ✅ Auto-refresh Keycloak tokens
- ✅ Role-based access via `HasKeycloakRoles` trait
- ✅ Middleware protection for routes
- ✅ Extendable service structure (OIDC, JWT, and Socialite)
- ✅ Plug-and-play with any Laravel app

---

## 📦 Installation

### Step 1: Install the package

```bash
composer require bhry98/keycloak-laravel-auth
```

---

### Step 2: Publish config file

```bash
php artisan vendor:publish --provider="Bhry98\KeycloakAuth\Providers\KeycloakAuthServiceProvider" --tag="config"
```

This will create a config file:

```
config/bhry98-keycloak.php
```

---

### Step 3: Add Keycloak credentials to `.env`

```env
KEYCLOAK_BASE_URL=https://keycloak-domain
KEYCLOAK_REALM=your-realm-id
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REDIRECT_URI=${APP_URL}/auth/callback
```

---

### Step 4: Register in Filament (optional)

```php
->authMiddleware([
    \Bhry98\KeycloakAuth\Http\Middleware\KeycloakMiddleware::class,
])
```

---

## 🔐 Middleware Usage

You can protect routes for both **API** and **Web** like this:

```php

// web 
Route::middleware(['keycloak.web'])->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});

// api
Route::middleware(['keycloak.api'])->group(function () {
    Route::get('/user', function (Request $request) {
        return $request->user();
    });
});
```

For **API frontends**, use token-based auth:

```bash
Authorization: Bearer <access_token>
```

---
### 🧱 Middleware

- `KeycloakMiddleware => keycloak.web` — checks for valid Keycloak access tokens basen on web session
- `KeycloakApiMiddleware => keycloak.api` — checks for valid Keycloak access tokens basen on api

---

## 🧠 Example Login Flow

### Web (Filament)

1. User clicks **Login with Keycloak**
2. Redirects to Keycloak
3. Keycloak returns `code` → package exchanges it for tokens
4. Laravel authenticates the user

### API (Frontend)

1. Frontend gets tokens via Keycloak
2. Sends `Authorization: Bearer <token>` with requests
3. Middleware validates and identifies the user

---

## 🧩 Folder Structure

```
src/
├── config/
│   └── bhry98-keycloak.php
├── Http/
│   ├── Controllers/
│   │   └── KeycloakAuthController.php
│   └── Middleware/
│       ├── KeycloakApiMiddleware.php
│       └── KeycloakMiddleware.php
├── Providers/
│   └── KeycloakAuthServiceProvider.php
├── routes/
│   └── web.php
└── Services/
    ├── KeycloakJWTService.php
    └── KeycloakSocialiteProvider.php
```

---
## 💡 Example `.env` Setup for API + Filament

```env
APP_URL=https://your-laravel-application-domain

KEYCLOAK_BASE_URL=https://keycloak-domain
KEYCLOAK_REALM=your-realm-id
KEYCLOAK_CLIENT_ID=your-client-id
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REDIRECT_URI=${APP_URL}/auth/callback
```

---

## 🧑‍💻 Author

**BHR Abdelrahman**    
💼 GitHub: [@bhry98](https://github.com/bhry98)

---

## 📄 License

This package is open-sourced software licensed under the **MIT license**.
