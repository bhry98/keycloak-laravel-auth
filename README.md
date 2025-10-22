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
php artisan vendor:publish --provider="Bhry98\KeycloakAuth\KeycloakAuthServiceProvider" --tag="config"
```

This will create a config file:

```
config/bhry98-keycloak.php
```

---

### Step 3: Add Keycloak credentials to `.env`

```env
KEYCLOAK_BASE_URL=https://sso.valleysoft-eg.com
KEYCLOAK_REALM=ERP
KEYCLOAK_CLIENT_ID=SS-Front
KEYCLOAK_CLIENT_SECRET=your-client-secret
KEYCLOAK_REDIRECT_URI=${APP_URL}/auth/callback
```

---

### Step 4: Configure Auth Guard

In `config/auth.php`:

```php
'guards' => [
    'keycloak' => [
        'driver' => 'keycloak',
        'provider' => 'users',
    ],
],
```

---

### Step 5: Register in Filament (optional)

```php
->authGuard('keycloak')
->authMiddleware([
    \Filament\Http\Middleware\Authenticate::class,
])
```

---

## 🔐 Middleware Usage

You can protect routes for both **API** and **Web** like this:

```php
Route::middleware(['keycloak'])->group(function () {
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

## ⚙️ Available Classes

### 🧩 Services

| Class | Description |
|-------|--------------|
| `KeycloakService` | Handles API communication with Keycloak |
| `KeycloakOIDCService` | Manages OpenID Connect (OIDC) login flows |
| `KeycloakJWTService` | Verifies and decodes JWT tokens |
| `KeycloakHelpers` | Helper functions (e.g., token parsing, realm URL builder) |

### 🔐 Guards

- `KeycloakGuard` — integrates with Laravel’s Auth system

### 🧱 Middleware

- `KeycloakMiddleware` — checks for valid Keycloak access tokens

### 🧰 Traits

- `HasKeycloakRoles` — adds role-based logic to your user model

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
├── Http/
│   ├── Controllers/
│   │   ├── LoginController.php
│   │   └── LogoutController.php
│   └── Middleware/
│       └── KeycloakMiddleware.php
├── Guards/
│   └── KeycloakGuard.php
├── Traits/
│   └── HasKeycloakRoles.php
├── Helpers/
│   └── KeycloakHelpers.php
├── Services/
│   ├── KeycloakService.php
│   ├── KeycloakOIDCService.php
│   └── KeycloakJWTService.php
├── routes/
│   └── web.php
└── KeycloakAuthServiceProvider.php
```

---

## 🧪 Testing

You can quickly test your guard in Tinker:

```bash
php artisan tinker
```

```php
Auth::guard('keycloak');
```

Expected output:
```
= Bhry98\KeycloakAuth\Guards\KeycloakGuard {#XXXX}
```

---

## 💡 Example `.env` Setup for API + Filament

```env
APP_URL=https://non-prod.portal.valleysoft-eg.com

KEYCLOAK_BASE_URL=https://sso.valleysoft-eg.com
KEYCLOAK_REALM=ERP
KEYCLOAK_CLIENT_ID=SS-Front
KEYCLOAK_CLIENT_SECRET=your-secret
KEYCLOAK_REDIRECT_URI=${APP_URL}/auth/callback
```

---

## 🧑‍💻 Author

**BHR Abdelrahman**  
Built for **Valleysoft ERP Systems**  
💼 GitHub: [@bhry98](https://github.com/bhry98)

---

## 📄 License

This package is open-sourced software licensed under the **MIT license**.
