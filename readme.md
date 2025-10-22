```
packages/
└── KeycloakAuth/
    ├── composer.json
    ├── src/
    │   ├── KeycloakAuthServiceProvider.php
    │   ├── Http/
    │   │   ├── Controllers/
    │   │   │   ├── LoginController.php
    │   │   │   └── LogoutController.php
    │   │   └── Middleware/
    │   │       └── KeycloakMiddleware.php
    │   ├── Services/
    │   │   ├── KeycloakOIDCService.php
    │   │   └── KeycloakJWTService.php
    │   ├── Traits/
    │   │   └── HasKeycloakRoles.php
    │   ├── Helpers/
    │   │   └── KeycloakHelpers.php
    │   ├── Guards/
    │   │   └── KeycloakGuard.php
    │   └── config/
    │       └── keycloak.php
    └── routes/
        └── web.php

```


```
client ID

1034705586606-4gmjoc3q2131qjrseapdg7ng2ir95452.apps.googleusercontent.com
```
```
client sec.

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
```