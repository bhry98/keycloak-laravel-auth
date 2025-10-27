<?php

return [
    "users_model" => \Bhry98\KeycloakAuth\Models\KCUserModel::class,
    'redirect' => env('KEYCLOAK_REDIRECT_URI', '/auth/keycloak/callback'),
    'base_url' => env('KEYCLOAK_BASE_URL', 'https://keycloak-domain'),
    'client_id' => env('KEYCLOAK_CLIENT_ID', 'laravel-app'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', ''),
    'realm' => env('KEYCLOAK_REALM', ''),
    "guard" => [
        "api" => [
            'client_id' => env('KC_API_CLIENT_ID', env('KEYCLOAK_CLIENT_ID', 'laravel-app')),
            'client_secret' => env('KC_API_CLIENT_SECRET', env('KEYCLOAK_CLIENT_SECRET', '')),
            'realm' => env('KC_API_REALM', env('KEYCLOAK_REALM', '')),
        ],
        "web" => [
            'client_id' => env('KC_WEB_CLIENT_ID', env('KEYCLOAK_CLIENT_ID', 'laravel-app')),
            'client_secret' => env('KC_WEB_CLIENT_SECRET', env('KEYCLOAK_CLIENT_SECRET', '')),
            'realm' => env('KC_WEB_REALM', env('KEYCLOAK_REALM', '')),
        ],
        "admin" => [
            'client_id' => env('KC_ADMIN_CLIENT_ID', env('KEYCLOAK_CLIENT_ID', 'laravel-app')),
            'client_secret' => env('KC_ADMIN_CLIENT_SECRET', env('KEYCLOAK_CLIENT_SECRET', '')),
            'realm' => env('KC_ADMIN_REALM', env('KEYCLOAK_REALM', '')),
        ],
    ]

];
