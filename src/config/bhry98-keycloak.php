<?php

return [
    'client_id' => env('KEYCLOAK_CLIENT_ID', 'laravel-app'),
    'client_secret' => env('KEYCLOAK_CLIENT_SECRET', ''),
    'redirect' => env('KEYCLOAK_REDIRECT_URI', '/keycloak/callback'),

    'base_url' => env('KEYCLOAK_BASE_URL', 'https://sso.valleysoft-eg.com'),
    'realm' => env('KEYCLOAK_REALM', 'ERP'),
];
