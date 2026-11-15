<?php

use Bhry98\KeycloakAuth\Http\Controllers\KeycloakAuthController;
use Illuminate\Support\Facades\Route;

Route::middleware((array) config('bhry98-keycloak.routes.middleware', ['web']))
    ->prefix((string) config('bhry98-keycloak.routes.prefix', 'auth/keycloak'))
    ->name((string) config('bhry98-keycloak.routes.name', 'keycloak.'))
    ->group(function () {
        Route::get('/login/{guard?}', [KeycloakAuthController::class, 'redirect'])->name('login');
        Route::get('/callback/{guard?}', [KeycloakAuthController::class, 'callback'])->name('callback');
        Route::get('/logout/{guard?}', [KeycloakAuthController::class, 'logout'])->name('logout');
    });
