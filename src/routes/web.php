<?php

use Illuminate\Support\Facades\Route;
use Bhry98\KeycloakAuth\Http\Controllers\KeycloakAuthController;

Route::middleware(['web'])
    ->prefix('auth/keycloak')
    ->name('keycloak.')
    ->group(function () {
        Route::get('/login/{guard?}', [KeycloakAuthController::class, 'redirect'])->name('login');
        Route::get('/callback/{guard?}', [KeycloakAuthController::class, 'callback'])->name('callback');
        Route::get('/logout/{guard?}', [KeycloakAuthController::class, 'logout'])->name('logout');
    });
