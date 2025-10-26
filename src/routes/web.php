<?php

use Illuminate\Support\Facades\Route;
use Bhry98\KeycloakAuth\Http\Controllers\KeycloakAuthController;

Route::middleware(['web'])
    ->prefix('auth/keycloak')
    ->name('keycloak.')
    ->group(function () {
        Route::get('/login', [KeycloakAuthController::class, 'redirect'])->name('login');
        Route::get('/callback', [KeycloakAuthController::class, 'callback'])->name('callback');
        Route::get('/logout', [KeycloakAuthController::class, 'logout'])->name('logout');
    });
