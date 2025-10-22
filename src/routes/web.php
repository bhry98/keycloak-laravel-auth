<?php

use Illuminate\Support\Facades\Route;
use Bhry98\KeycloakAuth\Http\Controllers\KeycloakAuthController;
Route::middleware(['web'])->group(function () {
    Route::get('/keycloak/login', [KeycloakAuthController::class, 'redirect'])->name('keycloak.login');
    Route::get('/keycloak/callback', [KeycloakAuthController::class, 'callback'])->name('keycloak.callback');
});
//
//Route::prefix('keycloak')->name('keycloak.')->group(function () {
//    Route::get('/login', [KeycloakAuthController::class, 'redirect'])->name('login');
//    Route::get('/callback', [KeycloakAuthController::class, 'callback'])->name('callback');
//    Route::get('/logout', [KeycloakAuthController::class, 'logout'])->name('logout');
//});
