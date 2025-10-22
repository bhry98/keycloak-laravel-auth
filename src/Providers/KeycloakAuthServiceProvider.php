<?php

namespace Bhry98\KeycloakAuth\Providers;

use Bhry98\KeycloakAuth\Http\Middleware\KeycloakApiMiddleware;
use Bhry98\KeycloakAuth\Http\Middleware\KeycloakMiddleware;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use Bhry98\KeycloakAuth\Services\KeycloakSocialiteProvider;

class KeycloakAuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/bhry98-keycloak.php', 'bhry98-keycloak');
        $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');

        // Register Socialite driver
        $socialite = $this->app->make(SocialiteFactory::class);
        $socialite->extend('keycloak', function ($app) use ($socialite) {
            $config = $app['config']['bhry98-keycloak'];
            return $socialite->buildProvider(KeycloakSocialiteProvider::class, [
                'client_id' => $config['client_id'],
                'client_secret' => $config['client_secret'],
                'redirect' => $config['redirect'],
            ]);
        });
        Route::aliasMiddleware('keycloak.api', KeycloakApiMiddleware::class);
        Route::aliasMiddleware('keycloak.web', KeycloakMiddleware::class);
    }
}
