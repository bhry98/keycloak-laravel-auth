<?php

namespace Bhry98\KeycloakAuth\Providers;

use Bhry98\KeycloakAuth\Http\Middleware\KeycloakApiMiddleware;
use Bhry98\KeycloakAuth\Http\Middleware\KeycloakMiddleware;
use Illuminate\Contracts\Container\BindingResolutionException;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use Bhry98\KeycloakAuth\Services\KeycloakSocialiteProvider;

class KeycloakAuthServiceProvider extends ServiceProvider
{
    /**
     * @throws BindingResolutionException
     */
    public function boot(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/bhry98-keycloak.php', 'bhry98-keycloak');
        $this->loadRoutesFrom(__DIR__ . '/../routes/web.php');
        $this->loadMigrationsFrom(__DIR__ . '/../migrations');
        // Register Socialite driver
        $socialite = $this->app->make(SocialiteFactory::class);
        foreach (config("bhry98-keycloak.guard") as $guard => $guardValue) {
            $socialite->extend("keycloak.$guard", function ($app) use ($socialite, $guard, $guardValue) {
                $config = $guardValue;
                $provider = $socialite->buildProvider(KeycloakSocialiteProvider::class, [
                    'client_id' => $config['client_id'],
                    'client_secret' => $config['client_secret'],
                    'realm' => $config['realm'],
                    'redirect' => $config['redirect'],
                ]);
                $provider->setGuard($guard);
                return $provider;
            });
//            Route::aliasMiddleware("keycloak.api.$guard", KeycloakApiMiddleware::class);
//            Route::aliasMiddleware("keycloak.web.$guard", KeycloakMiddleware::class);
        }
//        // Register Socialite driver
//        $socialite = $this->app->make(SocialiteFactory::class);
//        $socialite->extend('keycloak', function ($app) use ($socialite) {
//            $config = $app['config']['bhry98-keycloak'];
//            return $socialite->buildProvider(KeycloakSocialiteProvider::class, [
//                'client_id' => $config['client_id'],
//                'client_secret' => $config['client_secret'],
//                'redirect' => $config['redirect'],
//            ]);
//        });
        Route::aliasMiddleware('keycloak.api', KeycloakApiMiddleware::class);
        Route::aliasMiddleware('keycloak.web', KeycloakMiddleware::class);

    }
}
