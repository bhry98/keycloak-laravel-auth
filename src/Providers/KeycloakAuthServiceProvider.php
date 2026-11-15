<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Providers;

use Bhry98\KeycloakAuth\Auth\KeycloakGuard;
use Bhry98\KeycloakAuth\Auth\UserProvisioner;
use Bhry98\KeycloakAuth\Console\CheckCommand;
use Bhry98\KeycloakAuth\Console\ClearCacheCommand;
use Bhry98\KeycloakAuth\Console\DecodeTokenCommand;
use Bhry98\KeycloakAuth\Console\InstallCommand;
use Bhry98\KeycloakAuth\Http\Middleware\KeycloakApiMiddleware;
use Bhry98\KeycloakAuth\Http\Middleware\KeycloakMiddleware;
use Bhry98\KeycloakAuth\Http\Middleware\RequireAllRoles;
use Bhry98\KeycloakAuth\Http\Middleware\RequirePermission;
use Bhry98\KeycloakAuth\Http\Middleware\RequireRole;
use Bhry98\KeycloakAuth\Http\Middleware\RequireScope;
use Bhry98\KeycloakAuth\Http\Middleware\VerifyKeycloakTokenForAgent;
use Bhry98\KeycloakAuth\Http\Middleware\VerifyKeycloakTokenForApiAgent;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Services\KeycloakSocialiteProvider;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;
use Illuminate\View\Compilers\BladeCompiler;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use Laravel\Socialite\SocialiteManager;

class KeycloakAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/bhry98-keycloak.php', 'bhry98-keycloak');

        $this->app->singleton(KeycloakManager::class, fn (Application $app) => new KeycloakManager($app));
        $this->app->alias(KeycloakManager::class, 'keycloak');
        $this->app->singleton(UserProvisioner::class, fn (Application $app) => new UserProvisioner($app->make(KeycloakManager::class)));
        $this->app->bind(KeycloakToken::class, fn (Application $app) => $app->make(KeycloakManager::class)->token());
    }

    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerSocialiteDrivers();
        $this->registerGuard();
        $this->registerMiddleware();
        $this->registerHttpMacros();
        $this->registerGates();

        if ($this->app['config']->get('bhry98-keycloak.routes.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        }

        if ($this->app['config']->get('bhry98-keycloak.migrations.auto_load', true)) {
            $this->loadMigrationsFrom(__DIR__.'/../migrations');
        }

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
                CheckCommand::class,
                ClearCacheCommand::class,
                DecodeTokenCommand::class,
            ]);
        }
    }

    protected function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $config = [__DIR__.'/../config/bhry98-keycloak.php' => config_path('bhry98-keycloak.php')];
        $this->publishes($config, 'bhry98-keycloak-config');
        $this->publishes($config, 'config'); // 1.x tag

        $this->publishes([
            __DIR__.'/../migrations/user_table.php' => database_path('migrations/2025_01_01_000000_create_keycloak_users_table.php'),
            __DIR__.'/../migrations/user_attributes.php' => database_path('migrations/2025_01_01_000001_create_keycloak_users_attributes_table.php'),
        ], 'bhry98-keycloak-migrations');
    }

    /**
     * Registers "keycloak.{guard}" Socialite drivers lazily, only when
     * Socialite is actually resolved (no cost on API requests).
     */
    protected function registerSocialiteDrivers(): void
    {
        $this->callAfterResolving(SocialiteFactory::class, function (SocialiteFactory $socialite, Application $app) {
            if (! $socialite instanceof SocialiteManager) {
                return;
            }

            $keycloak = $app->make(KeycloakManager::class);

            foreach ($keycloak->guards() as $guard) {
                $socialite->extend("keycloak.{$guard}", function () use ($socialite, $keycloak, $guard) {
                    $realm = $keycloak->realm($guard);

                    /** @var KeycloakSocialiteProvider $provider */
                    $provider = $socialite->buildProvider(KeycloakSocialiteProvider::class, [
                        'client_id' => $realm->clientId,
                        'client_secret' => $realm->clientSecret,
                        'redirect' => $realm->redirect,
                        'guzzle' => [
                            'timeout' => (int) $keycloak->config('http.timeout', 10),
                            'connect_timeout' => (int) $keycloak->config('http.connect_timeout', 5),
                            'verify' => (bool) $keycloak->config('http.verify', true),
                        ],
                    ]);

                    $provider->setGuard($guard);

                    if ($keycloak->config('web.pkce', true)) {
                        $provider->enablePKCE();
                    }

                    return $provider;
                });
            }
        });
    }

    /**
     * config/auth.php:  'api' => ['driver' => 'keycloak', 'keycloak' => 'api']
     */
    protected function registerGuard(): void
    {
        $this->callAfterResolving('auth', function (AuthManager $auth, Application $app) {
            $auth->extend('keycloak', function (Application $app, string $name, array $config) {
                $guard = new KeycloakGuard(
                    $app->make(KeycloakManager::class),
                    $app->bound('request') ? $app['request'] : null,
                    (string) ($config['keycloak'] ?? $config['realm'] ?? $name),
                    isset($config['provision']) ? (bool) $config['provision'] : null,
                );

                $app->refresh('request', $guard, 'setRequest');

                return $guard;
            });
        });
    }

    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app['router'];

        $router->aliasMiddleware('keycloak.api', KeycloakApiMiddleware::class);
        $router->aliasMiddleware('keycloak.web', KeycloakMiddleware::class);
        $router->aliasMiddleware('keycloak.role', RequireRole::class);
        $router->aliasMiddleware('keycloak.roles', RequireAllRoles::class);
        $router->aliasMiddleware('keycloak.scope', RequireScope::class);
        $router->aliasMiddleware('keycloak.permission', RequirePermission::class);
        $router->aliasMiddleware('keycloak.agent', VerifyKeycloakTokenForAgent::class);
        $router->aliasMiddleware('keycloak.agent.api', VerifyKeycloakTokenForApiAgent::class);
    }

    /**
     * Http::withKeycloakToken('api')     - service-account token (client credentials, cached)
     * Http::withKeycloakUserToken()      - forward the current user's token
     */
    protected function registerHttpMacros(): void
    {
        if (! PendingRequest::hasMacro('withKeycloakToken')) {
            PendingRequest::macro('withKeycloakToken', function (?string $guard = null, ?string $scope = null) {
                /** @var PendingRequest $this */
                return $this->withToken(app(KeycloakManager::class)->serviceToken($guard, $scope));
            });
        }

        if (! PendingRequest::hasMacro('withKeycloakUserToken')) {
            PendingRequest::macro('withKeycloakUserToken', function () {
                /** @var PendingRequest $this */
                $token = app(KeycloakManager::class)->token();

                return $token !== null ? $this->withToken($token->jwt()) : $this;
            });
        }
    }

    protected function registerGates(): void
    {
        if (! $this->app['config']->get('bhry98-keycloak.gates', true)) {
            return;
        }

        $this->callAfterResolving(GateContract::class, function (GateContract $gate) {
            $gate->define('keycloak-role', fn ($user, ...$roles) => (bool) app(KeycloakManager::class)->token()?->hasAnyRole($roles));
            $gate->define('keycloak-roles', fn ($user, ...$roles) => (bool) app(KeycloakManager::class)->token()?->hasAllRoles($roles));
            $gate->define('keycloak-scope', fn ($user, ...$scopes) => (bool) app(KeycloakManager::class)->token()?->hasAnyScope($scopes));
            $gate->define('keycloak-group', fn ($user, string $group) => (bool) app(KeycloakManager::class)->token()?->inGroup($group));
        });

        $this->callAfterResolving('blade.compiler', function (BladeCompiler $blade) {
            $blade->if('keycloakRole', fn (string ...$roles) => (bool) app(KeycloakManager::class)->token()?->hasAnyRole($roles));
            $blade->if('keycloakScope', fn (string ...$scopes) => (bool) app(KeycloakManager::class)->token()?->hasAnyScope($scopes));
        });
    }
}
