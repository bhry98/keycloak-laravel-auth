<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Tests;

use Bhry98\KeycloakAuth\Facades\Keycloak;
use Bhry98\KeycloakAuth\Providers\KeycloakAuthServiceProvider;
use Bhry98\KeycloakAuth\Testing\InteractsWithKeycloak;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use InteractsWithKeycloak, RefreshDatabase;

    public const BASE = 'https://kc.test';

    protected function getPackageProviders($app): array
    {
        return [
            SocialiteServiceProvider::class,
            KeycloakAuthServiceProvider::class,
        ];
    }

    protected function getPackageAliases($app): array
    {
        return ['Keycloak' => Keycloak::class];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app['config'];

        $config->set('app.debug', false);
        $config->set('app.url', 'https://app.test');
        $config->set('database.default', 'testbench');
        $config->set('database.connections.testbench', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        $config->set('cache.default', 'array');

        $config->set('bhry98-keycloak.base_url', self::BASE);
        $config->set('bhry98-keycloak.realm', 'demo');
        $config->set('bhry98-keycloak.client_id', 'laravel-app');
        $config->set('bhry98-keycloak.client_secret', 'secret');
        $config->set('bhry98-keycloak.redirect_after_logout', 'https://app.test/bye');
        $config->set('bhry98-keycloak.guard', [
            'web' => [
                'realm' => 'demo',
                'client_id' => 'web-app',
                'client_secret' => 'web-secret',
                'redirect' => 'https://app.test/auth/keycloak/callback/web',
                'scopes' => ['openid', 'email', 'profile'],
            ],
            'api' => [
                'realm' => 'demo',
                'client_id' => 'api-app',
                'client_secret' => 'api-secret',
            ],
            'admin' => [
                'realm' => 'master',
                'client_id' => 'admin-cli-sa',
                'client_secret' => 'admin-secret',
            ],
        ]);

        $config->set('auth.guards.kc', ['driver' => 'keycloak', 'keycloak' => 'api']);
    }

    /** URL of an OpenID Connect endpoint of the demo realm. */
    protected function oidcUrl(string $endpoint, string $realm = 'demo'): string
    {
        return self::BASE."/realms/{$realm}/protocol/openid-connect/{$endpoint}";
    }

    protected function adminUrl(string $path = '', string $realm = 'demo'): string
    {
        return self::BASE."/admin/realms/{$realm}".($path === '' ? '' : '/'.ltrim($path, '/'));
    }
}
