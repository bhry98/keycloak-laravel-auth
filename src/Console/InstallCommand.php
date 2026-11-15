<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Console;

use Illuminate\Console\Command;

class InstallCommand extends Command
{
    protected $signature = 'keycloak:install {--migrations : Also publish the users migrations}';

    protected $description = 'Publish the Keycloak config and print the .env keys to set';

    public function handle(): int
    {
        $this->call('vendor:publish', ['--tag' => 'bhry98-keycloak-config']);

        if ($this->option('migrations')) {
            $this->call('vendor:publish', ['--tag' => 'bhry98-keycloak-migrations']);
        }

        $this->components->info('Add these keys to your .env file:');
        $this->line(<<<'ENV'
KEYCLOAK_BASE_URL=https://sso.example.com
KEYCLOAK_REALM=my-realm
KEYCLOAK_CLIENT_ID=my-laravel-app
KEYCLOAK_CLIENT_SECRET=
KEYCLOAK_REDIRECT_URI="${APP_URL}/auth/keycloak/callback/web"

# Admin REST API (service account with realm-management roles)
KC_ADMIN_REALM=my-realm
KC_ADMIN_CLIENT_ID=my-admin-client
KC_ADMIN_CLIENT_SECRET=
ENV);
        $this->newLine();
        $this->components->info('Then run: php artisan keycloak:check');

        return self::SUCCESS;
    }
}
