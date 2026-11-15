<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Console;

use Bhry98\KeycloakAuth\KeycloakManager;
use Illuminate\Console\Command;

class ClearCacheCommand extends Command
{
    protected $signature = 'keycloak:clear-cache';

    protected $description = 'Forget cached Keycloak realm keys, discovery documents and admin/service tokens';

    public function handle(KeycloakManager $keycloak): int
    {
        $keycloak->flushCache();

        $this->components->info('Keycloak cache cleared.');

        return self::SUCCESS;
    }
}
