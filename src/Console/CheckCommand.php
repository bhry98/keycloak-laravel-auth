<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Console;

use Bhry98\KeycloakAuth\KeycloakManager;
use Illuminate\Console\Command;
use Throwable;

class CheckCommand extends Command
{
    protected $signature = 'keycloak:check {guard?* : Guards to check (default: all)} {--admin : Also request an Admin API token}';

    protected $description = 'Check connectivity, realm keys and client credentials for each Keycloak guard';

    public function handle(KeycloakManager $keycloak): int
    {
        $guards = $this->argument('guard') ?: $keycloak->guards();
        $failed = false;
        $rows = [];

        foreach ($guards as $guard) {
            $realm = $keycloak->realm($guard);

            $discovery = $this->attempt(fn () => $keycloak->oidc($guard)->discovery()['issuer'] ?? '?');
            $keys = $this->attempt(function () use ($keycloak, $realm) {
                $keycloak->jwks()->forget($realm);

                return count($keycloak->jwks()->keys($realm)).' signing key(s)';
            });
            $credentials = $realm->clientSecret === ''
                ? ['skipped (public client)', true]
                : $this->attempt(fn () => isset($keycloak->oidc($guard)->clientCredentials()['access_token']) ? 'ok' : 'no token');

            $rows[] = [$guard, $realm->realm, $realm->clientId, $discovery[0], $keys[0], $credentials[0]];
            $failed = $failed || ! $discovery[1] || ! $keys[1];
        }

        $this->table(['Guard', 'Realm', 'Client', 'Discovery', 'JWKS', 'Client credentials'], $rows);

        if ($this->option('admin')) {
            [$message, $ok] = $this->attempt(fn () => $keycloak->admin()->token(true) !== '' ? 'Admin API token: ok' : 'no token');
            $ok ? $this->components->info($message) : $this->components->error($message);
            $failed = $failed || ! $ok;
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }

    /** @return array{0: string, 1: bool} */
    protected function attempt(callable $check): array
    {
        try {
            return ['<fg=green>'.$check().'</>', true];
        } catch (Throwable $e) {
            return ['<fg=red>'.mb_strimwidth($e->getMessage(), 0, 80, '...').'</>', false];
        }
    }
}
