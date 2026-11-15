<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Console;

use Bhry98\KeycloakAuth\KeycloakManager;
use Illuminate\Console\Command;
use Throwable;

class DecodeTokenCommand extends Command
{
    protected $signature = 'keycloak:decode {token : The access token (JWT)} {--guard= : Guard to verify against} {--verify : Verify signature, expiry, issuer and audience}';

    protected $description = 'Print the claims, roles and expiry of a Keycloak access token';

    public function handle(KeycloakManager $keycloak): int
    {
        $jwt = (string) $this->argument('token');
        $guard = $this->option('guard') ?: null;

        try {
            $token = $this->option('verify') ? $keycloak->validate($jwt, $guard) : $keycloak->decode($jwt, $guard);
        } catch (Throwable $e) {
            $this->components->error($e->getMessage());

            return self::FAILURE;
        }

        if ($this->option('verify')) {
            $this->components->info('Token is valid.');
        }

        $this->components->twoColumnDetail('Subject', (string) $token->subject());
        $this->components->twoColumnDetail('Username', (string) $token->username());
        $this->components->twoColumnDetail('Client (azp)', (string) $token->azp());
        $this->components->twoColumnDetail('Issuer', (string) $token->issuer());
        $this->components->twoColumnDetail('Expires', $token->expiresAt()?->toDateTimeString().($token->isExpired() ? ' <fg=red>(expired)</>' : ''));
        $this->components->twoColumnDetail('Realm roles', implode(', ', $token->realmRoles()));
        foreach ($token->allClientRoles() as $client => $roles) {
            $this->components->twoColumnDetail("Client roles [{$client}]", implode(', ', $roles));
        }
        $this->components->twoColumnDetail('Scopes', implode(' ', $token->scopes()));

        $this->newLine();
        $this->line((string) json_encode($token->claims(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

        return self::SUCCESS;
    }
}
