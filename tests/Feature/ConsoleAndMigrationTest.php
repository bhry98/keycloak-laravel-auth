<?php

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Schema;

it('decodes and verifies a token from the console', function () {
    $jwt = $this->keycloakToken(['sub' => 'console-user', 'roles' => ['admin']]);

    $this->artisan('keycloak:decode', ['token' => $jwt, '--guard' => 'api', '--verify' => true])
        ->expectsOutputToContain('Token is valid.')
        ->expectsOutputToContain('console-user')
        ->assertSuccessful();

    $this->artisan('keycloak:decode', ['token' => 'bad', '--verify' => true])->assertFailed();
});

it('clears the cache', function () {
    $this->artisan('keycloak:clear-cache')->assertSuccessful();
});

it('checks the connection of each guard', function () {
    Http::fake([
        '*/.well-known/openid-configuration' => Http::response(['issuer' => 'ok']),
        '*/protocol/openid-connect/certs' => Http::response($this->fakeKeycloak()->jwks()),
        '*/protocol/openid-connect/token' => Http::response(['access_token' => 'x', 'expires_in' => 60]),
    ]);

    $this->artisan('keycloak:check', ['--admin' => true])->assertSuccessful();
});

it('reports an unreachable keycloak from the check command', function () {
    Http::fake(['*' => Http::response('down', 503)]);

    $this->artisan('keycloak:check', ['guard' => ['api']])->assertFailed();
});

it('adds keycloak columns to an existing laravel users table', function () {
    Schema::drop('users');
    Schema::create('users', function (Blueprint $table) {
        $table->id();
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->rememberToken();
        $table->timestamps();
    });

    (require __DIR__.'/../../src/migrations/user_table.php')->up();

    expect(Schema::hasColumns('users', ['keycloak_id', 'keycloak_realm', 'username', 'email_verified', 'account_enable']))->toBeTrue();

    DB::table('users')->insert(['name' => 'n', 'email' => 'e@x.y', 'keycloak_id' => 'k']);
    expect(DB::table('users')->count())->toBe(1);
});

it('runs the bundled migrations idempotently', function () {
    (require __DIR__.'/../../src/migrations/user_table.php')->up();
    (require __DIR__.'/../../src/migrations/user_attributes.php')->up();

    expect(Schema::hasTable('users'))->toBeTrue()->and(Schema::hasTable('users_attributes'))->toBeTrue();
});
