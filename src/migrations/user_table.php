<?php

use Bhry98\KeycloakAuth\Models\KCUserModel;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * Creates the users table, or - when your app already has one (Laravel's
 * default migration) - adds the Keycloak columns to it.
 */
return new class extends Migration
{
    protected function table(): string
    {
        $model = config('bhry98-keycloak.users_model', KCUserModel::class);

        return (new $model)->getTable();
    }

    public function up(): void
    {
        $table = $this->table();

        if (! Schema::hasTable($table)) {
            Schema::create($table, function (Blueprint $table) {
                $table->id();
                $table->uuid('global_id')->nullable()->unique();
                $table->uuid('keycloak_id')->unique();
                $table->string('keycloak_realm')->index();
                $table->string('first_name', 50)->nullable();
                $table->string('last_name', 50)->nullable();
                $table->string('name', 200);
                $table->string('email')->unique();
                $table->string('username')->nullable()->unique();
                $table->string('avatar')->nullable();
                $table->string('type')->nullable();
                $table->string('locale', 5)->default('en');
                $table->boolean('email_verified')->default(false);
                $table->boolean('account_enable')->default(false);
                $table->rememberToken();
                $table->timestampsTz();
                $table->softDeletesTz();
            });

            return;
        }

        $columns = [
            'keycloak_id' => fn (Blueprint $t) => $t->string('keycloak_id', 64)->nullable()->unique(),
            'keycloak_realm' => fn (Blueprint $t) => $t->string('keycloak_realm')->nullable()->index(),
            'global_id' => fn (Blueprint $t) => $t->uuid('global_id')->nullable()->unique(),
            'first_name' => fn (Blueprint $t) => $t->string('first_name', 50)->nullable(),
            'last_name' => fn (Blueprint $t) => $t->string('last_name', 50)->nullable(),
            'username' => fn (Blueprint $t) => $t->string('username')->nullable()->unique(),
            'avatar' => fn (Blueprint $t) => $t->string('avatar')->nullable(),
            'type' => fn (Blueprint $t) => $t->string('type')->nullable(),
            'locale' => fn (Blueprint $t) => $t->string('locale', 5)->default('en'),
            'email_verified' => fn (Blueprint $t) => $t->boolean('email_verified')->default(false),
            'account_enable' => fn (Blueprint $t) => $t->boolean('account_enable')->default(true),
        ];

        foreach ($columns as $column => $definition) {
            if (! Schema::hasColumn($table, $column)) {
                Schema::table($table, fn (Blueprint $t) => $definition($t));
            }
        }

        // Keycloak users have no local password.
        if (Schema::hasColumn($table, 'password')) {
            Schema::table($table, fn (Blueprint $t) => $t->string('password')->nullable()->change());
        }
    }

    public function down(): void
    {
        // Intentionally left blank: never drop a users table that may predate this package.
    }
};
