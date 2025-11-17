<?php

use Bhry98\KeycloakAuth\Models\KCUserModel;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create((new KCUserModel)->getTable(), function (Blueprint $table) {
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
            $table->string('locale',5)->default('en');
            $table->boolean('email_verified')->default(false);
            $table->boolean('account_enable')->default(false);
            $table->timestampsTz();
            $table->softDeletesTz();
        });
    }

    public function down(): void
    {
        Schema::disableForeignKeyConstraints();
        Schema::dropIfExists((new KCUserModel)->getTable());
        Schema::enableForeignKeyConstraints();
    }
};
