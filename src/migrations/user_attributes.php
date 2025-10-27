<?php

use Bhry98\KeycloakAuth\Models\KCUserAttributesModel;
use Bhry98\KeycloakAuth\Models\KCUserModel;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::disableForeignKeyConstraints();
        Schema::create((new KCUserAttributesModel)->getTable(), function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->references('id')->on((new KCUserModel)->getTable())->cascadeOnDelete()->cascadeOnUpdate();
            $table->string('key');
            $table->longText('value')->nullable();
        });
        Schema::enableForeignKeyConstraints();
    }

    public function down(): void
    {
        Schema::disableForeignKeyConstraints();
        Schema::dropIfExists((new KCUserAttributesModel)->getTable());
        Schema::enableForeignKeyConstraints();
    }
};
