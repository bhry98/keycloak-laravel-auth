<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (Schema::hasTable('users_attributes')) {
            return;
        }

        Schema::create('users_attributes', function (Blueprint $table) {
            $table->id();
            // No database-level foreign key: this migration can run before the users table one.
            $table->unsignedBigInteger('user_id')->index();
            $table->string('key')->index();
            $table->longText('value')->nullable();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('users_attributes');
    }
};
