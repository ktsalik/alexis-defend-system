<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
        Schema::create('alexis_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address');
            $table->string('path');
            $table->string('method')->nullable();
            $table->text('user_agent')->nullable();
            $table->timestamp('created_at')->useCurrent();
        });

        Schema::table('alexis_logs', function (Blueprint $table) {
            $table->boolean('resolved')->default(false)->after('user_agent');
        });
    }
};
