<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up()
    {
      Schema::create('blacklisted_ips', function (Blueprint $table) {
        $table->id();
        $table->string('ip_address')->unique();
        $table->text('reason')->nullable();
        $table->timestamps();
      });
    }
};
