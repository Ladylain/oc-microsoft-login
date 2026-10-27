<?php namespace Ladylain\MicrosoftLogin\Updates;

use Schema;
use October\Rain\Database\Schema\Blueprint;
use October\Rain\Database\Updates\Migration;

return new class extends Migration
{
    public function up()
    {
        Schema::create('ladylain_microsoftlogin_identities', function (Blueprint $table) {
            $table->increments('id');
            $table->unsignedInteger('user_id')->unique();
            $table->string('tenant_id', 64);
            $table->string('object_id', 64);
            $table->string('email')->nullable();
            $table->timestamp('last_login_at')->nullable();
            $table->timestamps();

            $table->unique(['tenant_id', 'object_id']);
            $table->foreign('user_id')->references('id')->on('backend_users')->cascadeOnDelete();
        });
    }

    public function down()
    {
        Schema::dropIfExists('ladylain_microsoftlogin_identities');
    }
};
