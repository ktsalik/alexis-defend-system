<?php

namespace Tsal\Alexis\Models;

use Illuminate\Database\Eloquent\Model;

class BlacklistedIp extends Model
{
    protected $fillable = ['ip_address', 'reason'];
    protected $table = 'blacklisted_ips';
}
