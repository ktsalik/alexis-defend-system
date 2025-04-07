<?php

namespace Tsal\Alexis\Models;

use Illuminate\Database\Eloquent\Model;

class AlexisLog extends Model
{
    protected $table = 'alexis_logs';
    
    protected $fillable = [
        'ip_address',
        'path',
        'method', 
        'user_agent',
        'created_at'
    ];
    
    public $timestamps = false;
}
