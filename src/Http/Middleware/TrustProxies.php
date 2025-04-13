<?php

namespace Tsal\Alexis\Http\Middleware;

use Illuminate\Http\Request;
use Illuminate\Foundation\Http\Middleware\TrustProxies as Middleware;

class TrustProxies extends Middleware
{
    /**
     * The trusted proxies for this application.
     *
     * @var array|string
     */
    protected $proxies = '*'; // Trust all proxies (Cloudflare, etc.)
    
    /**
     * The headers that should be used to detect proxies.
     *
     * @var array
     */
    protected $headers = Request::HEADER_X_FORWARDED_ALL;  // Use all forwarded headers
}