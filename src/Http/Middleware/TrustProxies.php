<?php

namespace Tsal\Alexis\Http\Middleware;

use Illuminate\Http\Middleware\TrustProxies as Middleware;
use Symfony\Component\HttpFoundation\Request as SymfonyRequest;

class TrustProxies extends Middleware
{
    /**
     * Trust all proxies (e.g. Cloudflare, Nginx).
     */
    protected $proxies = '*';

    /**
     * Use forwarded headers to detect client info.
     */
    protected $headers =
        SymfonyRequest::HEADER_X_FORWARDED_FOR |
        SymfonyRequest::HEADER_X_FORWARDED_HOST |
        SymfonyRequest::HEADER_X_FORWARDED_PORT |
        SymfonyRequest::HEADER_X_FORWARDED_PROTO;
}