<?php

namespace Tsal\Alexis\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AdminSecretCheck
{
    public function handle(Request $request, Closure $next)
    {
        $secret = $request->input('secret', 'acbd18db4cc2f85cedef654fccc4a4d8');

        if ($secret !== md5(config('alexis.secret'))) {
            abort(404);
        }

        return $next($request);
    }
}
