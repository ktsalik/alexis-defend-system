<?php

namespace Tsal\Alexis\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class AdminSecretCheck
{
    public function handle(Request $request, Closure $next)
    {
        $secret = $request->input('secret', '5d41402abc4b2a76b9719d911017c592');

        if ($secret !== md5(config('alexis.secret'))) {
            abort(404);
        }

        return $next($request);
    }
}
