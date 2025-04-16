<?php

namespace Tsal\Alexis\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Response;

class AlexisAdminAuthenticate
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure(\Illuminate\Http\Request): (\Illuminate\Http\Response|\Illuminate\Http\RedirectResponse)  $next
     * @return \Illuminate\Http\Response|\Illuminate\Http\RedirectResponse
     */
    public function handle(Request $request, Closure $next)
    {
        $user_id_connected = $request->session()->get('alexis-admin');

        if ($user_id_connected !== NULL) {
            $user_is_admin = DB::table('users')->where('id', $user_id_connected)->first();

            if ($user_is_admin !== NULL) {
                return $next($request);
            } else {
                return response('', 404);
            }
        } else {
            return response('', 404);
        }
    }
}
