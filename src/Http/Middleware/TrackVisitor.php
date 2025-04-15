<?php

namespace Tsal\Alexis\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tsal\Alexis\Models\AlexisLog;
use Tsal\Alexis\Models\BlacklistedIp;

class TrackVisitor
{
    public function handle(Request $request, Closure $next)
    {
        $secret = $request->input('secret', NULL);

        if ($secret === md5(config('alexis.secret'))) {
            return $next($request);
        }

        $excluded = ['alexis-challenge', 'alexis-verify', 'alexis-dashboard'];
        if (in_array($request->path(), $excluded)) {
            return $next($request);
        }

        $ip = $this->get_client_ip();
        
        // Log the request as "unresolved" by default
        AlexisLog::create([
            'ip_address' => $ip,
            'path' => $request->path(),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
            'resolved' => false
        ]);

        if ($this->isSuspicious($ip)) {
            if ($this->isBannable($ip)) {
                $threshold = config('alexis.throttle.blacklist_after');

                BlacklistedIp::firstOrCreate(
                    ['ip_address' => $ip],
                    ['reason' => "Exceeded {$threshold} requests in 5 minutes"]
                );

                return response()->json(['error' => 'IP blocked'], 403);
            } else {
                return redirect()->route('alexis.challenge');
            }
        }

        return $next($request);
    }

    protected function isSuspicious($ip): bool
    {
        return AlexisLog::where('ip_address', $ip)
            ->where('created_at', '>', now()->subMinute())
            ->where('resolved', false) // Only count unresolved requests
            ->count() > config('alexis.throttle.requests_per_minute');
    }

    protected function isBannable($ip): bool
    {
        $threshold = config('alexis.throttle.blacklist_after');
        $lookbackMinutes = config('alexis.throttle.lookback_minutes', 5);
        
        if ($threshold <= 0) {
            return false; // Never ban if threshold is misconfigured
        }
        
        return AlexisLog::where('ip_address', $ip)
            ->where('created_at', '>', now()->subMinutes($lookbackMinutes))
            ->where('resolved', false)
            ->count() > $threshold;
    }

    private function get_client_ip()
    {
        foreach ([
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        ] as $key) {
            if (!empty($_SERVER[$key])) {
                $ipList = explode(',', $_SERVER[$key]);
                foreach ($ipList as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                        return $ip;
                    }
                }
            }
        }

        return request()->ip(); // fallback
    }
}
