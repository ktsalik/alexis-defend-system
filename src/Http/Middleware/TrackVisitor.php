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
        $excluded = ['alexis-challenge', 'alexis-verify', 'health-check'];
        if (in_array($request->path(), $excluded)) {
            return $next($request);
        }

        $ip = $request->ip();
        
        // Log the request as "unresolved" by default
        AlexisLog::create([
            'ip_address' => $ip,
            'path' => $request->path(),
            'method' => $request->method(),
            'user_agent' => $request->userAgent(),
            'resolved' => false
        ]);

        if ($this->isSuspicious($request)) {
            if ($this->isBannable($request)) {
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

    protected function isSuspicious(Request $request): bool
    {
        return AlexisLog::where('ip_address', $request->ip())
            ->where('created_at', '>', now()->subMinute())
            ->where('resolved', false) // Only count unresolved requests
            ->count() > config('alexis.throttle.requests_per_minute');
    }

    protected function isBannable(Request $request): bool
    {
        $threshold = config('alexis.throttle.blacklist_after');
        $lookbackMinutes = config('alexis.throttle.lookback_minutes', 5);
        
        if ($threshold <= 0) {
            return false; // Never ban if threshold is misconfigured
        }
        
        return AlexisLog::where('ip_address', $request->ip())
            ->where('created_at', '>', now()->subMinutes($lookbackMinutes))
            ->where('resolved', false)
            ->count() > $threshold;
        }
}
