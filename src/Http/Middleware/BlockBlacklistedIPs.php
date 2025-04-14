<?php

namespace Tsal\Alexis\Http\Middleware;

use Closure;
use Tsal\Alexis\Models\BlacklistedIp;
use Illuminate\Support\Facades\Cache;
use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Str;

class BlockBlacklistedIPs
{
    public function handle($request, Closure $next)
    {
        $ip = $this->getClientIp();
        $message = "If you think this is a mistake, please contact info@eltv.news.";
        
        if (Cache::has("blocked:{$ip}")) {
            return response()->json(['error' => 'IP blocked', 'message' => $message, 'ip' => $ip], 403);
        }

        $limiter = app(RateLimiter::class);
        $requests_allowed_per_minute = config('alexis.throttle.overall_requests_allowed_per_minute');
        if ($limiter->tooManyAttempts("block:{$ip}", $requests_allowed_per_minute)) { // 300 requests/minute
            BlacklistedIp::firstOrCreate(['ip_address' => $ip], ['reason' => "Rate limit exceeded ($requests_allowed_per_minute/minute was the limit)"]);
            return response()->json(['error' => 'Too many requests'], 429);
        }

        $limiter->hit("block:{$ip}", now()->addMinutes(1));

        $path = $request->path();

        // Block common attack paths
        $suspiciousPaths = ['/wp-admin', '/.env', '/adminer.php'];
        $suspiciousRegex = '/(wp-admin|admin[-\/](ajax|post|footer|login)|fckeditor|atomlib|function\.php|themes-install|owlmailer|engine\.php|uploads\/media\.php|adminfuns\.php7)/i';

        if (Str::contains($path, $suspiciousPaths) || preg_match($suspiciousRegex, $path)) {
            BlacklistedIp::firstOrCreate(
                ['ip_address' => $ip],
                ['reason' => "Suspicious path: {$path}"]
            );
            abort(403, 'Forbidden');
        }

        if (BlacklistedIp::where('ip_address', $ip)->exists()) {
            \Log::channel('security')->warning("Blocked IP access attempt", [
                'ip' => $ip,
                'user_agent' => $request->userAgent()
            ]);

            Cache::put("blocked:{$ip}", true, now()->addHours(6)); // Cache for 6 hours
            return response()->json(['error' => 'IP blocked', 'message' => $message, 'ip' => $ip], 403);
        }

        return $next($request);
    }

    private function getClientIp()
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
