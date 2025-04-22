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
        $ip = $this->get_client_ip();

        if ($this->has_server_secret_key($request)) {
            return $next($request);
        }
        
        $message = "If you think this is a mistake, please contact info@eltv.news.";
        
        if (Cache::has("blocked:{$ip}")) {
            return response()->json(['error' => 'IP blocked', 'message' => $message, 'ip' => $ip], 403);
        }

        $limiter = app(RateLimiter::class);
        $requests_allowed_per_minute = config('alexis.throttle.overall_requests_allowed_per_minute');
        if ($limiter->tooManyAttempts("block:{$ip}", $requests_allowed_per_minute)) {
            BlacklistedIp::firstOrCreate(['ip_address' => $ip], ['reason' => "Rate limit exceeded ($requests_allowed_per_minute/minute was the limit)"]);
            return response()->json(['error' => 'Too many requests'], 429);
        }

        $limiter->hit("block:{$ip}", now()->addMinutes(1));

        $path = $request->path();

        // Block known suspicious paths based on recent activity
        $suspiciousPaths = [
            'admin/fckeditor/editor/filemanager/updates.php',
            'admin/ty.php',
            'admin/images/slider/CUfcfoH.php',
            'admin/atomlib.php',
            'admin/upload/themes-install.php',
            'admin/fckeditor/editor/filemanager/owlmailer.php',
            'admin/controller/extension/extension/blue.php',
            'admin/uploads/lv.php',
            'admin/uploads/media.php',
            'admin/fckeditor/editor/filemanager/alfanew.php',
            'admin/editor/engine.php',
            'admin/function.php',
            'admin-footer.php',
            'admin-ajax.php',
            'admin/uploads',
            'admin-post.php',
            'adminfuns.php7',
            'administrator/index.php',
            'admin/editor',
            'admin_logs.php',
            'admin-console',
            'admin.aspx',
            'admin.html',
            'admin/auth',
            'admin/install',
            'admin/setup',
            'admin/upgrade',
            'admin_backup',
            'admin_console',
            'admin_panel',
            'admincp',
            'adminer',
            'adminer.php',
            'administrator',
            'admin/config.json',
            'admin/config.php',
            'admin/settings.php',
            'admin/config',
            'admin/people',
            'admin/reports/status',
            'admin-dev',
            'admin/indexupload.php',
            'admin/images/slider',
            'admin/fckeditor/editor/filemanager',
            'admin/controller/extension/extension',
            'admin/uploads/images',
            'admin/.env',
            'admin/uploads/worksec.php',
            'admin/upload/css.php',
            'admin-app/.env',
            'admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
            'admin/log/error.log',
            'admin/errors.log',
            'admin/logs/error.log',
            'admin/logs/errors.log',
            'admin/error.log',
            'admin/phpinfo.php',
            'admin-panel/.git/config',
            'administrator/.git/config',
            'admin/fckeditor/editor/filemanager/connectors/php/connector.php',
            'admin/fckeditor/editor/filemanager/connectors/asp/connector.asp',
            'admin/upload',
            'admin/.git/config',
            'admin/info.php',
            'administrator/phpinfo.php',
            'admin/autoload_classmap.php',
            'adminPanel.js',
            'admin_log.txt',
            'admin_phpinfo.php',
            'admin_report.csv',
            'admin_routes.yaml',
            'admin_routes.yml',
            'admin_secrets.yml',
            'admin_settings.yml',
            'admin.pl',
            'admin.php',
            'administrator/manifests/files/joomla.xml',
            'admin.jsa',
            'administrator/templates/bluestork/error.php',
            'administrator/templates/hathor/index.php',
            'administrator/templates/hathor/error.php',
            'administrator/templates/isis/index.php',
            'administrator/templates/isis/error.php',
        ];

        if (in_array(ltrim($path, '/'), $suspiciousPaths)) {
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

    function has_server_secret_key($request): bool
    {
        $authHeader = $request->header('X-Server-Auth');

        return !empty($authHeader) && $authHeader === md5(config('alexis.server_secret'));
    }
}
