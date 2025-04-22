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

        if (!is_trusted_ip($ip)) {
            http_response_code(404);
            header('Content-Type: text/plain');
            exit('Not Found');
        }

        if (in_array($ip, $this->get_all_server_ips())) {
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

    // Securely get the real client IP
    private function get_client_ip(): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Only trust headers if the request came from a trusted proxy
        if (is_trusted_ip($remoteAddr)) {
            foreach ([
                'HTTP_X_FORWARDED_FOR',
                'HTTP_CLIENT_IP',
                'HTTP_X_REAL_IP',
                'HTTP_X_CLUSTER_CLIENT_IP',
            ] as $key) {
                if (!empty($_SERVER[$key])) {
                    $ipList = explode(',', $_SERVER[$key]);
                    foreach ($ipList as $ip) {
                        $ip = trim($ip);
                        if (filter_var($ip, FILTER_VALIDATE_IP)) {
                            return $ip;
                        }
                    }
                }
            }
        }

        return $remoteAddr; // fallback, real IP seen by the server
    }

    // Returns true if an IP is trusted (Cloudflare, local, or server IP)
    private function is_trusted_ip(string $ip): bool
    {
        $trustedCidrs = [
            // Localhost & private networks
            '127.0.0.1',
            '::1',
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',

            // Cloudflare IPv4
            '173.245.48.0/20',
            '103.21.244.0/22',
            '103.22.200.0/22',
            '103.31.4.0/22',
            '141.101.64.0/18',
            '108.162.192.0/18',
            '190.93.240.0/20',
            '188.114.96.0/20',
            '197.234.240.0/22',
            '198.41.128.0/17',
            '162.158.0.0/15',
            '104.16.0.0/13',
            '104.24.0.0/14',
            '172.64.0.0/13',
            '131.0.72.0/22',

            // Cloudflare IPv6
            '2400:cb00::/32',
            '2606:4700::/32',
            '2803:f800::/32',
            '2405:b500::/32',
            '2405:8100::/32',
            '2a06:98c0::/29',
            '2c0f:f248::/32',
        ];

        // Include dynamic server IPs (self-calls)
        foreach (get_all_server_ips() as $serverIp) {
            $trustedCidrs[] = $serverIp;
        }

        // CIDR checker
        $ipInCidr = function ($ip, $cidr) {
            if (strpos($cidr, '/') === false) return $ip === $cidr;

            [$subnet, $bits] = explode('/', $cidr);
            $ipBin = inet_pton($ip);
            $subnetBin = inet_pton($subnet);

            if ($ipBin === false || $subnetBin === false) return false;

            $len = strlen($ipBin);
            $mask = str_repeat('f', intval($bits / 4));
            if ($bits % 4 !== 0) {
                $mask .= dechex(bindec(str_pad(str_repeat("1", $bits % 4), 4, "0")));
            }
            $mask = str_pad($mask, $len * 2, '0');
            $maskBin = pack('H*', $mask);

            return ($ipBin & $maskBin) === ($subnetBin & $maskBin);
        };

        foreach ($trustedCidrs as $cidr) {
            if ($ipInCidr($ip, $cidr)) {
                return true;
            }
        }

        return false;
    }

    // Returns array of the current server's IPs
    private function get_all_server_ips(): array
    {
        $ips = [];

        $records = dns_get_record(gethostname(), DNS_A + DNS_AAAA);
        foreach ($records as $r) {
            if (isset($r['ip'])) {
                $ips[] = $r['ip'];
            } elseif (isset($r['ipv6'])) {
                $ips[] = $r['ipv6'];
            }
        }

        if (!empty($_SERVER['SERVER_ADDR'])) {
            $ips[] = $_SERVER['SERVER_ADDR'];
        }

        return array_unique($ips);
    }
}
