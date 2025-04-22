<?php

namespace Tsal\Alexis\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Tsal\Alexis\Models\AlexisLog;
use Tsal\Alexis\Models\BlacklistedIp;
use Illuminate\Support\Facades\DB;

class TrackVisitor
{
    public function handle(Request $request, Closure $next)
    {
        $secret = $request->input('secret', NULL);

        if ($secret === md5(config('alexis.secret'))) {
            return $next($request);
        }

        $alexis_admin_id_connected = $request->session()->get('alexis-admin');
        $user_id_connected = $request->session()->get('user');

        if ($alexis_admin_id_connected !== NULL || $user_id_connected !== NULL) {
            $user = DB::table('users')->find($alexis_admin_id_connected);

            if ($user) {
                return $next($request);
            }

            $user = DB::table('users')->find($user_id_connected);

            if ($user) {
                return $next($request);
            }
        }

        $excluded = ['alexis-challenge', 'alexis-verify'];
        if (in_array($request->path(), $excluded)) {
            return $next($request);
        }

        $ip = $this->get_client_ip();
        
        if (in_array($ip, $this->get_all_server_ips())) {
            return $next($request);
        }
        
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

    // Securely get the real client IP
    private function get_client_ip(): string
    {
        $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Only trust headers if the request came from a trusted proxy
        if ($this->is_trusted_ip($remoteAddr)) {
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
        foreach ($this->get_all_server_ips() as $serverIp) {
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

    function get_all_server_ips(): array
    {
        $ips = [];

        // If running on localhost/dev environment — skip DNS resolution
        if (in_array(PHP_SAPI, ['cli', 'cli-server']) || $_SERVER['SERVER_NAME'] === 'localhost') {
            return ['127.0.0.1', '::1'];
        }

        // Try resolving hostname via DNS (production-safe)
        $hostname = gethostname();
        if ($hostname) {
            $records = @dns_get_record($hostname, DNS_A + DNS_AAAA, $authns, $addtl);
            foreach ($records as $r) {
                if (isset($r['ip'])) {
                    $ips[] = $r['ip'];
                } elseif (isset($r['ipv6'])) {
                    $ips[] = $r['ipv6'];
                }
            }
        }

        // Add $_SERVER['SERVER_ADDR'] if available
        if (!empty($_SERVER['SERVER_ADDR'])) {
            $ips[] = $_SERVER['SERVER_ADDR'];
        }

        return array_unique($ips);
    }
}
