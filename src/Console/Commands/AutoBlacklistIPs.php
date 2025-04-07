<?php

namespace Tsal\Alexis\Console\Commands;

use Illuminate\Console\Command;
use Tsal\Alexis\Models\AlexisLog;
use Tsal\Alexis\Models\BlacklistedIp;

class AutoBlacklistIPs extends Command
{
    protected $signature = 'alexis:blacklist';
    protected $description = 'Automatically blacklist suspicious IPs';

    public function handle()
    {
        $threshold = config('alexis.throttle.blacklist_after');
        
        $suspiciousIPs = AlexisLog::select('ip_address')
            ->where('created_at', '>', now()->subMinute())
            ->groupBy('ip_address')
            ->havingRaw("COUNT(*) > {$threshold}")
            ->pluck('ip_address');

        foreach ($suspiciousIPs as $ip) {
            BlacklistedIp::firstOrCreate(
                ['ip_address' => $ip],
                ['reason' => "Exceeded {$threshold} requests in 5 minutes"]
            );
        }

        $this->info("Blacklisted {$suspiciousIPs->count()} IPs");
    }
}
