<?php

return [
  'throttle' => [
      'requests_per_minute' => env('ALEXIS_REQUESTS_PER_MINUTE', 70),
      'blacklist_after' => env('ALEXIS_BLACKLIST_AFTER', 5 * 70), // blacklist after > 350 requests in 5 minutes (works after requests_per_minute exceeded)
      'lookback_minutes' => env('ALEXIS_LOOKBACK_MINUTES', 5)
    ],
];
