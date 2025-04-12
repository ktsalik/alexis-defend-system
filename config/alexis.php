<?php

return [
  'middleware_paths' => ['*'],
  'throttle' => [
      'requests_per_minute' => env('ALEXIS_REQUESTS_PER_MINUTE', 60),
      'lookback_minutes' => env('ALEXIS_LOOKBACK_MINUTES', 3),
      'blacklist_after' => env('ALEXIS_BLACKLIST_AFTER', 3 * 100), // blacklist after > ALEXIS_BLACKLIST_AFTER requests in ALEXIS_LOOKBACK_MINUTES
      'overall_requests_allowed_per_minute' => env('ALEXIS_OVERALL_REQUESTS_ALLOWED_PER_MINUTE', 150) // blacklist after OVERALL_REQUESTS_ALLOWED_PER_MINUTE
  ],
  'recaptcha' => [
    'site_key' => env('RECAPTCHA_SITE_KEY'),
    'secret_key' => env('RECAPTCHA_SECRET_KEY'),
  ],
];
