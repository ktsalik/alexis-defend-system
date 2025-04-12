<?php

namespace Tsal\Alexis;

use Illuminate\Support\ServiceProvider;
use Tsal\Alexis\Http\Middleware\{
    BlockBlacklistedIPs,
    TrackVisitor
};
use Tsal\Alexis\Console\Commands\AutoBlacklistIPs;

class AlexisServiceProvider extends ServiceProvider
{
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/alexis.php', 'alexis'
        );

        $this->commands([
            AutoBlacklistIPs::class,
        ]);
    }

    public function boot()
    {
        $this->registerMiddleware();
        $this->loadResources();
        $this->publishAssets();
    }

    protected function registerMiddleware(): void
    {
        $paths = config('alexis.middleware_paths', ['*']);

        if (in_array('*', $paths)) {
            $this->app['router']->pushMiddlewareToGroup('web', BlockBlacklistedIPs::class);
            $this->app['router']->pushMiddlewareToGroup('web', TrackVisitor::class);
        } else {
            $this->app['router']->aliasMiddleware('alexis.block', BlockBlacklistedIPs::class);
            $this->app['router']->aliasMiddleware('alexis.track', TrackVisitor::class);

            // Register a route middleware wrapper for path-specific application
            $this->app['router']->middlewareGroup('alexis.dynamic', [
                BlockBlacklistedIPs::class,
                TrackVisitor::class,
            ]);

            // Listen to route-matching and dynamically attach middleware
            $this->app->booted(function () use ($paths) {
                $this->app['router']->matched(function ($event) use ($paths) {
                    $currentPath = $event->request->path();

                    foreach ($paths as $path) {
                        if (str_starts_with($currentPath, ltrim($path, '/'))) {
                            $event->route->middleware('alexis.dynamic');
                            break;
                        }
                    }
                });
            });
        }
    }

    protected function loadResources(): void
    {
        $this->loadViewsFrom(__DIR__.'/resources/views', 'alexis');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
    }

    protected function publishAssets(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/alexis.php' => config_path('alexis.php'),
            ], 'alexis-config');

            $this->publishes([
                __DIR__.'/resources/views' => resource_path('views/vendor/alexis'),
            ], 'alexis-views');
        }
    }
}
