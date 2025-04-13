<?php

namespace Tsal\Alexis;

use Illuminate\Support\ServiceProvider;
use Tsal\Alexis\Http\Middleware\{
    BlockBlacklistedIPs,
    TrackVisitor,
    AdminSecretCheck
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
        $this->app['router']->aliasMiddleware('alexis.block', BlockBlacklistedIPs::class);
        $this->app['router']->aliasMiddleware('alexis.track', TrackVisitor::class);
        $this->app['router']->aliasMiddleware('alexis.secret', AdminSecretCheck::class);
        
        $paths = config('alexis.middleware_paths', ['*']);

        if (in_array('*', $paths)) {
            $this->app['router']->pushMiddlewareToGroup('web', TrustProxies::class);
            $this->app['router']->pushMiddlewareToGroup('web', BlockBlacklistedIPs::class);
        } else {
            $this->app['router']->middlewareGroup('alexis.dynamic', [
                BlockBlacklistedIPs::class,
                TrackVisitor::class,
            ]);

            $this->app->booted(function () use ($paths) {
                $this->app['router']->matched(function ($event) use ($paths) {
                    $currentPath = trim($event->request->path(), '/');

                    foreach ($paths as $path) {
                        $normalizedPath = trim($path, '/');

                        if (str_starts_with($currentPath, $normalizedPath)) {
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
