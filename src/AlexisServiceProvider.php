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
        // $this->app['router']->aliasMiddleware('alexis.block', BlockBlacklistedIPs::class);
        $this->app['router']->pushMiddlewareToGroup('web', BlockBlacklistedIPs::class);
        $this->app['router']->pushMiddlewareToGroup('web', TrackVisitor::class);
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
