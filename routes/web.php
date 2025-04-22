<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Tsal\Alexis\Helpers\IpHelper;
use Illuminate\Support\Facades\DB;
use Tsal\Alexis\Http\Controllers\AlexisInfoController;
use Tsal\Alexis\Http\Controllers\AlexisDashboardController;
use Tsal\Alexis\Http\Middleware\BlockBlacklistedIPs;
use Tsal\Alexis\Http\Middleware\TrackVisitor;
use Tsal\Alexis\Models\BlacklistedIp;
use Tsal\Alexis\Models\AlexisLog;

// Routes that SHOULD be tracked
Route::middleware(['web', TrackVisitor::class])->group(function () {
    // Route::get('/alexis', AlexisInfoController::class)
    //     ->middleware(BlockBlacklistedIPs::class);
    
    // Add other routes you want to track here
});

// Challenge routes that SHOULD NOT be tracked
Route::middleware('web')->group(function () {
    // Show puzzle challenge
    Route::get('/alexis-challenge', function (Request $request) {
        $num1 = rand(1, 10);
        $num2 = rand(1, 10);
        
        $request->session()->put('puzzle', [
            'answer' => $num1 + $num2,
            'ip'     => IpHelper::getClientIp()
        ]);

        return view('alexis::puzzle', [
            'num1' => $num1,
            'num2' => $num2
        ]);
    })->name('alexis.challenge');

    Route::post('/alexis-verify', function (Request $request) {
        // Retrieve the reCAPTCHA token from the request
        $token = $request->input('g-recaptcha-response');
        if (!$token) {
            return response()->json([
                'status' => 'error',
                'message' => 'Missing reCAPTCHA token.',
                'input' => $request->all(),
            ]);
        }
    
        // Verify reCAPTCHA token with Google
        $recaptchaSecret = config('alexis.recaptcha.secret_key');
        $recaptchaResponse = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptchaSecret}&response={$token}");
        $recaptchaData = json_decode($recaptchaResponse);

        // Check if verification was successful and that the score meets your threshold (e.g., 0.5)
        if (!$recaptchaData->success) {
            BlacklistedIp::firstOrCreate(
                ['ip_address' => IpHelper::getClientIp()],
                ['reason' => 'Failed verification']
            );
            abort(403, 'Verification failed. IP blacklisted.');
        }
    
        // Mark all previous requests from this IP as resolved
        AlexisLog::where('ip_address', IpHelper::getClientIp())
            ->where('resolved', false)
            ->update(['resolved' => true]);
    
        $request->session()->forget('puzzle');
        
        return redirect('/');
    })->name('alexis.verify');
});

Route::middleware(['web', 'alexis.block', 'alexis.track', 'alexis.secret'])
    ->prefix('admin/alexis')
    ->group(function () {
        // Route::get('/', [AlexisDashboardController::class, 'index'])->name('alexis.index');
        Route::get('/', [AlexisInfoController::class, 'dashboard_or_login']);
        Route::get('/login', function() {
            return view('alexis::alexis-admin-app-login');
        });
        Route::post('/authenticate', [AlexisInfoController::class, 'authenticate']);
        
        Route::get('/requests', [AlexisDashboardController::class, 'get_requests'])->name('alexis.requests')->middleware('alexis.admin-authenticate');
        Route::get('/blocked-ips', [AlexisDashboardController::class, 'get_blocked_ips'])->name('alexis.blocked-ips')->middleware('alexis.admin-authenticate');
        Route::get('/check-ip', [AlexisDashboardController::class, 'check_ip'])->name('alexis.check-ip')->middleware('alexis.admin-authenticate');
        Route::post('/block-ip', [AlexisDashboardController::class, 'block_ip'])->name('alexis.block-ip')->middleware('alexis.admin-authenticate');
        Route::post('/unblock-ip', [AlexisDashboardController::class, 'unblock_ip'])->name('alexis.unblock-ip')->middleware('alexis.admin-authenticate');
        
        Route::any('{catchall}', function (Request $request, $catchall) {
            $user_id_connected = $request->session()->get('alexis-admin');

            if ($user_id_connected !== null) {
                $user = DB::table('users')->find($user_id_connected);

                if ($user) {
                    return view('alexis-admin-app');
                } else {
                    return response('', 404);
                }
            } else {
                return response('', 404);
            }
        })->where('catchall', '.*');
    });
