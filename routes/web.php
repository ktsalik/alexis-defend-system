<?php

use Illuminate\Http\Request;
use Tsal\Alexis\Http\Controllers\AlexisInfoController;
use Tsal\Alexis\Http\Middleware\BlockBlacklistedIPs;
use Tsal\Alexis\Http\Middleware\TrackVisitor;
use Tsal\Alexis\Models\BlacklistedIp;
use Tsal\Alexis\Models\AlexisLog;

// Routes that SHOULD be tracked
Route::middleware(['web', TrackVisitor::class])->group(function () {
    Route::get('/alexis', AlexisInfoController::class)
        ->middleware(BlockBlacklistedIPs::class);
    
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
            'ip'     => $request->ip()
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
        $recaptchaSecret = config('services.recaptcha.secret_key');
        $recaptchaResponse = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret={$recaptchaSecret}&response={$token}");
        $recaptchaData = json_decode($recaptchaResponse);

        // Check if verification was successful and that the score meets your threshold (e.g., 0.5)
        if (!$recaptchaData->success) {
            BlacklistedIp::firstOrCreate(
                ['ip_address' => $request->ip()],
                ['reason' => 'Failed verification']
            );
            abort(403, 'Verification failed. IP blacklisted.');
        }
    
        // Mark all previous requests from this IP as resolved
        AlexisLog::where('ip_address', $request->ip())
            ->where('resolved', false)
            ->update(['resolved' => true]);
    
        $request->session()->forget('puzzle');
        
        return redirect('/');
    })->name('alexis.verify');
});
