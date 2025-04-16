<?php

namespace Tsal\Alexis\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class AlexisInfoController
{
    public function __invoke(): JsonResponse
    {
        return response()->json([
            'name' => 'Alexis Defend System',
            'version' => $this->getPackageVersion(),
            'status' => 'active'
        ]);
    }

    public function dashboard_or_login(Request $request) {
        $user_id = $request->session()->get('alexis-admin');

        if ($user_id === NULL) {
            return redirect('admin/alexis/login');
        } else {
            return view('alexis-admin-app');
        }
    }

    public function authenticate(Request $request) {
        $user = DB::table('users')
            ->where([
                'username' => $request->input('username'),
                'password' => md5($request->input('password')),
            ])
            ->first();

        if ($user !== NULL) {
            $request->session()->put('alexis-admin', $user->id);

            return redirect('admin/alexis');
        } else {
            return response()
                ->json([
                    'status' => 'error',
                    'error' => 'invalid credentials',
                ], Response::HTTP_UNAUTHORIZED);
        }
    }

    protected function getPackageVersion(): string
    {
        return json_decode(
            file_get_contents(__DIR__.'/../../../composer.json'),
            true
        )['version'] ?? '1.0.2-beta';
    }
}
