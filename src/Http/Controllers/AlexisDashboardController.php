<?php

namespace Tsal\Alexis\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;

class AlexisDashboardController
{
    public function index (Request $request)
    {
        return response()->json([
            'name' => 'Alexis Defend System Dashboard',
        ]);
    }

    public function get_requests(Request $request)
    {
        $perPage = $request->input('per_page', 10);

        $request_logs = DB::table('alexis_logs')
            ->orderBy('id', 'DESC')
            ->paginate($perPage);

        return response()->json($request_logs);
    }

    public function get_blocked_ips(Request $request)
    {
        $perPage = $request->input('per_page', 10);

        $blocked_ips = DB::table('blacklisted_ips')
            ->orderBy('id', 'DESC')
            ->paginate($perPage);

        return response()->json($blocked_ips);
    }
}
