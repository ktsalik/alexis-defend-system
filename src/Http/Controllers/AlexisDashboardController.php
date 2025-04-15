<?php

namespace Tsal\Alexis\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\DB;
use Illuminate\Database\QueryException;

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
        $search_query = $request->input('search', NULL);

        $request_logs = DB::table('alexis_logs')
            ->when($search_query !== NULL && strlen($search_query) >= 2, function ($query) use ($search_query) {
                $query->where(function ($subQuery) use ($search_query) {
                    $subQuery->where('path', 'LIKE', "%$search_query%")
                        ->orWhere('ip_address', 'LIKE', "%$search_query%")
                        ->orWhere('user_agent', 'LIKE', "%$search_query%")
                        ->orWhere('created_at', 'LIKE', "%$search_query%")
                        ->orWhere('method', 'LIKE', "%$search_query%");
                });

                $query->orderByRaw("
                    CASE 
                        WHEN path LIKE ? THEN 1
                        WHEN ip_address LIKE ? THEN 2
                        WHEN user_agent LIKE ? THEN 3
                        WHEN created_at LIKE ? THEN 4
                        WHEN method LIKE ? THEN 5
                        ELSE 6
                    END
                ", [
                    "%$search_query%",
                    "%$search_query%",
                    "%$search_query%",
                    "%$search_query%",
                    "%$search_query%",
                ]);
            })
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

    public function check_ip(Request $request) {
        $ip = $request->input('ip');

        if ($ip !== NULL) {
            $block_info = DB::table('blacklisted_ips')
                ->where([
                    'ip_address' => $ip
                ])
                ->first();

            $requests_info = DB::table('alexis_logs')
                ->where([
                    'ip_address' => $ip
                ])
                ->count();

            return response()->json([
                'status' => 'ok',
                'is_blocked' => $block_info !== NULL,
                'reason' => $block_info !== NULL ? $block_info->reason : NULL,
                'request_count' => $requests_info
            ], 200);
        } else {
            return response()->json([
                'status' => 'error',
                'error' => 'no ip provided'
            ], 400);
        }
    }

    public function block_ip(Request $request) {
        $data = $request->input('data');
        $ip = $data['ip'];
        $reason = (isset($data['reason']) && strlen($data['reason'] > 0)) ? $data['reason'] : 'Manually blocked';

        if ($ip !== NULL) {
            try {
                DB::table('blacklisted_ips')->insert([
                    'ip_address' => $ip,
                    'reason' => $reason
                ]);

                return response()->json([
                    'status' => 'ok',
                ], 201);
            } catch (QueryException $e) {
                if ($e->getCode() == '23000') { // Integrity constraint violation (e.g., duplicate entry)
                    return response()->json([
                        'status' => 'error',
                        'error' => 'ip is already blocked'
                    ], 409);
                }
        
                return response()->json([
                    'status' => 'error',
                    'error' => 'Database error'
                ], 500);
            }
        } else {
            return response()->json([
                'status' => 'error',
                'error' => 'no ip provided'
            ], 400);
        }
    }

    public function unblock_ip(Request $request) {
        $data = $request->input('data');
        $ip = $data['ip'];

        DB::table('blacklisted_ips')
            ->where([
                'ip_address' => $ip,
            ])
            ->delete();

        return response()->json([
            'status' => 'ok',
        ]);
    }
}
