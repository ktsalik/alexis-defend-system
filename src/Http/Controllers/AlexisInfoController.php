<?php

namespace Tsal\Alexis\Http\Controllers;

use Illuminate\Http\JsonResponse;

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

    protected function getPackageVersion(): string
    {
        return json_decode(
            file_get_contents(__DIR__.'/../../../composer.json'),
            true
        )['version'] ?? '1.0.2-beta';
    }
}
