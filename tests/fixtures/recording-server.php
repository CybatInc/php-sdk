<?php

/**
 * Router script for PHP's built-in dev server (php -S), used by CollectorTest
 * and CybatMiddlewareTest as a REAL local HTTP endpoint -- proves the SDK's
 * requests work byte-for-byte, not just in mocks. Mirrors _RecordingServer in
 * python/tests/test_collector.py.
 *
 * Each test spawns its own instance of this server with its own env vars
 * (CYBAT_TEST_LOG_FILE, CYBAT_TEST_FAIL_FIRST_N) so tests never interfere with
 * each other, since php -S does not share PHP variables between requests --
 * only what's written to disk persists across requests within one test's server.
 */

$logFile = getenv('CYBAT_TEST_LOG_FILE');
$failFirstN = (int) (getenv('CYBAT_TEST_FAIL_FIRST_N') ?: '0');
$countFile = $logFile . '.count';

$body = file_get_contents('php://input');
$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? null;

$count = is_file($countFile) ? ((int) file_get_contents($countFile)) + 1 : 1;
file_put_contents($countFile, (string) $count);

file_put_contents($logFile, json_encode(['apiKey' => $apiKey, 'events' => json_decode($body, true)]) . "\n", FILE_APPEND);

http_response_code($count <= $failFirstN ? 500 : 202);
