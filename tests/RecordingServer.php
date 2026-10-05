<?php

declare(strict_types=1);

namespace Cybat\Sdk\Tests;

/** Spawns tests/fixtures/recording-server.php via PHP's built-in dev server as a real, isolated local HTTP endpoint for one test. */
final class RecordingServer
{
    /** @var resource */
    private $process;
    private readonly string $logFile;
    private readonly int $port;

    public function __construct(int $failFirstN = 0)
    {
        $this->logFile = tempnam(sys_get_temp_dir(), 'cybat_test_');
        $this->port = self::findFreePort();

        // $_ENV is empty under the default `variables_order` ini setting (no "E"),
        // so building a custom env array for proc_open would drop PATH entirely and
        // the shell would fail to find `php`. Passing null instead inherits the
        // real parent environment, and the two test-only vars are set via a shell
        // prefix directly in the command string.
        $script = __DIR__ . '/fixtures/recording-server.php';
        $cmd = sprintf(
            'CYBAT_TEST_LOG_FILE=%s CYBAT_TEST_FAIL_FIRST_N=%d exec php -S 127.0.0.1:%d %s',
            escapeshellarg($this->logFile),
            $failFirstN,
            $this->port,
            escapeshellarg($script),
        );

        $process = proc_open($cmd, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, null);
        if ($process === false) {
            throw new \RuntimeException('failed to start recording server');
        }
        $this->process = $process;
        $this->waitUntilReady();
    }

    public function url(): string
    {
        return "http://127.0.0.1:{$this->port}";
    }

    /** @return array<int, array{apiKey: ?string, events: array<mixed>}> */
    public function received(): array
    {
        if (!is_file($this->logFile)) {
            return [];
        }
        $lines = array_filter(explode("\n", file_get_contents($this->logFile) ?: ''));
        return array_map(static fn (string $line): array => json_decode($line, true), $lines);
    }

    public function close(): void
    {
        proc_terminate($this->process);
        proc_close($this->process);
        @unlink($this->logFile);
        @unlink($this->logFile . '.count');
    }

    private function waitUntilReady(): void
    {
        $deadline = microtime(true) + 5;
        while (microtime(true) < $deadline) {
            $conn = @fsockopen('127.0.0.1', $this->port, $errno, $errstr, 0.2);
            if ($conn !== false) {
                fclose($conn);
                return;
            }
            usleep(20_000);
        }
        throw new \RuntimeException('recording server did not become ready in time');
    }

    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        if ($socket === false) {
            throw new \RuntimeException("could not allocate a free port: {$errstr}");
        }
        $name = stream_socket_get_name($socket, false);
        fclose($socket);
        return (int) substr($name, strrpos($name, ':') + 1);
    }
}
