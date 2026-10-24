<?php

declare(strict_types=1);

namespace Cybat\Sdk\Tests;

use Cybat\Sdk\Collector;
use Cybat\Sdk\Options;
use Cybat\Sdk\StatusFilter;
use PHPUnit\Framework\TestCase;

final class CollectorTest extends TestCase
{
    private ?RecordingServer $server = null;

    protected function tearDown(): void
    {
        $this->server?->close();
        $this->server = null;
    }

    private static function makeEvent(int $status = 200): array
    {
        return [
            'method' => 'GET',
            'url' => '/x',
            'status' => $status,
            'remoteIp' => '203.0.113.9',
            'userAgent' => 'ua',
            'latencyMs' => 1,
            'bytesSent' => 0,
            'timestamp' => '2026-09-26T00:00:00.000Z',
        ];
    }

    // -- Options validation ---------------------------------------------------

    public function testRequiresApiKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Options(apiKey: '', gcpProjectId: 'p');
    }

    public function testRequiresACloudProjectId(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Options(apiKey: 'k');
    }

    public function testMutuallyExclusiveCloudProjects(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Options(apiKey: 'k', gcpProjectId: 'p', awsProjectId: 'a');
    }

    public function testGcpProjectIdRoutesToGcp(): void
    {
        $o = new Options(apiKey: 'k', gcpProjectId: 'p');
        $this->assertSame('https://gcp-ingest.cybat.co', $o->ingestUrl);
    }

    public function testAwsProjectIdRoutesToAws(): void
    {
        $o = new Options(apiKey: 'k', awsProjectId: 'a');
        $this->assertSame('https://aws-ingest.cybat.co', $o->ingestUrl);
    }

    public function testExplicitIngestUrlWins(): void
    {
        $o = new Options(apiKey: 'k', gcpProjectId: 'p', ingestUrl: 'http://localhost:1234');
        $this->assertSame('http://localhost:1234', $o->ingestUrl);
    }

    public function testBodyMaxBytesIsClamped(): void
    {
        $this->assertSame(256, (new Options(apiKey: 'k', gcpProjectId: 'p', bodyMaxBytes: 1))->bodyMaxBytes);
        $this->assertSame(8192, (new Options(apiKey: 'k', gcpProjectId: 'p', bodyMaxBytes: 999_999))->bodyMaxBytes);
    }

    // -- Wire behavior (real HTTP via php -S) ---------------------------------

    public function testSendsBatchWithApiKeyHeader(): void
    {
        $this->server = new RecordingServer();
        $collector = new Collector(new Options(apiKey: 'k123', gcpProjectId: 'p', ingestUrl: $this->server->url()));

        $collector->record(self::makeEvent());

        $received = $this->server->received();
        $this->assertCount(1, $received);
        $this->assertSame('k123', $received[0]['apiKey']);
        $this->assertSame('/x', $received[0]['events'][0]['url']);
    }

    public function testStatusFilterDropsTheWholeEvent(): void
    {
        $this->server = new RecordingServer();
        $collector = new Collector(new Options(
            apiKey: 'k',
            gcpProjectId: 'p',
            ingestUrl: $this->server->url(),
            statusFilter: StatusFilter::errors(),
        ));

        $collector->record(self::makeEvent(200));
        $this->assertCount(0, $this->server->received());

        $collector->record(self::makeEvent(403));
        $this->assertCount(1, $this->server->received());
    }

    public function testRetriesOn5xxThenSucceeds(): void
    {
        $this->server = new RecordingServer(failFirstN: 1);
        $collector = new Collector(new Options(
            apiKey: 'k',
            gcpProjectId: 'p',
            ingestUrl: $this->server->url(),
            maxRetries: 2,
            retryBackoffMs: 10,
        ));

        $collector->record(self::makeEvent());

        $this->assertCount(2, $this->server->received()); // 1 failed attempt + 1 that succeeded
    }

    public function testGivesUpAfterMaxRetries(): void
    {
        $this->server = new RecordingServer(failFirstN: 999);
        $collector = new Collector(new Options(
            apiKey: 'k',
            gcpProjectId: 'p',
            ingestUrl: $this->server->url(),
            maxRetries: 2,
            retryBackoffMs: 10,
        ));

        $collector->record(self::makeEvent());

        $this->assertCount(3, $this->server->received()); // 1 initial + 2 retries, then dropped
    }

    public function testNeverThrowsWhenTheEndpointIsUnreachable(): void
    {
        $collector = new Collector(new Options(
            apiKey: 'k',
            gcpProjectId: 'p',
            ingestUrl: 'http://127.0.0.1:1',
            maxRetries: 1,
            retryBackoffMs: 5,
            timeoutSeconds: 1,
        ));

        $collector->record(self::makeEvent()); // must not throw
        $this->addToAssertionCount(1);
    }

    // -- captureBodyFor ---------------------------------------------------------

    private static function bodyCollector(array $overrides = []): Collector
    {
        $defaults = ['apiKey' => 'k', 'gcpProjectId' => 'p', 'ingestUrl' => 'http://127.0.0.1:1'];
        return new Collector(new Options(...array_merge($defaults, $overrides)));
    }

    public function testCaptureBodyForOffByDefault(): void
    {
        $c = self::bodyCollector();
        $this->assertNull($c->captureBodyFor('{"password":"hunter2"}', 'application/json', 200));
    }

    public function testCaptureBodyForRedactsAndReturnsWireKeys(): void
    {
        $c = self::bodyCollector(['captureBody' => true]);
        $out = $c->captureBodyFor('{"password":"hunter2xyz"}', 'application/json', 200);
        $this->assertNotNull($out);
        $this->assertStringNotContainsString('hunter2xyz', $out['body']);
        $this->assertFalse($out['bodyTruncated']);
    }

    public function testCaptureBodyForSkipsUncapturableContentType(): void
    {
        $c = self::bodyCollector(['captureBody' => true]);
        $this->assertNull($c->captureBodyFor("\x00\x01", 'application/octet-stream', 200));
    }

    public function testCaptureBodyForSkipsEmpty(): void
    {
        $c = self::bodyCollector(['captureBody' => true]);
        $this->assertNull($c->captureBodyFor(null, 'application/json', 200));
        $this->assertNull($c->captureBodyFor('', 'application/json', 200));
    }

    public function testCaptureBodyForBodyStatusFilterIndependentOfStatusFilter(): void
    {
        $c = self::bodyCollector(['captureBody' => true, 'bodyStatusFilter' => StatusFilter::errors()]);
        $this->assertNull($c->captureBodyFor('{"a":1}', 'application/json', 200));
        $this->assertNotNull($c->captureBodyFor('{"a":1}', 'application/json', 403));
    }

    public function testCaptureBodyForFlagsTruncation(): void
    {
        $c = self::bodyCollector(['captureBody' => true, 'bodyMaxBytes' => 64]);
        $big = str_repeat('A', 5000) . "' UNION SELECT 1 --" . str_repeat('B', 5000);
        $out = $c->captureBodyFor($big, 'text/plain', 200);
        $this->assertTrue($out['bodyTruncated']);
        $this->assertLessThanOrEqual(300, strlen($out['body']));
        $this->assertStringContainsString('UNION SELECT', $out['body']);
    }

    public function testCaptureBodyForRedactsExtraSensitiveKeys(): void
    {
        $c = self::bodyCollector(['captureBody' => true, 'extraSensitiveKeys' => ['account_number']]);
        $out = $c->captureBodyFor('{"account_number":"9988776655","note":"hi"}', 'application/json', 200);
        $this->assertStringNotContainsString('9988776655', $out['body']);
    }

    public function testCaptureBodyForWithoutExtraSensitiveKeysLeavesFieldUntouched(): void
    {
        $c = self::bodyCollector(['captureBody' => true]);
        $out = $c->captureBodyFor('{"account_number":"9988776655"}', 'application/json', 200);
        $this->assertStringContainsString('9988776655', $out['body']);
    }
}
