<?php

declare(strict_types=1);

namespace Cybat\Sdk\Tests;

use Cybat\Sdk\CybatMiddleware;
use Cybat\Sdk\Options;
use Cybat\Sdk\StatusFilter;
use Nyholm\Psr7\Response;
use Nyholm\Psr7\ServerRequest;
use Nyholm\Psr7\Stream;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Drives the real CybatMiddleware::process -> Collector -> HTTP path against
 * a real local server (RecordingServer), same pattern as the Flask/ASGI
 * integration tests in the Python SDK. PSR-7 objects are real (Nyholm's
 * implementation, a require-dev-only dependency), never mocked -- only the
 * downstream "app" being wrapped is a small test double.
 */
final class CybatMiddlewareTest extends TestCase
{
    private ?RecordingServer $server = null;

    protected function tearDown(): void
    {
        $this->server?->close();
        $this->server = null;
    }

    private static function handlerReturning(int $status, string $body = ''): RequestHandlerInterface
    {
        return new class ($status, $body) implements RequestHandlerInterface {
            public function __construct(private readonly int $status, private readonly string $body)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                return new Response($this->status, [], $this->body);
            }
        };
    }

    /** A handler that actually reads the request body, like a real controller deserializing JSON would. */
    private static function handlerThatReadsBody(int $status): RequestHandlerInterface
    {
        return new class ($status) implements RequestHandlerInterface {
            public function __construct(private readonly int $status)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                (string) $request->getBody(); // simulate a controller reading/deserializing the body
                return new Response($this->status);
            }
        };
    }

    public function testCapturesBasicRequestMetadata(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(apiKey: 'k1', gcpProjectId: 'p', ingestUrl: $this->server->url()));

        $request = new ServerRequest('GET', '/ok?x=1', [], null, '1.1', ['REMOTE_ADDR' => '203.0.113.9']);
        $request = $request->withHeader('User-Agent', 'phpunit-ua');

        $response = $middleware->process($request, self::handlerReturning(200, 'hello'));

        $this->assertSame(200, $response->getStatusCode());
        $received = $this->server->received();
        $this->assertCount(1, $received);
        $event = $received[0]['events'][0];
        $this->assertSame('GET', $event['method']);
        $this->assertSame('/ok?x=1', $event['url']);
        $this->assertSame(200, $event['status']);
        $this->assertSame('203.0.113.9', $event['remoteIp']);
        $this->assertSame('phpunit-ua', $event['userAgent']);
        $this->assertSame('p', $event['projectId']);
    }

    public function testRedactsSecretInQueryString(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(apiKey: 'k1', gcpProjectId: 'p', ingestUrl: $this->server->url()));

        $request = new ServerRequest('GET', '/ok?token=abc123secret&name=jane');
        $middleware->process($request, self::handlerReturning(200));

        $event = $this->server->received()[0]['events'][0];
        $this->assertStringNotContainsString('abc123secret', $event['url']);
        $this->assertStringContainsString('name=jane', $event['url']);
    }

    public function testBodyCaptureWhenEnabled(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(
            apiKey: 'k1',
            gcpProjectId: 'p',
            ingestUrl: $this->server->url(),
            captureBody: true,
        ));

        $request = (new ServerRequest('POST', '/login'))
            ->withHeader('Content-Type', 'application/json')
            ->withBody(Stream::create('{"password":"hunter2xyz"}'));

        $response = $middleware->process($request, self::handlerThatReadsBody(401));

        $this->assertSame(401, $response->getStatusCode());
        $event = $this->server->received()[0]['events'][0];
        $this->assertSame(401, $event['status']);
        $this->assertStringNotContainsString('hunter2xyz', $event['body']);
        $this->assertStringContainsString('REDACTED', $event['body']);
    }

    public function testDoesNotCaptureBodyByDefault(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(apiKey: 'k1', gcpProjectId: 'p', ingestUrl: $this->server->url()));

        $request = (new ServerRequest('POST', '/login'))
            ->withHeader('Content-Type', 'application/json')
            ->withBody(Stream::create('{"password":"hunter2"}'));

        $middleware->process($request, self::handlerThatReadsBody(200));

        $event = $this->server->received()[0]['events'][0];
        $this->assertArrayNotHasKey('body', $event);
    }

    public function testDownstreamHandlerStillReadsTheBodyAfterCapture(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(
            apiKey: 'k1',
            gcpProjectId: 'p',
            ingestUrl: $this->server->url(),
            captureBody: true,
        ));

        $seenByHandler = null;
        $handler = new class ($seenByHandler) implements RequestHandlerInterface {
            public function __construct(private mixed &$seenByHandler)
            {
            }

            public function handle(ServerRequestInterface $request): ResponseInterface
            {
                $this->seenByHandler = (string) $request->getBody();
                return new Response(200);
            }
        };

        $request = (new ServerRequest('POST', '/echo'))
            ->withHeader('Content-Type', 'application/json')
            ->withBody(Stream::create('{"a":1}'));

        $middleware->process($request, $handler);

        $this->assertSame('{"a":1}', $seenByHandler);
    }

    public function testStatusFilterDropsNonErrors(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(
            apiKey: 'k1',
            gcpProjectId: 'p',
            ingestUrl: $this->server->url(),
            statusFilter: StatusFilter::errors(),
        ));

        $middleware->process(new ServerRequest('GET', '/ok'), self::handlerReturning(200));

        $this->assertCount(0, $this->server->received());
    }

    public function testPreservesResponseFromHandler(): void
    {
        $this->server = new RecordingServer();
        $middleware = new CybatMiddleware(new Options(apiKey: 'k1', gcpProjectId: 'p', ingestUrl: $this->server->url()));

        $response = $middleware->process(new ServerRequest('GET', '/ok'), self::handlerReturning(418, 'teapot'));

        $this->assertSame(418, $response->getStatusCode());
        $this->assertSame('teapot', (string) $response->getBody());
    }
}
