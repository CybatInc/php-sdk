<?php

declare(strict_types=1);

namespace Cybat\Sdk;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware -- works with any PSR-15-compatible framework (Slim 4,
 * Mezzio, and others).
 *
 *     $app->add(new CybatMiddleware(new Options(
 *         apiKey: getenv('CYBAT_API_KEY'),
 *         gcpProjectId: 'my-gcp-project', // required (or awsProjectId) -- also enables automatic blocking, see php/README.md
 *     )));
 *
 * PSR-15 middleware runs BEFORE the response is emitted to the client, not
 * after -- unlike {@see Collector}'s ideal usage (a terminate-style hook
 * running after the response is already sent), this middleware calls
 * Collector::record() inline, so the ingest HTTP call's latency (bounded by
 * Options::$timeoutSeconds, plus retries) is added to every tracked response.
 * See Collector's doc comment for the Laravel/Symfony alternative that avoids
 * this entirely.
 *
 * If your app sits behind a load balancer or reverse proxy you own, resolve
 * the real client IP from X-Forwarded-For yourself (e.g. a dedicated PSR-15
 * middleware ahead of this one that rewrites the request's client-ip
 * attribute) -- otherwise RemoteIp resolves to the proxy's address instead of
 * the real client, and every event will look like it came from one source.
 */
final class CybatMiddleware implements MiddlewareInterface
{
    private readonly Collector $collector;

    public function __construct(Options $options)
    {
        $this->collector = new Collector($options);
    }

    /** The underlying Collector, for advanced use. */
    public function getCollector(): Collector
    {
        return $this->collector;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $start = microtime(true);

        $rawBody = null;
        if ($this->collector->captureBodyEnabled()) {
            $bodyStream = $request->getBody();
            $rawBody = (string) $bodyStream; // PSR-7: __toString() reads from the start but leaves the pointer at EOF
            if ($bodyStream->isSeekable()) {
                $bodyStream->rewind(); // so the downstream handler still sees a fresh, readable stream
            }
        }

        $response = $handler->handle($request);

        try {
            $this->recordEvent($request, $response, $rawBody, $start);
        } catch (\Throwable) {
            // Instrumentation must never break the host app.
        }

        return $response;
    }

    private function recordEvent(ServerRequestInterface $request, ResponseInterface $response, ?string $rawBody, float $start): void
    {
        $status = $response->getStatusCode();
        if (!$this->collector->wants($status)) {
            return;
        }

        $uri = $request->getUri();
        $path = $uri->getPath();
        $query = $uri->getQuery();
        $url = $query !== '' ? "{$path}?{$query}" : $path;

        $event = [
            'method' => $request->getMethod(),
            'url' => Redact::maskString($url),
            'status' => $status,
            'remoteIp' => $this->remoteIp($request),
            'latencyMs' => (int) round((microtime(true) - $start) * 1000),
            'bytesSent' => $response->getBody()->getSize() ?? 0,
            'timestamp' => $this->isoTimestamp($start),
        ];

        $projectId = $this->collector->projectId();
        if ($projectId !== null) {
            $event['projectId'] = $projectId;
        }
        $serviceName = $this->collector->serviceName();
        if ($serviceName !== null) {
            $event['serviceName'] = $serviceName;
        }

        $userAgent = $request->getHeaderLine('User-Agent');
        if ($userAgent !== '') {
            $event['userAgent'] = Redact::maskString($userAgent);
        }
        $referer = $request->getHeaderLine('Referer');
        if ($referer !== '') {
            $event['referer'] = Redact::maskString($referer);
        }

        if ($rawBody !== null) {
            $contentType = $request->getHeaderLine('Content-Type');
            $capture = $this->collector->captureBodyFor($rawBody, $contentType !== '' ? $contentType : null, $status);
            if ($capture !== null) {
                $event['body'] = $capture['body'];
                if ($capture['bodyTruncated']) {
                    $event['bodyTruncated'] = true;
                }
            }
        }

        $this->collector->record($event);
    }

    private function remoteIp(ServerRequestInterface $request): string
    {
        $params = $request->getServerParams();
        return $params['REMOTE_ADDR'] ?? 'unknown';
    }

    private function isoTimestamp(float $epochSeconds): string
    {
        $millis = (int) round(($epochSeconds - floor($epochSeconds)) * 1000);
        return gmdate('Y-m-d\TH:i:s', (int) $epochSeconds) . sprintf('.%03dZ', $millis);
    }
}
