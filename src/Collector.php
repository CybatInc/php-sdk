<?php

declare(strict_types=1);

namespace Cybat\Sdk;

/**
 * Sends captured HTTP events to ingest-api (behind API Gateway). Never throws
 * out of its own public methods -- a broken or unreachable ingest endpoint
 * must never take down the host application. On repeated failure the event is
 * dropped rather than retried indefinitely (Pub/Sub is the durability layer
 * on Cybat's side; this SDK only needs to survive transient network blips).
 *
 * Unlike the Node/Python/Go/Java SDKs, {@see record()} sends immediately --
 * there is no background buffering thread, because classic PHP-FPM tears down
 * (or recycles) the process after each request, with no persistent process to
 * run one. Each event is its own batch of one (the wire contract explicitly
 * allows a single JSON object in place of an array).
 *
 * **This means record() blocks for the duration of the HTTP call (plus any
 * retries) unless you call it from a point in the request lifecycle that runs
 * AFTER the response has already been sent to the client.** Symfony's
 * `kernel.terminate` event and Laravel's `terminate()` middleware method both
 * run at exactly that point (both frameworks already call
 * `fastcgi_finish_request()` internally as part of their normal
 * termination flow) -- wire `record()` into one of those hooks for
 * zero-latency-impact tracking. {@see CybatMiddleware} (PSR-15) does NOT have
 * access to such a hook -- PSR-15 middleware runs before the response is
 * emitted, not after -- so it calls record() inline and the ingest call's
 * latency (bounded by Options::$timeoutSeconds, default 5s, plus retries) is
 * added to the response. Keep maxRetries/timeoutSeconds small for that path,
 * or prefer the terminate-hook pattern if your framework supports it.
 */
final class Collector
{
    private const CAPTURABLE_CONTENT_TYPE = '/^(application\/(json|[\w.+-]+\+json|x-www-form-urlencoded)|text\/)/i';

    public function __construct(private readonly Options $opts)
    {
    }

    /** Lets an integration skip building an event that statusFilter would discard anyway. */
    public function wants(int $status): bool
    {
        return ($this->opts->statusFilter)($status);
    }

    public function captureBodyEnabled(): bool
    {
        return $this->opts->captureBody;
    }

    public function projectId(): ?string
    {
        return $this->opts->projectId();
    }

    public function serviceName(): ?string
    {
        return $this->opts->serviceName;
    }

    /**
     * Redacts and caps a raw request body for inclusion in an event. Returns
     * null (never the raw body) when capture is off, the response doesn't
     * match bodyStatusFilter, the body is empty, or the content type isn't
     * one of JSON/form/text.
     *
     * @return array{body: string, bodyTruncated: bool}|null
     */
    public function captureBodyFor(?string $rawBody, ?string $contentType, int $status): ?array
    {
        if (!$this->opts->captureBody || !($this->opts->bodyStatusFilter)($status)) {
            return null;
        }
        if ($rawBody === null || $rawBody === '') {
            return null;
        }
        if ($contentType !== null && preg_match(self::CAPTURABLE_CONTENT_TYPE, $contentType) !== 1) {
            return null;
        }

        try {
            $masked = Redact::maskBody($rawBody);
            $text = is_string($masked) ? $masked : json_encode($masked);
            if ($text === false) {
                return null;
            }
            $excerpt = Redact::snippetAround($text, $this->opts->bodyMaxBytes);
            return ['body' => $excerpt, 'bodyTruncated' => $excerpt !== $text];
        } catch (\Throwable) {
            return null; // when in doubt, send nothing rather than something unredacted
        }
    }

    /**
     * Sends event immediately as a batch of one. See this class's doc comment
     * for what that means for request latency depending on where you call it from.
     *
     * @param array<string, mixed> $event
     */
    public function record(array $event): void
    {
        if (!($this->opts->statusFilter)((int) $event['status'])) {
            return;
        }
        $this->send([$event], 0);
    }

    /** @param array<int, array<string, mixed>> $batch */
    private function send(array $batch, int $attempt): void
    {
        $body = json_encode($batch);
        if ($body === false) {
            return; // nothing sensible to retry -- nothing was even sent
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => "Content-Type: application/json\r\nx-api-key: {$this->opts->apiKey}\r\n",
                'content' => $body,
                'timeout' => $this->opts->timeoutSeconds,
                'ignore_errors' => true, // still read the response (and its status) on 4xx/5xx instead of throwing
            ],
        ]);

        $result = @file_get_contents($this->opts->ingestUrl, false, $context);
        $status = $this->responseStatus($http_response_header ?? null);

        if ($result !== false && $status >= 200 && $status < 300) {
            return;
        }

        if ($attempt < $this->opts->maxRetries) {
            usleep($this->opts->retryBackoffMs * (2 ** $attempt) * 1000);
            $this->send($batch, $attempt + 1);
            return;
        }

        if ($result === false) {
            error_log('[cybat-sdk] failed to reach ingest endpoint, dropping ' . count($batch) . ' event(s)');
        } else {
            error_log("[cybat-sdk] ingest rejected batch ({$status}), dropping " . count($batch) . ' event(s)');
        }
    }

    /** @param array<int, string>|null $headers */
    private function responseStatus(?array $headers): int
    {
        if ($headers === null || $headers === []) {
            return 0;
        }
        if (preg_match('/\s(\d{3})\s/', $headers[0], $m) === 1) {
            return (int) $m[1];
        }
        return 0;
    }
}
