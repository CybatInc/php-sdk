# cybat-sdk (PHP)

A PSR-15 middleware for the Cybat Intelligence Engine — captures HTTP traffic your server already receives and reports it directly to Cybat. Works with any PSR-15-compatible framework (Slim 4, Mezzio, and others).

## ⚠️ Read this before you install: how this SDK differs from the others

The Node/Python/Go/Java SDKs all buffer captured events in memory and flush them in a batch every couple of seconds, on a background thread that outlives any single request. **Classic PHP-FPM has no such thread** — the process handling your request is reused or torn down once the response is sent, with nothing left running in the background. So this SDK doesn't pretend otherwise: `Collector::record()` sends **immediately**, one event per HTTP call (the wire contract explicitly allows a single JSON object in place of a batch array).

That has one real consequence: calling `record()` blocks for the duration of the ingest HTTP call (plus retries) **unless you call it from a point in the request lifecycle that runs after the response has already been sent to the client**. Two good options, in order of preference:

1. **Symfony's `kernel.terminate` event or Laravel's `terminate()` middleware method.** Both frameworks already call `fastcgi_finish_request()` internally as part of their normal termination flow — code running in either hook executes *after* the client has the response, so the ingest call adds zero user-facing latency. Wire `Collector::record()` (or a `CybatMiddleware` you build directly, matching this package's) into that hook.
2. **`CybatMiddleware` (PSR-15), included in this package,** for frameworks without a hook like that. PSR-15 middleware runs *before* the response is emitted, not after, so this middleware calls `record()` inline — the ingest call's latency (bounded by `Options::$timeoutSeconds`, default 5s, plus retries) is added to every tracked response. Keep `maxRetries`/`timeoutSeconds` small if you use this path.

## Install

```bash
composer require cybat/sdk
```

(Not yet published to Packagist — see "Publishing" below.)

## Usage

**PSR-15** (Slim 4, Mezzio, etc.):

```php
use Cybat\Sdk\CybatMiddleware;
use Cybat\Sdk\Options;

$app->add(new CybatMiddleware(new Options(
    apiKey: getenv('CYBAT_API_KEY'),
    gcpProjectId: 'my-gcp-project', // required (or awsProjectId) -- also enables automatic blocking, see below
    serviceName: 'checkout-api',    // optional, just a label on incidents
)));
```

**Zero-latency-impact, via a terminate hook** (Symfony shown; Laravel's `terminate()` middleware method follows the same shape):

```php
use Cybat\Sdk\Collector;
use Cybat\Sdk\Options;
use Cybat\Sdk\Redact;
use Symfony\Component\HttpKernel\Event\TerminateEvent;

class CybatSubscriber
{
    private Collector $collector;

    public function __construct()
    {
        $this->collector = new Collector(new Options(
            apiKey: $_ENV['CYBAT_API_KEY'],
            gcpProjectId: 'my-gcp-project',
        ));
    }

    public function onKernelTerminate(TerminateEvent $event): void
    {
        $request = $event->getRequest();
        $response = $event->getResponse();
        if (!$this->collector->wants($response->getStatusCode())) {
            return;
        }
        $this->collector->record([
            'method' => $request->getMethod(),
            'url' => Redact::maskString($request->getRequestUri()),
            'status' => $response->getStatusCode(),
            'remoteIp' => $request->getClientIp() ?? 'unknown',
            'latencyMs' => 0, // compute from your own request-start marker if you need this
            'bytesSent' => $response->headers->get('Content-Length') ?? 0,
            'timestamp' => gmdate('Y-m-d\TH:i:s.v\Z'),
        ]);
    }
}
```

Create an API key from the Intelligence Dashboard → **API Keys**. It's shown once at creation — store it as a secret (`CYBAT_API_KEY`), it can't be retrieved again.

## Multi-cloud routing

Set **exactly one** of `gcpProjectId` or `awsProjectId` — required, and never both on the same `Options`. Which one you set decides where data is sent, automatically:

| You set | Data goes to | Status |
|---------|--------------|--------|
| `gcpProjectId` | `gcp-ingest.cybat.co` | Live |
| `awsProjectId` | `aws-ingest.cybat.co` | **Not yet implemented** — batches will fail to send until AWS-based ingestion ships |

An app that runs in both clouds needs two `Collector`s, one per cloud — not one with both fields set (`Options`'s constructor throws `InvalidArgumentException` if you do that, since it's ambiguous which cloud's infrastructure should be enforced against). It also throws if **neither** is set — there's no default cloud, you must say which one this app runs on.

## ⚠️ Automatic blocking also requires the right IAM grant on `gcpProjectId`

Cybat classifies and alerts on threats as soon as `gcpProjectId` is set. But **automatically blocking** a malicious IP (VPC Firewall / Cloud Armor) additionally requires granting Cybat access to that specific project — without the grant below, threats are still detected and you still get alerted, but nothing gets blocked automatically.

To enable blocking:
1. Set `gcpProjectId` to the GCP project your app's infrastructure lives in (already required above).
2. Grant the Cybat service account (shown in the Intelligence Dashboard onboarding flow) the `roles/compute.securityAdmin` and `roles/compute.networkViewer` roles on that project.

## ⚠️ Behind a load balancer or reverse proxy?

`CybatMiddleware` resolves the client IP from the `REMOTE_ADDR` server parameter, which reflects the *direct* TCP peer. If your app sits behind your own load balancer, CDN, or reverse proxy, resolve the real client from `X-Forwarded-For` yourself (e.g. a small PSR-15 middleware ahead of this one that overrides `REMOTE_ADDR`) — otherwise every request reports the proxy's IP, and Cybat won't be able to tell your traffic apart.

## Options

```php
new Options(
    apiKey: string,                 // required
    gcpProjectId: ?string,          // required (unless awsProjectId set) -- routes to GCP, enables automatic blocking -- see above
    awsProjectId: ?string,          // required (unless gcpProjectId set) -- routes to AWS -- NOT YET LIVE, see "Multi-cloud routing"
    serviceName: ?string,           // optional label shown on incidents
    ingestUrl: ?string,             // overrides cloud auto-detection entirely; default depends on gcpProjectId/awsProjectId
    maxRetries: int,                // default 2 -- an event is dropped, not queued forever, after this
    retryBackoffMs: int,            // default 500 -- base delay before the first retry; doubles each retry (exponential)
    statusFilter: ?callable,        // default StatusFilter::all() -- see below
    captureBody: bool,              // send a redacted excerpt of the request body -- see "Request bodies & privacy"
    bodyMaxBytes: int,              // default 2048, max 8192 -- cap on the body excerpt after redaction
    bodyStatusFilter: ?callable,    // capture bodies only for matching responses
    timeoutSeconds: int,            // default 5 -- timeout for the ingest HTTP call itself
    extraSensitiveKeys: ?array,     // e.g. ["account_number", "medical_record_number"] -- see "Request bodies & privacy"
);
```

There's no `flushIntervalMs`/`maxBatchSize` here — see "how this SDK differs from the others" above for why.

A status filter is any `callable(int $status): bool`:
- `StatusFilter::all()` (default) — every request, regardless of status code.
- `StatusFilter::errors()` — only 4xx/5xx. Use this to cut ingestion volume/cost on high-traffic apps where 2xx telemetry isn't needed — Cybat still classifies and alerts on threats using only error responses, the same signal the old GCP Log Sink integration filtered down to.
- Any callable — full control, e.g. `fn(int $status) => $status !== 304` to drop cache-hit noise but keep everything else, 2xx included.

## Request bodies & privacy

`captureBody` is off by default. `CybatMiddleware` reads the request body via PSR-7's `(string) $request->getBody()` and, if the stream is seekable, rewinds it afterward so the downstream handler still sees a fresh, readable stream — this is simpler than the Go/Java SDKs' manual stream-teeing, since PSR-7 message bodies are meant to be re-readable, unlike a raw one-shot stream.

Redaction is **not optional** once `captureBody` is on: before an event is even sent, the body is masked in-process — emails, card numbers (Luhn-checked), JWT/Bearer tokens, provider API keys, and the value of any field named like a secret (`password`, `token`, `cvv`, `ssn`, …). A masked secret is replaced by a content-free shape such as `[REDACTED len=13 sus=quote,comment]` — its length and what kind of attack characters it contained, so a SQL injection typed into a password box is still visible, but the value is not. JSON, form-encoded and text bodies only; multipart and binary are skipped.

The built-in list can't know that a field called `account_number` or `medical_record_number` happens to contain something private in your app — `extraSensitiveKeys` lets you extend it with your own:

```php
new Options(
    apiKey: getenv('CYBAT_API_KEY'),
    gcpProjectId: 'my-gcp-project',
    captureBody: true,
    extraSensitiveKeys: ['account_number', 'medical_record_number', 'internal_employee_id'],
);
```

Matching is an exact, case-insensitive field name, not a regex fragment or substring — adding a short name like `id` only catches a field literally named `id`, it can't accidentally swallow unrelated keys the way the built-in fragment-based patterns (`pass`, `token`, `key`…) deliberately do. Values under these keys get the same content-free `[REDACTED len=N sus=…]` treatment as the built-in list, applied wherever `captureBody` already looks (JSON, form-encoded and text bodies) — it does not extend which query-string parameter names get redacted in the URL. If a route handles data you don't want to leave your infrastructure at all regardless of field name, leave `captureBody` off, or use `bodyStatusFilter` / a `statusFilter` callable to exclude it.

## Behavior

- Never throws out of `CybatMiddleware::process` or `Collector`'s own methods — a network error, a rejected request, or a misconfigured key results in a dropped event and a message via `error_log()`, not a broken response.
- Sends immediately, synchronously, one event per HTTP call — see "how this SDK differs from the others" at the top of this file.
- Uses only PHP's built-in `stream_context_create`/`file_get_contents` (core PHP, `allow_url_fopen` must be enabled — the default) for the HTTP call, and PHP's built-in `json_encode`/`json_decode` — no runtime dependency beyond the PSR HTTP interface packages (`psr/http-message`, `psr/http-server-middleware`, `psr/http-server-handler`), which are interfaces only, with no implementation bundled.
- A failed send retries `maxRetries` times with exponential backoff (`usleep`-based: `retryBackoffMs`, `retryBackoffMs * 2`, `retryBackoffMs * 4`, ...) before the event is dropped for good. Each retry's sleep is real wall-clock time in whatever context called `record()` — see the latency note above.

## Wire format

See [`../README.md`](../README.md) for the shared batch/auth contract every language SDK implements. Field names on the wire (`remoteIp`, `latencyMs`, `bodyTruncated`, ...) are camelCase per that shared contract even though this package's own PHP API (`gcpProjectId`, `statusFilter`, ...) is idiomatic PHP — that boundary is deliberate: the wire format is a cross-language contract, the options are this language's idiomatic API.

The redaction contract (`src/Redact.php`) is a line-for-line port of `node/src/redact.ts`, `python/cybat_sdk/redact.py`, `go/redact.go` and `java/src/main/java/co/cybat/sdk/Redact.java`. PHP's PCRE engine supports lookahead like Java's does, so this port follows the JS source directly — with one PHP-specific adjustment: PCRE fails to even *compile* the JSON-pair pattern at the other ports' 4000-character bound ("regular expression is too large"), so it's capped at 1000 here, the same practical ceiling `go/redact.go` hit with RE2's explicit repeat-count limit, for an unrelated underlying reason. See the comment on `JSON_PAIR_RE` in `Redact.php`.

## Testing

```bash
composer install
./vendor/bin/phpunit tests/
```

`CollectorTest`/`CybatMiddlewareTest` spawn PHP's own built-in dev server (`php -S`) as a real local HTTP endpoint per test (`tests/RecordingServer.php`) — never a mock of the HTTP transport itself. `nyholm/psr7` is a require-dev-only dependency used to build real PSR-7 request/response objects for `CybatMiddlewareTest` (the PSR interfaces this SDK depends on at runtime have no implementation of their own to instantiate) — never bundled into the published package.

## Publishing (maintainers)

Not yet published to Packagist. `.github/workflows/test-php.yml` runs `phpunit` on every push/PR touching `php/`; there is no publish job yet — publishing to Packagist just requires registering the GitHub repo there and enabling its auto-update webhook, no build/signing step like PyPI or Maven Central.
