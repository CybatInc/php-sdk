<?php

declare(strict_types=1);

namespace Cybat\Sdk;

/**
 * Configures a {@see Collector} (or a {@see CybatMiddleware}, which builds one
 * internally).
 *
 * Unlike the Node/Python/Go/Java SDKs, there is no flushIntervalMs or
 * maxBatchSize here -- classic PHP-FPM has no persistent process to run a
 * background buffering timer across requests, so {@see Collector::record()}
 * sends each event immediately as its own batch of one (the wire contract
 * explicitly allows a single object in place of an array). See Collector's
 * doc comment for what this means for request latency and how to avoid it.
 */
final class Options
{
    private const DEFAULT_GCP_INGEST_URL = 'https://gcp-ingest.cybat.co';
    private const DEFAULT_AWS_INGEST_URL = 'https://aws-ingest.cybat.co';
    private const BODY_DEFAULT_BYTES = 2048;
    private const BODY_HARD_MAX_BYTES = 8192;

    public readonly string $apiKey;
    public readonly ?string $gcpProjectId;
    public readonly ?string $awsProjectId;
    public readonly ?string $serviceName;
    public readonly string $ingestUrl;
    public readonly int $maxRetries;
    public readonly int $retryBackoffMs;
    /** @var callable(int): bool */
    public readonly mixed $statusFilter;
    public readonly bool $captureBody;
    public readonly int $bodyMaxBytes;
    /** @var callable(int): bool */
    public readonly mixed $bodyStatusFilter;
    /** Timeout in seconds for the ingest HTTP call. Kept short since (outside a terminate/kernel.terminate hook) this delays the response. */
    public readonly int $timeoutSeconds;
    /** @var array<string> normalized (lowercased) extra sensitive field names */
    public readonly array $extraSensitiveKeys;

    /**
     * @param string $apiKey Raw key from the Intelligence Dashboard -> API Keys. Required.
     * @param string|null $gcpProjectId The GCP project this app runs in (or whose traffic should be
     *     enforced against). Exactly one of gcpProjectId/awsProjectId is required -- it says which
     *     cloud this app's traffic belongs to (mutually exclusive: one Collector targets one cloud)
     *     and determines routing. On GCP it also enables automatic blocking (VPC Firewall / Cloud
     *     Armor) -- Grant the Cybat service account (shown in onboarding) compute.securityAdmin +
     *     compute.networkViewer on this project for enforcement to work.
     * @param string|null $awsProjectId Routes data to the AWS ingestion endpoint instead of GCP's.
     *     Required (instead of gcpProjectId) for an AWS-hosted app. NOT YET LIVE --
     *     aws-ingest.cybat.co has no backend behind it yet. Setting this today means every batch
     *     fails to send (retried, then dropped) until AWS-based ingestion ships.
     * @param string|null $serviceName Optional label identifying which of the customer's services
     *     this is, shown on incidents.
     * @param string|null $ingestUrl Overrides cloud auto-detection entirely -- set this explicitly
     *     for local/staging testing.
     * @param int $maxRetries Retries on a failed send before the batch is dropped. Default 2 (3
     *     attempts total). Each retry sleeps (usleep) before trying again -- see Collector's doc
     *     comment on what this means for latency.
     * @param int $retryBackoffMs Base delay in ms before the first retry; doubles on each
     *     subsequent retry (exponential backoff). Default 500.
     * @param callable|null $statusFilter `callable(int $status): bool`. Which events to send based
     *     on the response status code. Default StatusFilter::all().
     * @param bool $captureBody Include the request body in each event. Default false. See
     *     CybatMiddleware's doc comment on "Request bodies & privacy" -- redaction is not optional
     *     once this is on.
     * @param int $bodyMaxBytes Cap on the captured body after redaction, in bytes. Default 2048, max 8192.
     * @param callable|null $bodyStatusFilter `callable(int $status): bool`. Capture bodies only for
     *     responses matching this filter (independent of statusFilter). Default StatusFilter::all().
     * @param int $timeoutSeconds Timeout for the ingest HTTP call itself. Default 5.
     * @param array<string>|null $extraSensitiveKeys Extra field names to treat as secrets on top of
     *     the built-in list (password, token, secret, cvv, ssn, iban, ...) -- e.g. domain-specific
     *     identifiers like "account_number" or "medical_record_number" that wouldn't otherwise
     *     match. Matched as an exact, case-insensitive field name (not a regex fragment), so adding
     *     a short name like "id" can't accidentally swallow unrelated keys. Only affects
     *     captureBody's redaction of the request body -- it does not extend which query-string
     *     parameter names get redacted in the url. Default: none.
     */
    public function __construct(
        string $apiKey,
        ?string $gcpProjectId = null,
        ?string $awsProjectId = null,
        ?string $serviceName = null,
        ?string $ingestUrl = null,
        int $maxRetries = 2,
        int $retryBackoffMs = 500,
        ?callable $statusFilter = null,
        bool $captureBody = false,
        int $bodyMaxBytes = self::BODY_DEFAULT_BYTES,
        ?callable $bodyStatusFilter = null,
        int $timeoutSeconds = 5,
        ?array $extraSensitiveKeys = null,
    ) {
        if ($apiKey === '') {
            throw new \InvalidArgumentException('cybat: apiKey is required');
        }
        $hasGcp = $gcpProjectId !== null && $gcpProjectId !== '';
        $hasAws = $awsProjectId !== null && $awsProjectId !== '';
        if (!$hasGcp && !$hasAws) {
            throw new \InvalidArgumentException(
                "cybat: one of gcpProjectId or awsProjectId is required -- set whichever cloud this app's traffic belongs to"
            );
        }
        if ($hasGcp && $hasAws) {
            throw new \InvalidArgumentException(
                'cybat: set only one of gcpProjectId or awsProjectId -- a single Collector targets a single cloud; use two Collectors for an app split across both'
            );
        }

        $this->apiKey = $apiKey;
        $this->gcpProjectId = $gcpProjectId;
        $this->awsProjectId = $awsProjectId;
        $this->serviceName = $serviceName;
        $this->ingestUrl = ($ingestUrl !== null && $ingestUrl !== '')
            ? $ingestUrl
            : ($hasAws ? self::DEFAULT_AWS_INGEST_URL : self::DEFAULT_GCP_INGEST_URL);
        $this->maxRetries = $maxRetries;
        $this->retryBackoffMs = $retryBackoffMs;
        $this->statusFilter = $statusFilter ?? StatusFilter::all();
        $this->captureBody = $captureBody;
        $this->bodyMaxBytes = min(self::BODY_HARD_MAX_BYTES, max(256, $bodyMaxBytes));
        $this->bodyStatusFilter = $bodyStatusFilter ?? StatusFilter::all();
        $this->timeoutSeconds = $timeoutSeconds;
        $this->extraSensitiveKeys = array_map('strtolower', $extraSensitiveKeys ?? []);
    }

    public function projectId(): ?string
    {
        return $this->gcpProjectId ?? $this->awsProjectId;
    }
}
