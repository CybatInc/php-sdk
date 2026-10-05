<?php

declare(strict_types=1);

namespace Cybat\Sdk;

/**
 * Factory for the two common status filters. A StatusFilter is just a
 * `callable(int $status): bool` -- pass any callable (closure, first-class
 * callable syntax, etc.) to Options for full control, e.g. `fn(int $status) => $status !== 304`.
 */
final class StatusFilter
{
    private function __construct()
    {
    }

    /** Sends every captured request regardless of status code. This is the default. */
    public static function all(): callable
    {
        return static fn (int $status): bool => true;
    }

    /**
     * Sends only 4xx/5xx responses -- useful to cut ingestion volume/cost on
     * high-traffic apps where 2xx telemetry isn't needed.
     */
    public static function errors(): callable
    {
        return static fn (int $status): bool => $status >= 400;
    }
}
