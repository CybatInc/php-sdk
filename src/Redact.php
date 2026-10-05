<?php

declare(strict_types=1);

namespace Cybat\Sdk;

/**
 * Layer 1 of the data-protection stack: fast, local, dependency-free redaction.
 *
 * This is a line-for-line port of node/src/redact.ts (see also
 * python/cybat_sdk/redact.py, go/redact.go, and
 * java/src/main/java/co/cybat/sdk/Redact.java) -- all must stay in sync (see
 * SDK/README.md's redaction contract). PHP's PCRE (preg_*) supports
 * lookahead like Java's engine does, so these patterns port directly from the
 * JS source without the RE2-specific restructuring go/redact.go needed.
 *
 * PHP strings are plain byte sequences (not a distinct "unicode string"
 * type), so strlen() already IS the UTF-8 byte length every other language
 * port computes explicitly -- no separate byte-length helper is needed here.
 *
 * The SDK runs this on the customer's side BEFORE anything leaves their
 * infrastructure; the server runs it again (the SDK may be old, modified or
 * hostile) before persisting, before prompting the model, and before alerts.
 * It is therefore idempotent: masking already-masked text leaves it unchanged.
 */
final class Redact
{
    private function __construct()
    {
    }

    private const REDACTED = '[REDACTED';

    /** @var array<int, array{0: string, 1: string}> */
    private const SUSPICIOUS = [
        ['quote', '/[\'"`]|%27|%22/i'],
        ['comment', '/--|\/\*|#\s*$/'],
        ['sqlkw', '/\b(union|select|insert|update|delete|drop|sleep|benchmark|waitfor)\b/i'],
        ['angle', '/[<>]|%3c|%3e/i'],
        ['semicolon', '/;/'],
        ['traversal', '/\.\.[\/\\\\]|%2e%2e/i'],
        ['cmdchar', '/[|&$`]|\$\(/'],
        ['template', '/\{\{|\$\{|<%/'],
        ['nullbyte', '/%00|\x00/'],
    ];

    /** "[REDACTED len=N sus=a,b]" -- no characters of the original value survive. */
    public static function redactedShape(?string $value): string
    {
        $s = $value ?? '';
        $sus = [];
        foreach (self::SUSPICIOUS as [$name, $pattern]) {
            if (preg_match($pattern, $s) === 1) {
                $sus[] = $name;
            }
        }
        $suffix = $sus !== [] ? ' sus=' . implode(',', $sus) : '';
        return self::REDACTED . ' len=' . strlen($s) . $suffix . ']';
    }

    // -- Credit cards (Luhn) --------------------------------------------------

    public static function luhnValid(string $digits): bool
    {
        if (preg_match('/^\d{13,19}$/', $digits) !== 1) {
            return false;
        }
        $sum = 0;
        $alt = false;
        for ($i = strlen($digits) - 1; $i >= 0; $i--) {
            $n = ord($digits[$i]) - ord('0');
            if ($alt) {
                $n *= 2;
                if ($n > 9) {
                    $n -= 9;
                }
            }
            $sum += $n;
            $alt = !$alt;
        }
        return $sum % 10 === 0;
    }

    private static function maskCard(string $digits): string
    {
        return 'XXXX-XXXX-XXXX-' . substr($digits, -4);
    }

    // -- Emails -----------------------------------------------------------------

    public static function maskEmail(string $local, string $domain): string
    {
        $first = $local === '' ? '' : $local[0];
        $last = strlen($local) > 2 ? substr($local, -1) : '';
        return $first . '***' . $last . '@' . $domain;
    }

    private const EMAIL_RE = '/([A-Za-z0-9._%+*-]{1,64})(?:@|%40)([A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,24})/';
    private const CARD_RE = '/\b\d(?:[ -]?\d){12,18}\b/';
    private const JWT_RE = '/\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/';
    private const BEARER_RE = '/\b(Bearer|Basic)\s+(?!\[REDACTED)[A-Za-z0-9._~+\/=-]{8,}/i';
    private const PRIVKEY_RE = '/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/';

    private const KEY_TOKEN_RES = [
        '/\bAKIA[0-9A-Z]{16}\b/',                     // AWS access key id
        '/\bAIza[0-9A-Za-z_-]{35}\b/',                // Google API key
        '/\bgh[pousr]_[A-Za-z0-9]{36,}\b/',           // GitHub tokens
        '/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/',         // Slack tokens
        '/\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b/', // Stripe keys
    ];

    // key=value pairs whose *name* says the value is a secret (URL query strings,
    // form bodies, cookie-style strings). The leading class stops `sort_key=` and
    // `monkey=` from matching. The value runs to the next `&`, `#`, newline or
    // "; " -- deliberately NOT stopping at quotes or spaces, because a secret (or
    // an attacker's payload standing in for one) routinely contains them.
    private const PARAM_SECRET_RE =
        '/(?:^|[?&;,\s"\'])(?:access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|apikey|client[_-]?secret|secret|password|passwd|passphrase|pwd|auth|authorization|session(?:[_-]?id)?|sid|signature|sig|key|credential|cc[_-]?num(?:ber)?|card[_-]?(?:number|no|num)?|cvv|cvc|ssn|iban)=((?:(?!;\s)[^&#\r\n])+)/i';

    // Input is attacker-controlled and some patterns (emails) are quadratic on
    // long runs with no delimiter, so bound the work. Anything longer is cut,
    // not skipped: dropping the tail is safe; leaving it unscanned would not be.
    private const MAX_INPUT_BYTES = 65536;

    // `"key": "value"` pairs inside JSON text. Needed on top of maskValue
    // because a body that was truncated mid-way (the SDK caps bodies) no
    // longer parses as JSON, and this is the only pass left that can still see
    // its keys.
    //
    // The JS/Python versions bound the value at 4000 chars; PHP's PCRE fails
    // to even COMPILE this pattern above roughly 1500-2000 ("regular
    // expression is too large") -- same practical ceiling go/redact.go hit
    // with RE2's explicit 1000-repeat cap, for a different underlying reason.
    // Capped at 1000 here too. This only shortens how much of one oversized
    // quoted value this fallback pass can see before giving up on matching it
    // as a whole -- it does not weaken redaction (a value this pass can't
    // fully match still isn't leaked; maskString's other passes and the
    // overall MAX_INPUT_BYTES cap still apply).
    private const JSON_PAIR_RE = '/"([^"\\\\]{1,64})"(\s*:\s*)(?:"((?:[^"\\\\]|\\\\.){0,1000})"|(-?\d{1,25}))/';

    /** Redacts secrets and personal data inside free text. Idempotent. */
    public static function maskString(?string $input): ?string
    {
        if ($input === null || $input === '') {
            return $input;
        }
        $s = $input;
        if (strlen($s) > self::MAX_INPUT_BYTES) {
            $s = self::truncateUtf8($s, self::MAX_INPUT_BYTES) . '…[truncated]';
        }

        $s = preg_replace(self::PRIVKEY_RE, self::REDACTED . ' private-key]', $s);
        $s = preg_replace(self::JWT_RE, self::REDACTED . ' jwt]', $s);
        $s = preg_replace_callback(self::BEARER_RE, static function (array $m): string {
            return $m[1] . ' ' . self::REDACTED . ']';
        }, $s);
        foreach (self::KEY_TOKEN_RES as $pattern) {
            $s = preg_replace($pattern, self::REDACTED . ' key]', $s);
        }

        $s = preg_replace_callback(self::PARAM_SECRET_RE, static function (array $m): string {
            $value = $m[1];
            if (str_starts_with($value, self::REDACTED)) {
                return $m[0];
            }
            $prefix = substr($m[0], 0, strlen($m[0]) - strlen($value));
            return $prefix . self::redactedShape(self::safeDecode($value));
        }, $s);

        $s = preg_replace_callback(self::JSON_PAIR_RE, static function (array $m): string {
            $key = $m[1];
            $colon = $m[2];
            $str = $m[3] ?? '';
            $num = $m[4] ?? '';
            if (preg_match(self::SENSITIVE_KEY_RE, $key) !== 1) {
                return $m[0];
            }
            $raw = $str !== '' ? $str : $num;
            if (str_starts_with($raw, self::REDACTED) || str_starts_with($raw, 'XXXX-XXXX-XXXX-')) {
                return $m[0];
            }
            $digits = preg_replace('/\D/', '', $raw);
            $masked = (preg_match(self::CARD_KEY_RE, $key) === 1 && strlen($digits) >= 12)
                ? self::maskCard($digits)
                : self::redactedShape($raw);
            return '"' . $key . '"' . $colon . '"' . $masked . '"';
        }, $s);

        $s = preg_replace_callback(self::CARD_RE, static function (array $m): string {
            $digits = preg_replace('/[ -]/', '', $m[0]);
            return self::luhnValid($digits) ? self::maskCard($digits) : $m[0];
        }, $s);

        $s = preg_replace_callback(self::EMAIL_RE, static function (array $m): string {
            $local = $m[1];
            $domain = $m[2];
            return str_contains($local, '***') ? $m[0] : self::maskEmail($local, $domain);
        }, $s);

        return $s;
    }

    private static function safeDecode(string $v): string
    {
        $decoded = @rawurldecode(str_replace('+', ' ', $v));
        return $decoded === false ? $v : $decoded;
    }

    // -- Structured values (parsed JSON / form bodies) ------------------------

    private const SENSITIVE_KEY_RE =
        '/(pass|pwd|secret|token|auth|cookie|session|credential|private|api[_-]?key|apikey|card|cvv|cvc|ssn|iban|\bpin\b)/i';
    private const CARD_KEY_RE = '/(card|cc[_-]?num|ccnum|pan)/i';

    private const MAX_DEPTH = 6;
    private const MAX_ITEMS = 50;

    /**
     * Deep-masks a parsed body (the result of json_decode(..., true), or a
     * hand-built array tree). Values under sensitive key names become a shape
     * descriptor (card-number fields keep only the last 4 digits); every other
     * string goes through maskString. Depth and width are bounded so a
     * hostile payload can't make this expensive.
     *
     * @param mixed $value
     * @return mixed
     */
    public static function maskValue(mixed $value, int $depth = 0): mixed
    {
        if ($value === null) {
            return null;
        }
        if (is_string($value)) {
            return self::maskString($value);
        }
        if (is_bool($value) || is_int($value) || is_float($value)) {
            return $value;
        }
        if ($depth >= self::MAX_DEPTH) {
            return self::REDACTED . ' depth-limit]';
        }

        if (is_array($value)) {
            if (self::isList($value)) {
                $count = count($value);
                $limit = min($count, self::MAX_ITEMS);
                $out = [];
                for ($i = 0; $i < $limit; $i++) {
                    $out[] = self::maskValue($value[$i], $depth + 1);
                }
                if ($count > self::MAX_ITEMS) {
                    $out[] = '…[' . ($count - self::MAX_ITEMS) . ' more items]';
                }
                return $out;
            }

            $out = [];
            $count = 0;
            foreach ($value as $k => $v) {
                if ($count >= self::MAX_ITEMS) {
                    break;
                }
                $count++;
                $key = (string) $k;
                if (preg_match(self::SENSITIVE_KEY_RE, $key) === 1 && (is_string($v) || is_int($v) || is_float($v))) {
                    $raw = is_string($v) ? $v : (string) $v;
                    if (str_starts_with($raw, self::REDACTED) || str_starts_with($raw, 'XXXX-XXXX-XXXX-')) {
                        $out[$key] = $raw;
                        continue;
                    }
                    $digits = preg_replace('/\D/', '', $raw);
                    $out[$key] = (preg_match(self::CARD_KEY_RE, $key) === 1 && strlen($digits) >= 12)
                        ? self::maskCard($digits)
                        : self::redactedShape($raw);
                } else {
                    $out[$key] = self::maskValue($v, $depth + 1);
                }
            }
            if (count($value) > self::MAX_ITEMS) {
                $out['…'] = (count($value) - self::MAX_ITEMS) . ' more keys';
            }
            return $out;
        }

        return (string) $value;
    }

    /** @param array<mixed> $value */
    private static function isList(array $value): bool
    {
        return array_is_list($value);
    }

    /**
     * Masks a request body of unknown shape: an already-parsed array (e.g.
     * from json_decode(..., true)), JSON text, form-encoded text, or
     * plain/truncated text. Shared by the SDK (client side, before anything
     * is sent) and the server (second pass), so both apply the same rules.
     *
     * @param mixed $body
     * @return mixed
     */
    public static function maskBody(mixed $body): mixed
    {
        if ($body === null) {
            return null;
        }
        if (!is_string($body)) {
            return self::maskValue($body, 0);
        }
        $trimmed = trim($body);
        if (str_starts_with($trimmed, '{') || str_starts_with($trimmed, '[')) {
            $parsed = json_decode($trimmed, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $masked = self::maskValue($parsed, 0);
                $encoded = json_encode($masked);
                if ($encoded !== false) {
                    return $encoded;
                }
            }
            // truncated JSON -- text pass below
        }
        return self::maskString($body);
    }

    // -- Truncation (Layer 2) --------------------------------------------------

    /** Truncates s to at most maxBytes bytes without splitting a multi-byte UTF-8 character. */
    private static function truncateUtf8(string $s, int $maxBytes): string
    {
        if (strlen($s) <= $maxBytes) {
            return $s;
        }
        $cut = max(0, $maxBytes);
        while ($cut > 0 && (ord($s[$cut]) & 0xC0) === 0x80) {
            $cut--;
        }
        return substr($s, 0, $cut);
    }

    /** Byte-aware cap. Appends a marker so a reader knows content was dropped. */
    public static function capText(string $s, int $maxBytes): string
    {
        if (strlen($s) <= $maxBytes) {
            return $s;
        }
        $cut = max(0, $maxBytes - 32);
        $head = self::truncateUtf8($s, $cut);
        return $head . '…[truncated ' . (strlen($s) - strlen($head)) . ' bytes]';
    }

    private const TRIGGER_RES = [
        '/\'\s*(or|and)\s+[\'\d]/i',
        '/union\s+select/i',
        '/<\s*script/i',
        '/on\w+\s*=/i',
        '/\.\.[\/\\\\]/',
        '/\$\{jndi/i',
        '/;\s*(cat|ls|curl|wget|nc|bash|sh)\b/i',
        '/(ignore|disregard)\s+(all\s+)?(previous|prior)/i',
        '/169\.254\.169\.254|metadata\.google\.internal/i',
        '/--\s*$/m',
        '/%27|%3c\s*script/i',
    ];

    /**
     * Keeps at most maxBytes of text, windowed around the first thing that
     * looks like the reason it was flagged (injection marker, traversal, SSRF
     * target...) so a capped payload still shows the analyst the interesting
     * part rather than its first N bytes. Falls back to the head when nothing
     * stands out.
     */
    public static function snippetAround(string $text, int $maxBytes): string
    {
        if (strlen($text) <= $maxBytes) {
            return $text;
        }
        $at = -1;
        foreach (self::TRIGGER_RES as $pattern) {
            if (preg_match($pattern, $text, $m, PREG_OFFSET_CAPTURE) === 1) {
                $idx = $m[0][1];
                if ($at === -1 || $idx < $at) {
                    $at = $idx;
                }
            }
        }
        if ($at === -1 || $at <= intdiv($maxBytes, 4)) {
            return self::capText($text, $maxBytes);
        }
        $start = max(0, $at - intdiv($maxBytes, 4));
        return '…' . self::capText(substr($text, $start), $maxBytes - 3);
    }
}
