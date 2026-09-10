<?php

declare(strict_types=1);

namespace PasskeyMfa\Libraries;

/**
 * Wraps log_message() so the diagnostic logging added while chasing
 * several confirmed bugs in this package only ever writes when
 * ENVIRONMENT is 'development' - not in staging or production.
 *
 * WHY THIS EXISTS: this logging includes user_id values, credential_id
 * values, and exception details - genuinely useful while actively
 * diagnosing an issue, but not something that should accumulate in a
 * production log indefinitely just because a past investigation needed
 * it, and not something every app that installs this package should
 * have silently writing to their own production logs on every failed
 * passkey attempt. Gating on environment, rather than removing the
 * logging entirely, keeps it available the next time it's actually
 * needed - switch to a dev environment (or set
 * CI_ENVIRONMENT=development for a specific debugging session) to
 * reproduce and see it, rather than needing to re-add logging from
 * scratch each time.
 *
 * Deliberately its own tiny class rather than a check repeated inline
 * at every call site - keeps the condition itself in one place, and
 * makes it easy to adjust later (e.g. if a different flag than
 * ENVIRONMENT ever becomes the better switch) without touching every
 * individual log call.
 */
class DiagnosticLog
{
    /**
     * @param array<string, mixed> $context
     */
    public static function write(string $level, string $message, array $context = []): void
    {
        if (ENVIRONMENT !== 'development') {
            return;
        }

        log_message($level, $message, $context);
    }
}
