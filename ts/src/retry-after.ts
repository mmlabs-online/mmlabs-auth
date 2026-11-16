const DEFAULT_RETRY_AFTER = 5;
/** Upper bound for any wait: the server's 15-minute backoff cap (T5). */
export const MAX_RETRY_AFTER = 900;

function clamp(seconds: number): number {
  return Number.isFinite(seconds)
    ? Math.min(MAX_RETRY_AFTER, Math.max(0, seconds))
    : MAX_RETRY_AFTER;
}

/**
 * Seconds to wait after a 429: `Retry-After` as delta-seconds or an HTTP-date, then the
 * envelope's `details.retry_after`, then 5 s. Always clamped to [0, 900] s.
 */
export function parseRetryAfter(header: string | null, details: unknown, nowMs: number): number {
  const value = header?.trim() ?? "";
  if (/^\d+$/.test(value)) return clamp(Number(value));
  if (value !== "") {
    const at = Date.parse(value);
    if (!Number.isNaN(at)) return clamp(Math.ceil((at - nowMs) / 1000));
  }
  if (typeof details === "object" && details !== null && "retry_after" in details) {
    const fallback = details.retry_after;
    if (typeof fallback === "number" && Number.isFinite(fallback) && fallback >= 0) {
      return clamp(Math.ceil(fallback));
    }
  }
  return DEFAULT_RETRY_AFTER;
}
