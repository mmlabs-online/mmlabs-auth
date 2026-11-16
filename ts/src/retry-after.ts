const DEFAULT_RETRY_AFTER = 5;

/**
 * Seconds to wait after a 429: `Retry-After` as delta-seconds or an HTTP-date, then the
 * envelope's `details.retry_after`, then 5 s.
 */
export function parseRetryAfter(header: string | null, details: unknown, nowMs: number): number {
  const value = header?.trim() ?? "";
  if (/^\d+$/.test(value)) return Number(value);
  if (value !== "") {
    const at = Date.parse(value);
    if (!Number.isNaN(at)) return Math.max(0, Math.ceil((at - nowMs) / 1000));
  }
  if (typeof details === "object" && details !== null && "retry_after" in details) {
    const fallback = details.retry_after;
    if (typeof fallback === "number" && Number.isFinite(fallback) && fallback >= 0) {
      return Math.ceil(fallback);
    }
  }
  return DEFAULT_RETRY_AFTER;
}
