import { parseRetryAfter } from "./retry-after.js";

export interface AuthErrorInit {
  requestId?: string | undefined;
  details?: unknown;
  retryAfter?: number | undefined;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Base class of every error the client throws. The message is fixed (`mmlabs-auth: <code>`):
 * server messages, request bodies and tokens are never kept. Only `code`, `status`,
 * `requestId` and the allow-listed `details` of a subclass survive.
 */
export class AuthError extends Error {
  override name = "AuthError";
  readonly code: string;
  readonly status: number;
  readonly requestId: string | undefined;

  constructor(code: string, status: number, init: AuthErrorInit = {}) {
    super(`mmlabs-auth: ${code}`);
    this.code = code;
    this.status = status;
    this.requestId = init.requestId;
  }

  toJSON(): object {
    return { ...this, message: this.message };
  }
}

export class SessionInvalidError extends AuthError {
  override name = "SessionInvalidError";
}
export class InvalidCredentialsError extends AuthError {
  override name = "InvalidCredentialsError";
}
export class EmailUnverifiedError extends AuthError {
  override name = "EmailUnverifiedError";
}
export class TurnstileRequiredError extends AuthError {
  override name = "TurnstileRequiredError";
}
export class TurnstileFailedError extends AuthError {
  override name = "TurnstileFailedError";
}
export class JoinUnavailableError extends AuthError {
  override name = "JoinUnavailableError";
}
export class ConfigurationError extends AuthError {
  override name = "ConfigurationError";
}
export class EmailTakenError extends AuthError {
  override name = "EmailTakenError";
}
export class EmailAlreadyVerifiedError extends AuthError {
  override name = "EmailAlreadyVerifiedError";
}
export class TokenInvalidError extends AuthError {
  override name = "TokenInvalidError";
}
export class NetworkError extends AuthError {
  override name = "NetworkError";
}

export class NotMemberError extends AuthError {
  override name = "NotMemberError";
  readonly joinAvailable: boolean;
  constructor(code: string, status: number, init: AuthErrorInit = {}) {
    super(code, status, init);
    this.joinAvailable = isRecord(init.details) && init.details.join_available === true;
  }
}

export class WeakPasswordError extends AuthError {
  override name = "WeakPasswordError";
  readonly reasons: string[];
  constructor(code: string, status: number, init: AuthErrorInit = {}) {
    super(code, status, init);
    const reasons = isRecord(init.details) ? init.details.reasons : undefined;
    this.reasons = Array.isArray(reasons)
      ? reasons.filter((r): r is string => typeof r === "string")
      : [];
  }
}

export interface ValidationIssue {
  type: string;
  loc: Array<string | number>;
}

export class ValidationError extends AuthError {
  override name = "ValidationError";
  readonly issues: ValidationIssue[];
  constructor(code: string, status: number, init: AuthErrorInit = {}) {
    super(code, status, init);
    const items = Array.isArray(init.details) ? init.details : [];
    this.issues = items.filter(isRecord).map((item) => ({
      type: typeof item.type === "string" ? item.type : "",
      loc: Array.isArray(item.loc)
        ? item.loc.filter(
            (l): l is string | number => typeof l === "string" || typeof l === "number",
          )
        : [],
    }));
  }
}

export class RateLimitedError extends AuthError {
  override name = "RateLimitedError";
  /** Seconds to wait before trying again. */
  readonly retryAfter: number;
  constructor(code: string, status: number, init: AuthErrorInit = {}) {
    super(code, status, init);
    this.retryAfter = init.retryAfter ?? parseRetryAfter(null, init.details, 0);
  }
}

type ErrorClass = new (code: string, status: number, init?: AuthErrorInit) => AuthError;

const BY_CODE: Record<string, ErrorClass> = {
  session_invalid: SessionInvalidError,
  invalid_credentials: InvalidCredentialsError,
  not_member: NotMemberError,
  email_unverified: EmailUnverifiedError,
  turnstile_required: TurnstileRequiredError,
  turnstile_failed: TurnstileFailedError,
  join_closed: JoinUnavailableError,
  join_approval_unavailable: JoinUnavailableError,
  join_unavailable: JoinUnavailableError,
  audience_mismatch: ConfigurationError,
  app_header_required: ConfigurationError,
  origin_not_allowed: ConfigurationError,
  app_mismatch: ConfigurationError,
  org_not_supported: ConfigurationError,
  email_taken: EmailTakenError,
  email_already_verified: EmailAlreadyVerifiedError,
  validation_error: ValidationError,
  weak_password: WeakPasswordError,
  token_invalid: TokenInvalidError,
  rate_limited: RateLimitedError,
};

/** Maps an error response (`{"error": {code, message, details}}`) to its error class. */
export function mapError(
  status: number,
  body: unknown,
  headers: Headers,
  nowMs: number,
): AuthError {
  const requestId = headers.get("X-Request-ID") ?? undefined;
  const error = isRecord(body) ? body.error : undefined;
  if (!isRecord(error) || typeof error.code !== "string") {
    return new AuthError("unexpected_response", status, { requestId });
  }
  const { code, details } = error;
  const ErrorType = Object.hasOwn(BY_CODE, code) ? (BY_CODE[code] ?? AuthError) : AuthError;
  const retryAfter =
    ErrorType === RateLimitedError
      ? parseRetryAfter(headers.get("Retry-After"), details, nowMs)
      : undefined;
  return new ErrorType(code, status, { requestId, details, retryAfter });
}
