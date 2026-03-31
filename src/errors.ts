export const WebAuthnCoreErrorCode = {
  CONFIG_INVALID: 'CONFIG_INVALID',
  NO_ACTIVE_CREDENTIALS: 'NO_ACTIVE_CREDENTIALS',
  CHALLENGE_NOT_FOUND_OR_EXPIRED: 'CHALLENGE_NOT_FOUND_OR_EXPIRED',
  REGISTRATION_VERIFICATION_FAILED: 'REGISTRATION_VERIFICATION_FAILED',
  AUTHENTICATION_VERIFICATION_FAILED: 'AUTHENTICATION_VERIFICATION_FAILED',
  CREDENTIAL_ALREADY_BOUND_TO_ANOTHER_USER: 'CREDENTIAL_ALREADY_BOUND_TO_ANOTHER_USER',
  CREDENTIAL_NOT_FOUND_FOR_USER: 'CREDENTIAL_NOT_FOUND_FOR_USER',
  COUNTER_OUT_OF_RANGE: 'COUNTER_OUT_OF_RANGE',
} as const;

export type WebAuthnCoreErrorCode =
  (typeof WebAuthnCoreErrorCode)[keyof typeof WebAuthnCoreErrorCode];

export class WebAuthnCoreError extends Error {
  readonly code: WebAuthnCoreErrorCode;

  constructor(code: WebAuthnCoreErrorCode, message: string, options?: { cause?: unknown }) {
    super(message);
    this.name = 'WebAuthnCoreError';
    this.code = code;
    if (options?.cause !== undefined) {
      // Assign cause manually for runtimes where ErrorOptions typing differs.
      (this as Error & { cause?: unknown }).cause = options.cause;
    }
  }
}
