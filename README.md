# webauthn-core

Reusable server-side WebAuthn orchestration with pluggable adapters for challenge storage, credential storage, and MFA state updates.

## Implemented in this phase

- Dual-format package output (ESM + CJS) with bundled type declarations
- Stable package-owned error codes via WebAuthnCoreError
- Adapter contracts for storage/config dependencies
- WebAuthnCoreService methods:
  - createRegistrationOptions
  - createAuthenticationOptions
  - verifyRegistrationAndStoreCredential
  - verifyAuthenticationResponseForUser

## Install

```bash
npm install @carlwelchdesign/webauthn-core
```

## Minimal usage

```ts
import { WebAuthnCoreService } from '@carlwelchdesign/webauthn-core';

const webauthn = new WebAuthnCoreService(
  {
    configProvider,
    challengeStore,
    credentialStore,
    userMfaStore,
  },
  {
    challengeTtlMs: 5 * 60 * 1000,
    registrationTimeoutMs: 60_000,
    authenticationTimeoutMs: 60_000,
  },
);
```

## Next integration step

Implement adapters in your app layer (for example Prisma-backed stores) and map your existing route handlers to this service.
