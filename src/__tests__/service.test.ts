import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  generateRegistrationOptions as mockGenReg,
  generateAuthenticationOptions as mockGenAuth,
  verifyRegistrationResponse as mockVerifyReg,
  verifyAuthenticationResponse as mockVerifyAuth,
} from '@simplewebauthn/server';
import { WebAuthnCoreService } from '../service';
import { WebAuthnCoreError, WebAuthnCoreErrorCode } from '../errors';
import type {
  ChallengeStore,
  CredentialStore,
  CreateChallengeInput,
  StoredWebAuthnChallenge,
  StoredWebAuthnCredential,
  UpdateCredentialUsageInput,
  UpsertCredentialInput,
  UserMfaStore,
  WebAuthnConfigProvider,
} from '../types';

// ---------------------------------------------------------------------------
// In-memory adapters
// ---------------------------------------------------------------------------

function makeConfigProvider(overrides?: Partial<{ rpID: string; rpName: string; expectedOrigin: string }>): WebAuthnConfigProvider {
  return {
    getConfig() {
      return {
        rpID: overrides?.rpID ?? 'localhost',
        rpName: overrides?.rpName ?? 'Test App',
        expectedOrigin: overrides?.expectedOrigin ?? 'http://localhost:3000',
      };
    },
  };
}

function makeChallengeStore(): ChallengeStore & { _challenges: StoredWebAuthnChallenge[] } {
  const _challenges: StoredWebAuthnChallenge[] = [];

  return {
    _challenges,
    async invalidateOpenChallenges(userId, flowType) {
      const now = new Date();
      for (const c of _challenges) {
        if (c.userId === userId && c.flowType === flowType && !c.consumedAt) {
          c.consumedAt = now;
        }
      }
    },
    async createChallenge(input: CreateChallengeInput) {
      _challenges.push({
        id: `challenge-${_challenges.length + 1}`,
        userId: input.userId,
        flowType: input.flowType,
        challenge: input.challenge,
        metadata: input.metadata,
        createdAt: new Date(),
        expiresAt: input.expiresAt,
        consumedAt: null,
      });
    },
    async pruneExpiredChallenges(userId?: string) {
      const now = new Date();
      const filtered = _challenges.filter(
        (c) => (!userId || c.userId === userId) ? c.expiresAt > now : true,
      );
      _challenges.length = 0;
      _challenges.push(...filtered);
    },
    async consumeLatestChallenge(userId, flowType): Promise<StoredWebAuthnChallenge | null> {
      const now = new Date();
      // prune expired
      for (let i = _challenges.length - 1; i >= 0; i--) {
        if (_challenges[i].expiresAt <= now) _challenges.splice(i, 1);
      }

      const active = _challenges
        .filter((c) => c.userId === userId && c.flowType === flowType && !c.consumedAt && c.expiresAt > now)
        .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());

      const challenge = active[0];
      if (!challenge) return null;

      challenge.consumedAt = new Date();
      return challenge;
    },
  };
}

function makeCredentialStore(): CredentialStore & { _credentials: StoredWebAuthnCredential[] } {
  const _credentials: StoredWebAuthnCredential[] = [];

  return {
    _credentials,
    async listActiveCredentials(userId) {
      return _credentials.filter((c) => c.userId === userId && !c.revokedAt);
    },
    async findCredentialByCredentialId(credentialId) {
      return _credentials.find((c) => c.credentialId === credentialId) ?? null;
    },
    async findActiveCredentialForUser(userId, credentialId) {
      return _credentials.find((c) => c.userId === userId && c.credentialId === credentialId && !c.revokedAt) ?? null;
    },
    async upsertCredential(input: UpsertCredentialInput) {
      const existing = _credentials.find((c) => c.credentialId === input.credentialId);
      if (existing) {
        Object.assign(existing, {
          publicKeyBase64Url: input.publicKeyBase64Url,
          counter: input.counter,
          deviceType: input.deviceType,
          backedUp: input.backedUp,
          transports: input.transports,
          label: input.label,
          revokedAt: input.revokedAt ?? null,
        });
        return existing;
      }
      const created: StoredWebAuthnCredential = {
        id: `cred-${_credentials.length + 1}`,
        userId: input.userId,
        credentialId: input.credentialId,
        publicKeyBase64Url: input.publicKeyBase64Url,
        counter: input.counter,
        transports: input.transports,
        deviceType: input.deviceType,
        backedUp: input.backedUp,
        label: input.label,
        createdAt: new Date(),
        lastUsedAt: null,
        revokedAt: null,
      };
      _credentials.push(created);
      return created;
    },
    async updateCredentialUsage(input: UpdateCredentialUsageInput) {
      const cred = _credentials.find((c) => c.id === input.credentialRecordId);
      if (!cred) throw new Error(`Credential not found: ${input.credentialRecordId}`);
      cred.counter = input.newCounter;
      cred.deviceType = input.deviceType;
      cred.backedUp = input.backedUp;
      cred.lastUsedAt = input.lastUsedAt;
      return cred;
    },
  };
}

function makeUserMfaStore(): UserMfaStore & { _enrolled: Map<string, Date>; _verified: Map<string, Date> } {
  const _enrolled = new Map<string, Date>();
  const _verified = new Map<string, Date>();
  return {
    _enrolled,
    _verified,
    async markMfaEnrolled(userId, at) {
      _enrolled.set(userId, at);
    },
    async markMfaVerified(userId, at) {
      _verified.set(userId, at);
    },
  };
}

// ---------------------------------------------------------------------------
// Mock @simplewebauthn/server
// ---------------------------------------------------------------------------

vi.mock('@simplewebauthn/server', () => ({
  generateRegistrationOptions: vi.fn(async (opts) => ({
    challenge: 'test-reg-challenge',
    rp: { id: opts.rpID, name: opts.rpName },
    user: { id: Buffer.from(opts.userID).toString('base64url'), name: opts.userName, displayName: opts.userDisplayName },
    pubKeyCredParams: [],
    timeout: opts.timeout,
    excludeCredentials: opts.excludeCredentials ?? [],
    authenticatorSelection: opts.authenticatorSelection,
    attestation: 'none',
    extensions: {},
  })),
  generateAuthenticationOptions: vi.fn(async (opts) => ({
    challenge: 'test-auth-challenge',
    rpId: opts.rpID,
    timeout: opts.timeout,
    userVerification: opts.userVerification,
    allowCredentials: opts.allowCredentials ?? [],
    extensions: {},
  })),
  verifyRegistrationResponse: vi.fn(),
  verifyAuthenticationResponse: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const FAKE_CREDENTIAL_ID = 'cred-id-abc123';
const FAKE_PUBLIC_KEY_B64 = 'dGVzdC1wdWJsaWMta2V5'; // base64url of "test-public-key"

function makeService(overrides?: {
  configProvider?: WebAuthnConfigProvider;
  challengeStore?: ChallengeStore;
  credentialStore?: CredentialStore;
  userMfaStore?: UserMfaStore;
}) {
  return new WebAuthnCoreService({
    configProvider: overrides?.configProvider ?? makeConfigProvider(),
    challengeStore: overrides?.challengeStore ?? makeChallengeStore(),
    credentialStore: overrides?.credentialStore ?? makeCredentialStore(),
    userMfaStore: overrides?.userMfaStore ?? makeUserMfaStore(),
  });
}

// ---------------------------------------------------------------------------
// Tests: createRegistrationOptions
// ---------------------------------------------------------------------------

describe('createRegistrationOptions', () => {
  it('returns options and stores a fresh challenge', async () => {
    const challengeStore = makeChallengeStore();
    const service = makeService({ challengeStore });

    const result = await service.createRegistrationOptions({
      user: { id: 'user-1', email: 'user@example.com', name: 'Test User' },
      flowType: 'REGISTRATION',
    });

    expect(result.options.challenge).toBe('test-reg-challenge');
    expect(challengeStore._challenges).toHaveLength(1);
    expect(challengeStore._challenges[0].userId).toBe('user-1');
    expect(challengeStore._challenges[0].flowType).toBe('REGISTRATION');
    expect(challengeStore._challenges[0].consumedAt).toBeNull();
  });

  it('invalidates open challenges for the same user+flow before creating a new one', async () => {
    const challengeStore = makeChallengeStore();
    const service = makeService({ challengeStore });

    const user = { id: 'user-2', email: 'u@example.com', name: null };

    await service.createRegistrationOptions({ user, flowType: 'REGISTRATION' });
    const firstChallenge = challengeStore._challenges[0];
    expect(firstChallenge.consumedAt).toBeNull();

    await service.createRegistrationOptions({ user, flowType: 'REGISTRATION' });
    expect(firstChallenge.consumedAt).not.toBeNull();
    expect(challengeStore._challenges).toHaveLength(2);
  });

  it('stores label in challenge metadata when provided', async () => {
    const challengeStore = makeChallengeStore();
    const service = makeService({ challengeStore });

    await service.createRegistrationOptions({
      user: { id: 'user-3', email: 'u@example.com', name: null },
      flowType: 'REGISTRATION',
      label: 'YubiKey 5',
    });

    const meta = challengeStore._challenges[0].metadata as Record<string, unknown>;
    expect(meta?.label).toBe('YubiKey 5');
  });

  it('excludes existing credentials from options', async () => {
    const { generateRegistrationOptions } = await import('@simplewebauthn/server');
    const credentialStore = makeCredentialStore();
    await credentialStore.upsertCredential({
      userId: 'user-4',
      credentialId: 'existing-cred',
      publicKeyBase64Url: FAKE_PUBLIC_KEY_B64,
      counter: 0,
      transports: ['usb'],
    });

    const service = makeService({ credentialStore });
    await service.createRegistrationOptions({
      user: { id: 'user-4', email: 'u@example.com', name: null },
      flowType: 'REGISTRATION',
    });

    expect(mockGenReg).toHaveBeenCalledWith(
      expect.objectContaining({
        excludeCredentials: [{ id: 'existing-cred', transports: ['usb'] }],
      }),
    );
  });
});

// ---------------------------------------------------------------------------
// Tests: createAuthenticationOptions
// ---------------------------------------------------------------------------

describe('createAuthenticationOptions', () => {
  it('returns options and stores a challenge', async () => {
    const challengeStore = makeChallengeStore();
    const credentialStore = makeCredentialStore();
    await credentialStore.upsertCredential({
      userId: 'user-5',
      credentialId: FAKE_CREDENTIAL_ID,
      publicKeyBase64Url: FAKE_PUBLIC_KEY_B64,
      counter: 0,
      transports: ['usb'],
    });

    const service = makeService({ challengeStore, credentialStore });
    const result = await service.createAuthenticationOptions({
      userId: 'user-5',
      flowType: 'AUTHENTICATION',
    });

    expect(result.options.challenge).toBe('test-auth-challenge');
    expect(challengeStore._challenges).toHaveLength(1);
  });

  it('throws NO_ACTIVE_CREDENTIALS when user has no credentials', async () => {
    const service = makeService();

    await expect(
      service.createAuthenticationOptions({ userId: 'nobody', flowType: 'AUTHENTICATION' }),
    ).rejects.toMatchObject({
      code: WebAuthnCoreErrorCode.NO_ACTIVE_CREDENTIALS,
    });
  });
});

// ---------------------------------------------------------------------------
// Tests: verifyRegistrationAndStoreCredential
// ---------------------------------------------------------------------------

describe('verifyRegistrationAndStoreCredential', () => {
  beforeEach(() => {
    vi.mocked(mockVerifyReg).mockResolvedValue({
      verified: true,
      registrationInfo: {
        credential: {
          id: FAKE_CREDENTIAL_ID,
          publicKey: new Uint8Array([116, 101, 115, 116]), // "test"
          counter: 0,
          transports: ['usb'] as never,
        },
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        fmt: 'none',
        aaguid: '00000000-0000-0000-0000-000000000000',
        attestationObject: new Uint8Array(),
        userVerified: true,
        rpID: 'localhost',
        origin: 'http://localhost:3000',
        sameOriginWithAncestors: true,
      } as never,
    });
  });

  it('throws CHALLENGE_NOT_FOUND_OR_EXPIRED when no challenge exists', async () => {
    const service = makeService();

    await expect(
      service.verifyRegistrationAndStoreCredential({
        userId: 'user-no-challenge',
        flowType: 'REGISTRATION',
        response: {} as never,
      }),
    ).rejects.toMatchObject({ code: WebAuthnCoreErrorCode.CHALLENGE_NOT_FOUND_OR_EXPIRED });
  });

  it('stores credential and marks MFA enrolled on success', async () => {
    const challengeStore = makeChallengeStore();
    const credentialStore = makeCredentialStore();
    const userMfaStore = makeUserMfaStore();
    const service = makeService({ challengeStore, credentialStore, userMfaStore });

    // Seed a valid challenge
    const futureExpiry = new Date(Date.now() + 60_000);
    await challengeStore.createChallenge({
      userId: 'user-6',
      flowType: 'REGISTRATION',
      challenge: 'test-reg-challenge',
      expiresAt: futureExpiry,
    });

    const result = await service.verifyRegistrationAndStoreCredential({
      userId: 'user-6',
      flowType: 'REGISTRATION',
      response: { response: { transports: ['usb'] } } as never,
      label: 'My Key',
    });

    expect(result.verified).toBe(true);
    expect(result.credential.credentialId).toBe(FAKE_CREDENTIAL_ID);
    expect(credentialStore._credentials).toHaveLength(1);
    expect(userMfaStore._enrolled.has('user-6')).toBe(true);
  });

  it('challenge is consumed and cannot be reused', async () => {
    const challengeStore = makeChallengeStore();
    const credentialStore = makeCredentialStore();
    const userMfaStore = makeUserMfaStore();
    const service = makeService({ challengeStore, credentialStore, userMfaStore });

    const futureExpiry = new Date(Date.now() + 60_000);
    await challengeStore.createChallenge({
      userId: 'user-7',
      flowType: 'REGISTRATION',
      challenge: 'test-reg-challenge',
      expiresAt: futureExpiry,
    });

    await service.verifyRegistrationAndStoreCredential({
      userId: 'user-7',
      flowType: 'REGISTRATION',
      response: { response: { transports: [] } } as never,
    });

    // Second attempt must fail — challenge already consumed
    await expect(
      service.verifyRegistrationAndStoreCredential({
        userId: 'user-7',
        flowType: 'REGISTRATION',
        response: { response: { transports: [] } } as never,
      }),
    ).rejects.toMatchObject({ code: WebAuthnCoreErrorCode.CHALLENGE_NOT_FOUND_OR_EXPIRED });
  });

  it('throws CREDENTIAL_ALREADY_BOUND_TO_ANOTHER_USER if credentialId belongs to different user', async () => {
    const challengeStore = makeChallengeStore();
    const credentialStore = makeCredentialStore();
    const userMfaStore = makeUserMfaStore();
    const service = makeService({ challengeStore, credentialStore, userMfaStore });

    // Pre-create a credential owned by a different user
    await credentialStore.upsertCredential({
      userId: 'OTHER-USER',
      credentialId: FAKE_CREDENTIAL_ID,
      publicKeyBase64Url: FAKE_PUBLIC_KEY_B64,
      counter: 0,
      transports: [],
    });

    const futureExpiry = new Date(Date.now() + 60_000);
    await challengeStore.createChallenge({
      userId: 'user-8',
      flowType: 'REGISTRATION',
      challenge: 'test-reg-challenge',
      expiresAt: futureExpiry,
    });

    await expect(
      service.verifyRegistrationAndStoreCredential({
        userId: 'user-8',
        flowType: 'REGISTRATION',
        response: { response: { transports: [] } } as never,
      }),
    ).rejects.toMatchObject({ code: WebAuthnCoreErrorCode.CREDENTIAL_ALREADY_BOUND_TO_ANOTHER_USER });
  });
});

// ---------------------------------------------------------------------------
// Tests: verifyAuthenticationResponseForUser
// ---------------------------------------------------------------------------

describe('verifyAuthenticationResponseForUser', () => {
  beforeEach(() => {
    vi.mocked(mockVerifyAuth).mockResolvedValue({
      verified: true,
      authenticationInfo: {
        newCounter: 1,
        credentialDeviceType: 'singleDevice',
        credentialBackedUp: false,
        credentialID: FAKE_CREDENTIAL_ID,
        userVerified: true,
        origin: 'http://localhost:3000',
        rpID: 'localhost',
        sameOriginWithAncestors: true,
      } as never,
    });
  });

  it('throws CHALLENGE_NOT_FOUND_OR_EXPIRED when no challenge exists', async () => {
    const service = makeService();

    await expect(
      service.verifyAuthenticationResponseForUser({
        userId: 'user-no-challenge',
        flowType: 'AUTHENTICATION',
        response: { id: FAKE_CREDENTIAL_ID } as never,
      }),
    ).rejects.toMatchObject({ code: WebAuthnCoreErrorCode.CHALLENGE_NOT_FOUND_OR_EXPIRED });
  });

  it('throws CREDENTIAL_NOT_FOUND_FOR_USER when credential does not belong to user', async () => {
    const challengeStore = makeChallengeStore();
    const service = makeService({ challengeStore });

    await challengeStore.createChallenge({
      userId: 'user-9',
      flowType: 'AUTHENTICATION',
      challenge: 'test-auth-challenge',
      expiresAt: new Date(Date.now() + 60_000),
    });

    await expect(
      service.verifyAuthenticationResponseForUser({
        userId: 'user-9',
        flowType: 'AUTHENTICATION',
        response: { id: 'nonexistent-cred' } as never,
      }),
    ).rejects.toMatchObject({ code: WebAuthnCoreErrorCode.CREDENTIAL_NOT_FOUND_FOR_USER });
  });

  it('verifies, updates counter, and marks MFA verified on success', async () => {
    const challengeStore = makeChallengeStore();
    const credentialStore = makeCredentialStore();
    const userMfaStore = makeUserMfaStore();
    const service = makeService({ challengeStore, credentialStore, userMfaStore });

    await credentialStore.upsertCredential({
      userId: 'user-10',
      credentialId: FAKE_CREDENTIAL_ID,
      publicKeyBase64Url: FAKE_PUBLIC_KEY_B64,
      counter: 0,
      transports: ['usb'],
    });

    await challengeStore.createChallenge({
      userId: 'user-10',
      flowType: 'AUTHENTICATION',
      challenge: 'test-auth-challenge',
      expiresAt: new Date(Date.now() + 60_000),
    });

    const result = await service.verifyAuthenticationResponseForUser({
      userId: 'user-10',
      flowType: 'AUTHENTICATION',
      response: { id: FAKE_CREDENTIAL_ID } as never,
    });

    expect(result.verified).toBe(true);
    expect(credentialStore._credentials[0].counter).toBe(1);
    expect(userMfaStore._verified.has('user-10')).toBe(true);
  });

  it('challenge is consumed and cannot be reused', async () => {
    const challengeStore = makeChallengeStore();
    const credentialStore = makeCredentialStore();
    const userMfaStore = makeUserMfaStore();
    const service = makeService({ challengeStore, credentialStore, userMfaStore });

    await credentialStore.upsertCredential({
      userId: 'user-11',
      credentialId: FAKE_CREDENTIAL_ID,
      publicKeyBase64Url: FAKE_PUBLIC_KEY_B64,
      counter: 0,
      transports: [],
    });

    await challengeStore.createChallenge({
      userId: 'user-11',
      flowType: 'AUTHENTICATION',
      challenge: 'test-auth-challenge',
      expiresAt: new Date(Date.now() + 60_000),
    });

    await service.verifyAuthenticationResponseForUser({
      userId: 'user-11',
      flowType: 'AUTHENTICATION',
      response: { id: FAKE_CREDENTIAL_ID } as never,
    });

    // Second use must fail
    await expect(
      service.verifyAuthenticationResponseForUser({
        userId: 'user-11',
        flowType: 'AUTHENTICATION',
        response: { id: FAKE_CREDENTIAL_ID } as never,
      }),
    ).rejects.toMatchObject({ code: WebAuthnCoreErrorCode.CHALLENGE_NOT_FOUND_OR_EXPIRED });
  });
});
