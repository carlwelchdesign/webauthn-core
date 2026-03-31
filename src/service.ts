import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
  type WebAuthnCredential,
} from '@simplewebauthn/server';

import { decodeBase64Url, encodeBase64Url } from './base64url';
import { WebAuthnCoreError, WebAuthnCoreErrorCode } from './errors';
import type {
  AuthenticationOptionsParams,
  CreateAuthenticationOptionsResult,
  CreateRegistrationOptionsResult,
  JsonValue,
  RegistrationOptionsParams,
  StoredWebAuthnCredential,
  VerifyAuthenticationResult,
  VerifyRegistrationResult,
  WebAuthnCoreDependencies,
  WebAuthnCoreOptions,
} from './types';

const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const DEFAULT_REGISTRATION_TIMEOUT_MS = 60_000;
const DEFAULT_AUTHENTICATION_TIMEOUT_MS = 60_000;

function buildChallengeMetadata(label?: string | null, metadata?: JsonValue): JsonValue | undefined {
  if (label == null && metadata == null) {
    return undefined;
  }

  return {
    ...(label != null ? { label } : {}),
    ...(metadata != null ? { context: metadata } : {}),
  };
}

function readChallengeLabel(metadata: JsonValue | undefined): string | null {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    return null;
  }

  const value = metadata.label;
  return typeof value === 'string' ? value : null;
}

function toVerificationCredential(credential: StoredWebAuthnCredential): WebAuthnCredential {
  if (!Number.isSafeInteger(credential.counter) || credential.counter < 0) {
    throw new WebAuthnCoreError(
      WebAuthnCoreErrorCode.COUNTER_OUT_OF_RANGE,
      'Stored WebAuthn counter exceeds safe integer range',
    );
  }

  return {
    id: credential.credentialId,
    publicKey: decodeBase64Url(credential.publicKeyBase64Url),
    counter: credential.counter,
    transports: credential.transports,
  };
}

export class WebAuthnCoreService {
  private readonly deps: WebAuthnCoreDependencies;
  private readonly challengeTtlMs: number;
  private readonly registrationTimeoutMs: number;
  private readonly authenticationTimeoutMs: number;

  constructor(dependencies: WebAuthnCoreDependencies, options?: WebAuthnCoreOptions) {
    this.deps = dependencies;
    this.challengeTtlMs = options?.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
    this.registrationTimeoutMs =
      options?.registrationTimeoutMs ?? DEFAULT_REGISTRATION_TIMEOUT_MS;
    this.authenticationTimeoutMs =
      options?.authenticationTimeoutMs ?? DEFAULT_AUTHENTICATION_TIMEOUT_MS;
  }

  async createRegistrationOptions(
    params: RegistrationOptionsParams,
  ): Promise<CreateRegistrationOptionsResult> {
    const config = this.deps.configProvider.getConfig();
    const credentials = await this.deps.credentialStore.listActiveCredentials(params.user.id);

    const options = await generateRegistrationOptions({
      rpID: config.rpID,
      rpName: config.rpName,
      userID: new TextEncoder().encode(params.user.id),
      userName: params.user.email,
      userDisplayName: params.user.name ?? params.user.email,
      timeout: this.registrationTimeoutMs,
      preferredAuthenticatorType: params.preferredAuthenticatorType,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'required',
      },
      excludeCredentials: credentials.map((credential) => ({
        id: credential.credentialId,
        transports: credential.transports,
      })),
    });

    await this.deps.challengeStore.invalidateOpenChallenges(params.user.id, params.flowType);
    await this.deps.challengeStore.createChallenge({
      userId: params.user.id,
      flowType: params.flowType,
      challenge: options.challenge,
      expiresAt: new Date(Date.now() + this.challengeTtlMs),
      metadata: buildChallengeMetadata(params.label, params.metadata),
    });

    return { options };
  }

  async createAuthenticationOptions(
    params: AuthenticationOptionsParams,
  ): Promise<CreateAuthenticationOptionsResult> {
    const config = this.deps.configProvider.getConfig();
    const credentials = await this.deps.credentialStore.listActiveCredentials(params.userId);

    if (credentials.length === 0) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.NO_ACTIVE_CREDENTIALS,
        'No active WebAuthn credentials found for user',
      );
    }

    const options = await generateAuthenticationOptions({
      rpID: config.rpID,
      timeout: this.authenticationTimeoutMs,
      userVerification: 'required',
      allowCredentials: credentials.map((credential) => ({
        id: credential.credentialId,
        transports: credential.transports,
      })),
    });

    await this.deps.challengeStore.invalidateOpenChallenges(params.userId, params.flowType);
    await this.deps.challengeStore.createChallenge({
      userId: params.userId,
      flowType: params.flowType,
      challenge: options.challenge,
      expiresAt: new Date(Date.now() + this.challengeTtlMs),
      metadata: params.metadata,
    });

    return { options };
  }

  async verifyRegistrationAndStoreCredential(params: {
    userId: string;
    flowType: string;
    response: RegistrationResponseJSON;
    label?: string | null;
  }): Promise<VerifyRegistrationResult> {
    const config = this.deps.configProvider.getConfig();
    const challenge = await this.deps.challengeStore.consumeLatestChallenge(
      params.userId,
      params.flowType,
    );

    if (!challenge) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.CHALLENGE_NOT_FOUND_OR_EXPIRED,
        'WebAuthn challenge not found or expired',
      );
    }

    const verification = await verifyRegistrationResponse({
      response: params.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.REGISTRATION_VERIFICATION_FAILED,
        'WebAuthn registration verification failed',
      );
    }

    const credentialId = verification.registrationInfo.credential.id;
    const existingCredential = await this.deps.credentialStore.findCredentialByCredentialId(credentialId);

    if (existingCredential && existingCredential.userId !== params.userId) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.CREDENTIAL_ALREADY_BOUND_TO_ANOTHER_USER,
        'WebAuthn credential already belongs to another user',
      );
    }

    const now = new Date();
    const label = params.label ?? readChallengeLabel(challenge.metadata);

    const credential = await this.deps.credentialStore.upsertCredential({
      userId: params.userId,
      credentialId,
      publicKeyBase64Url: encodeBase64Url(verification.registrationInfo.credential.publicKey),
      counter: verification.registrationInfo.credential.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
      backedUp: verification.registrationInfo.credentialBackedUp,
      transports: (params.response.response.transports ?? []) as AuthenticatorTransportFuture[],
      label,
      revokedAt: null,
    });

    await this.deps.userMfaStore.markMfaEnrolled(params.userId, now);

    return { verified: true, credential };
  }

  async verifyAuthenticationResponseForUser(params: {
    userId: string;
    flowType: string;
    response: AuthenticationResponseJSON;
  }): Promise<VerifyAuthenticationResult> {
    const config = this.deps.configProvider.getConfig();
    const challenge = await this.deps.challengeStore.consumeLatestChallenge(
      params.userId,
      params.flowType,
    );

    if (!challenge) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.CHALLENGE_NOT_FOUND_OR_EXPIRED,
        'WebAuthn challenge not found or expired',
      );
    }

    const credential = await this.deps.credentialStore.findActiveCredentialForUser(
      params.userId,
      params.response.id,
    );

    if (!credential) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.CREDENTIAL_NOT_FOUND_FOR_USER,
        'WebAuthn credential not found for user',
      );
    }

    const verification = await verifyAuthenticationResponse({
      response: params.response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: config.expectedOrigin,
      expectedRPID: config.rpID,
      credential: toVerificationCredential(credential),
      requireUserVerification: true,
    });

    if (!verification.verified) {
      throw new WebAuthnCoreError(
        WebAuthnCoreErrorCode.AUTHENTICATION_VERIFICATION_FAILED,
        'WebAuthn authentication verification failed',
      );
    }

    const now = new Date();
    const updatedCredential = await this.deps.credentialStore.updateCredentialUsage({
      credentialRecordId: credential.id,
      newCounter: verification.authenticationInfo.newCounter,
      deviceType: verification.authenticationInfo.credentialDeviceType,
      backedUp: verification.authenticationInfo.credentialBackedUp,
      lastUsedAt: now,
    });

    await this.deps.userMfaStore.markMfaVerified(params.userId, now);

    return { verified: true, credential: updatedCredential };
  }
}
