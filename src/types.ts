import type {
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/server';

export type JsonPrimitive = string | number | boolean | null;

export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export type WebAuthnFlowType = string;

export type WebAuthnUser = {
  id: string;
  email: string;
  name: string | null;
};

export type WebAuthnConfig = {
  rpID: string;
  rpName: string;
  expectedOrigin: string;
};

export type StoredWebAuthnCredential = {
  id: string;
  userId: string;
  credentialId: string;
  publicKeyBase64Url: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  deviceType?: string | null;
  backedUp?: boolean | null;
  label?: string | null;
  createdAt?: Date;
  lastUsedAt?: Date | null;
  revokedAt?: Date | null;
};

export type StoredWebAuthnChallenge = {
  id: string;
  userId: string;
  flowType: WebAuthnFlowType;
  challenge: string;
  metadata?: JsonValue;
  createdAt: Date;
  expiresAt: Date;
  consumedAt?: Date | null;
};

export type RegistrationOptionsParams = {
  user: WebAuthnUser;
  flowType: WebAuthnFlowType;
  label?: string | null;
  metadata?: JsonValue;
  preferredAuthenticatorType?: 'securityKey' | 'localDevice' | 'remoteDevice';
};

export type AuthenticationOptionsParams = {
  userId: string;
  flowType: WebAuthnFlowType;
  metadata?: JsonValue;
};

export type CreateChallengeInput = {
  userId: string;
  flowType: WebAuthnFlowType;
  challenge: string;
  expiresAt: Date;
  metadata?: JsonValue;
};

export type UpsertCredentialInput = {
  userId: string;
  credentialId: string;
  publicKeyBase64Url: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
  deviceType?: string | null;
  backedUp?: boolean | null;
  label?: string | null;
  revokedAt?: Date | null;
};

export type UpdateCredentialUsageInput = {
  credentialRecordId: string;
  newCounter: number;
  deviceType?: string | null;
  backedUp?: boolean | null;
  lastUsedAt: Date;
};

export interface WebAuthnConfigProvider {
  getConfig(): WebAuthnConfig;
}

export interface ChallengeStore {
  invalidateOpenChallenges(userId: string, flowType: WebAuthnFlowType): Promise<void>;
  createChallenge(input: CreateChallengeInput): Promise<void>;
  pruneExpiredChallenges(userId?: string): Promise<void>;
  consumeLatestChallenge(userId: string, flowType: WebAuthnFlowType): Promise<StoredWebAuthnChallenge | null>;
}

export interface CredentialStore {
  listActiveCredentials(userId: string): Promise<StoredWebAuthnCredential[]>;
  findCredentialByCredentialId(credentialId: string): Promise<StoredWebAuthnCredential | null>;
  findActiveCredentialForUser(userId: string, credentialId: string): Promise<StoredWebAuthnCredential | null>;
  upsertCredential(input: UpsertCredentialInput): Promise<StoredWebAuthnCredential>;
  updateCredentialUsage(input: UpdateCredentialUsageInput): Promise<StoredWebAuthnCredential>;
}

export interface UserMfaStore {
  markMfaEnrolled(userId: string, at: Date): Promise<void>;
  markMfaVerified(userId: string, at: Date): Promise<void>;
}

export type WebAuthnCoreDependencies = {
  configProvider: WebAuthnConfigProvider;
  challengeStore: ChallengeStore;
  credentialStore: CredentialStore;
  userMfaStore: UserMfaStore;
};

export type WebAuthnCoreOptions = {
  challengeTtlMs?: number;
  registrationTimeoutMs?: number;
  authenticationTimeoutMs?: number;
};

export type CreateRegistrationOptionsResult = {
  options: PublicKeyCredentialCreationOptionsJSON;
};

export type CreateAuthenticationOptionsResult = {
  options: PublicKeyCredentialRequestOptionsJSON;
};

export type VerifyRegistrationResult = {
  verified: true;
  credential: StoredWebAuthnCredential;
};

export type VerifyAuthenticationResult = {
  verified: true;
  credential: StoredWebAuthnCredential;
};
