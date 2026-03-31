export { WebAuthnCoreError, WebAuthnCoreErrorCode } from './errors';
export { WebAuthnCoreService } from './service';
export { decodeBase64Url, encodeBase64Url } from './base64url';

export type {
  AuthenticationOptionsParams,
  ChallengeStore,
  CredentialStore,
  CreateAuthenticationOptionsResult,
  CreateRegistrationOptionsResult,
  JsonValue,
  RegistrationOptionsParams,
  StoredWebAuthnChallenge,
  StoredWebAuthnCredential,
  UpdateCredentialUsageInput,
  VerifyAuthenticationResult,
  VerifyRegistrationResult,
  UpsertCredentialInput,
  UserMfaStore,
  WebAuthnConfig,
  WebAuthnConfigProvider,
  WebAuthnCoreDependencies,
  WebAuthnCoreOptions,
  WebAuthnFlowType,
  WebAuthnUser,
} from './types';
