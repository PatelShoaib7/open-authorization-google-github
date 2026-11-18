import crypto from 'node:crypto';
import { env } from '../../config/env.js';
import { getRedisStore } from '../../config/redis.js';
import { ErrorCode, HttpStatus, REDIS_PREFIXES } from '../../constants/index.js';
import { RefreshTokenFamily, RequestMeta, SsoSessionData } from '../../types/index.js';
import { AppError } from '../../utils/app-error.js';
import { generateRandomToken, sha256Hex } from '../../utils/crypto.js';
import { logger } from '../../utils/logger.js';

const UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface IssueRefreshTokenParams {
  userId: string;
  clientId: string;
  scope: string;
  meta?: RequestMeta;
}

export interface SafeSessionSummary {
  familyId: string;
  clientId: string;
  scope: string;
  userAgent?: string;
  ipAddress?: string;
  createdAt: string;
  rotatedAt: string;
  expiresAt: string;
}

export class TokenFamilyService {
  private get refreshTtlSeconds(): number {
    return env.REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60;
  }

  private get ssoTtlSeconds(): number {
    return env.SSO_SESSION_TTL_DAYS * 24 * 60 * 60;
  }

  /**
   * Creates a new Refresh Token family in Redis and returns the raw opaque token for HttpOnly cookie storage.
   */
  public async issueRefreshTokenFamily(params: IssueRefreshTokenParams): Promise<{
    rawRefreshToken: string;
    family: RefreshTokenFamily;
  }> {
    const redis = getRedisStore();
    const familyId = crypto.randomUUID();
    const secret = generateRandomToken(32);
    const rawRefreshToken = `rt.${familyId}.${secret}`;
    const tokenHash = sha256Hex(rawRefreshToken);

    const now = Date.now();
    const expiresAt = now + this.refreshTtlSeconds * 1000;

    const family: RefreshTokenFamily = {
      familyId,
      userId: params.userId,
      clientId: params.clientId,
      scope: params.scope,
      currentTokenHash: tokenHash,
      usedTokenHashes: [],
      ...(params.meta?.userAgent ? { userAgent: params.meta.userAgent.slice(0, 256) } : {}),
      ...(params.meta?.ipAddress ? { ipAddress: params.meta.ipAddress } : {}),
      createdAt: now,
      rotatedAt: now,
      expiresAt,
    };

    const familyKey = `${REDIS_PREFIXES.REFRESH_FAMILY}${familyId}`;
    const userFamiliesKey = `${REDIS_PREFIXES.USER_FAMILIES}${params.userId}`;

    await redis.set(familyKey, JSON.stringify(family), this.refreshTtlSeconds);
    await redis.sadd(userFamiliesKey, familyId, this.refreshTtlSeconds);

    return { rawRefreshToken, family };
  }

  /**
   * Atomically rotates a Refresh Token and enforces strict Reuse Detection.
   * If a previously rotated token is replayed, the entire token family is revoked immediately.
   */
  public async rotateRefreshToken(rawRefreshToken: string): Promise<{
    newRawRefreshToken: string;
    family: RefreshTokenFamily;
  }> {
    const parts = rawRefreshToken.split('.');
    if (parts.length !== 3 || parts[0] !== 'rt' || !parts[1] || !parts[2]) {
      throw new AppError(
        'Malformed refresh token.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_REFRESH_TOKEN,
      );
    }

    const familyId = parts[1];
    if (!UUID_REGEX.test(familyId)) {
      throw new AppError(
        'Invalid refresh token family identifier.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_REFRESH_TOKEN,
      );
    }

    const incomingTokenHash = sha256Hex(rawRefreshToken);
    const newSecret = generateRandomToken(32);
    const newRawRefreshToken = `rt.${familyId}.${newSecret}`;
    const newTokenHash = sha256Hex(newRawRefreshToken);

    const redis = getRedisStore();
    const outcome = await redis.rotateRefreshTokenFamily({
      familyId,
      incomingTokenHash,
      newTokenHash,
      nowMs: Date.now(),
    });

    if (outcome.status === 'REUSE_DETECTED') {
      logger.security(
        'REFRESH_TOKEN_REUSE_DETECTED: Compromised or rotated refresh token replayed. Entire token family revoked.',
        {
          userId: outcome.family.userId,
          familyId: outcome.family.familyId,
          clientId: outcome.family.clientId,
        },
      );
      throw new AppError(
        'Refresh token reuse detected. For your security, this session has been revoked.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.REFRESH_TOKEN_REUSE_DETECTED,
      );
    }

    if (outcome.status !== 'ROTATED') {
      throw new AppError(
        'Invalid or expired refresh token.',
        HttpStatus.UNAUTHORIZED,
        ErrorCode.INVALID_REFRESH_TOKEN,
      );
    }

    return {
      newRawRefreshToken,
      family: outcome.family,
    };
  }

  public extractFamilyIdFromRawToken(rawRefreshToken?: string): string | null {
    if (!rawRefreshToken) return null;
    const parts = rawRefreshToken.split('.');
    if (parts.length !== 3 || parts[0] !== 'rt' || !parts[1] || !UUID_REGEX.test(parts[1])) {
      return null;
    }
    return parts[1];
  }

  public async revokeFamilyById(familyId: string, expectedUserId?: string): Promise<boolean> {
    const redis = getRedisStore();
    const familyKey = `${REDIS_PREFIXES.REFRESH_FAMILY}${familyId}`;
    const raw = await redis.get(familyKey);
    if (!raw) {
      return false;
    }

    const family = JSON.parse(raw) as RefreshTokenFamily;
    if (expectedUserId && family.userId !== expectedUserId) {
      return false;
    }

    await redis.del(familyKey);
    await redis.srem(`${REDIS_PREFIXES.USER_FAMILIES}${family.userId}`, familyId);
    return true;
  }

  public async revokeFamilyByRawToken(rawRefreshToken?: string): Promise<void> {
    const familyId = this.extractFamilyIdFromRawToken(rawRefreshToken);
    if (!familyId) return;
    await this.revokeFamilyById(familyId);
  }

  public async revokeAllUserFamilies(userId: string): Promise<number> {
    const redis = getRedisStore();
    const userFamiliesKey = `${REDIS_PREFIXES.USER_FAMILIES}${userId}`;
    const familyIds = await redis.smembers(userFamiliesKey);

    for (const familyId of familyIds) {
      await redis.del(`${REDIS_PREFIXES.REFRESH_FAMILY}${familyId}`);
    }
    await redis.del(userFamiliesKey);
    return familyIds.length;
  }

  public async listUserActiveFamilies(userId: string): Promise<SafeSessionSummary[]> {
    const redis = getRedisStore();
    const userFamiliesKey = `${REDIS_PREFIXES.USER_FAMILIES}${userId}`;
    const familyIds = await redis.smembers(userFamiliesKey);
    const summaries: SafeSessionSummary[] = [];
    const now = Date.now();

    for (const familyId of familyIds) {
      const raw = await redis.get(`${REDIS_PREFIXES.REFRESH_FAMILY}${familyId}`);
      if (!raw) {
        await redis.srem(userFamiliesKey, familyId);
        continue;
      }
      const family = JSON.parse(raw) as RefreshTokenFamily;
      if (family.expiresAt <= now) {
        await redis.del(`${REDIS_PREFIXES.REFRESH_FAMILY}${familyId}`);
        await redis.srem(userFamiliesKey, familyId);
        continue;
      }
      summaries.push({
        familyId: family.familyId,
        clientId: family.clientId,
        scope: family.scope,
        ...(family.userAgent ? { userAgent: family.userAgent } : {}),
        ...(family.ipAddress ? { ipAddress: family.ipAddress } : {}),
        createdAt: new Date(family.createdAt).toISOString(),
        rotatedAt: new Date(family.rotatedAt).toISOString(),
        expiresAt: new Date(family.expiresAt).toISOString(),
      });
    }

    return summaries.sort((a, b) => b.rotatedAt.localeCompare(a.rotatedAt));
  }

  // ==========================================================================
  // Browser Single Sign-On (SSO) Session Management
  // ==========================================================================

  public async createSsoSession(userId: string, meta?: RequestMeta): Promise<string> {
    const redis = getRedisStore();
    const rawSessionToken = `sso.${crypto.randomUUID()}.${generateRandomToken(32)}`;
    const sessionHash = sha256Hex(rawSessionToken);
    const now = Date.now();

    const sessionData: SsoSessionData = {
      sessionId: sessionHash,
      userId,
      ...(meta?.userAgent ? { userAgent: meta.userAgent.slice(0, 256) } : {}),
      ...(meta?.ipAddress ? { ipAddress: meta.ipAddress } : {}),
      createdAt: now,
      expiresAt: now + this.ssoTtlSeconds * 1000,
    };

    await redis.set(
      `${REDIS_PREFIXES.SSO_SESSION}${sessionHash}`,
      JSON.stringify(sessionData),
      this.ssoTtlSeconds,
    );
    await redis.sadd(
      `${REDIS_PREFIXES.USER_SSO_SESSIONS}${userId}`,
      sessionHash,
      this.ssoTtlSeconds,
    );

    return rawSessionToken;
  }

  public async resolveSsoSession(rawSessionToken?: string): Promise<SsoSessionData | null> {
    if (!rawSessionToken || !rawSessionToken.startsWith('sso.')) {
      return null;
    }
    const redis = getRedisStore();
    const sessionHash = sha256Hex(rawSessionToken);
    const raw = await redis.get(`${REDIS_PREFIXES.SSO_SESSION}${sessionHash}`);
    if (!raw) {
      return null;
    }

    const session = JSON.parse(raw) as SsoSessionData;
    if (session.expiresAt <= Date.now()) {
      await redis.del(`${REDIS_PREFIXES.SSO_SESSION}${sessionHash}`);
      return null;
    }
    return session;
  }

  public async destroySsoSession(rawSessionToken?: string): Promise<void> {
    if (!rawSessionToken || !rawSessionToken.startsWith('sso.')) {
      return;
    }
    const redis = getRedisStore();
    const sessionHash = sha256Hex(rawSessionToken);
    const raw = await redis.get(`${REDIS_PREFIXES.SSO_SESSION}${sessionHash}`);
    if (raw) {
      const session = JSON.parse(raw) as SsoSessionData;
      await redis.srem(`${REDIS_PREFIXES.USER_SSO_SESSIONS}${session.userId}`, sessionHash);
    }
    await redis.del(`${REDIS_PREFIXES.SSO_SESSION}${sessionHash}`);
  }

  public async destroyAllUserSsoSessions(userId: string): Promise<void> {
    const redis = getRedisStore();
    const userSessionsKey = `${REDIS_PREFIXES.USER_SSO_SESSIONS}${userId}`;
    const hashes = await redis.smembers(userSessionsKey);
    for (const hash of hashes) {
      await redis.del(`${REDIS_PREFIXES.SSO_SESSION}${hash}`);
    }
    await redis.del(userSessionsKey);
  }
}
