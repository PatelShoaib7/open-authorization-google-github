import { Redis } from 'ioredis';
import { REDIS_PREFIXES, TOKEN_LIMITS } from '../constants/index.js';
import { RefreshTokenFamily } from '../types/index.js';
import { logger } from '../utils/logger.js';
import { env } from './env.js';

export type RotationOutcome =
  | { status: 'ROTATED'; family: RefreshTokenFamily }
  | { status: 'REUSE_DETECTED'; family: RefreshTokenFamily }
  | { status: 'NOT_FOUND' }
  | { status: 'EXPIRED' }
  | { status: 'INVALID_TOKEN' };

export interface IRedisStore {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
  consumeOnce(key: string): Promise<string | null>;
  sadd(key: string, member: string, ttlSeconds?: number): Promise<void>;
  srem(key: string, member: string): Promise<void>;
  smembers(key: string): Promise<string[]>;
  rotateRefreshTokenFamily(params: {
    familyId: string;
    incomingTokenHash: string;
    newTokenHash: string;
    nowMs: number;
  }): Promise<RotationOutcome>;
  ping(): Promise<boolean>;
  disconnect(): Promise<void>;
}

const CONSUME_ONCE_LUA = `
local val = redis.call('GET', KEYS[1])
if val then
  redis.call('DEL', KEYS[1])
end
return val
`;

const ROTATE_FAMILY_LUA = `
local familyKey = KEYS[1]
local userFamiliesPrefix = ARGV[1]
local incomingHash = ARGV[2]
local newHash = ARGV[3]
local nowMs = tonumber(ARGV[4])
local maxUsedHashes = tonumber(ARGV[5])

local raw = redis.call('GET', familyKey)
if not raw then
  return {'NOT_FOUND'}
end

local family = cjson.decode(raw)
if family.expiresAt <= nowMs then
  redis.call('DEL', familyKey)
  redis.call('SREM', userFamiliesPrefix .. family.userId, family.familyId)
  return {'EXPIRED'}
end

if family.currentTokenHash == incomingHash then
  local used = family.usedTokenHashes or {}
  table.insert(used, incomingHash)
  while #used > maxUsedHashes do
    table.remove(used, 1)
  end
  family.usedTokenHashes = used
  family.currentTokenHash = newHash
  family.rotatedAt = nowMs

  local pttl = redis.call('PTTL', familyKey)
  local updatedRaw = cjson.encode(family)
  if pttl > 0 then
    redis.call('PSETEX', familyKey, pttl, updatedRaw)
  else
    local remainingMs = math.max(1000, family.expiresAt - nowMs)
    redis.call('PSETEX', familyKey, remainingMs, updatedRaw)
  end
  return {'ROTATED', updatedRaw}
end

local isReused = false
local used = family.usedTokenHashes or {}
for i = 1, #used do
  if used[i] == incomingHash then
    isReused = true
    break
  end
end

if isReused then
  redis.call('DEL', familyKey)
  redis.call('SREM', userFamiliesPrefix .. family.userId, family.familyId)
  return {'REUSE_DETECTED', raw}
end

return {'INVALID_TOKEN'}
`;

export class IoRedisStore implements IRedisStore {
  private readonly client: Redis;

  constructor(redisUrl: string = env.REDIS_URL) {
    this.client = new Redis(redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 3,
      enableReadyCheck: true,
    });

    this.client.on('connect', () => {
      logger.info('Redis connection established.');
    });

    this.client.on('error', (err: unknown) => {
      logger.error('Redis client error.', { error: err });
    });
  }

  public async connect(): Promise<void> {
    if (this.client.status === 'wait') {
      await this.client.connect();
    }
  }

  public async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds && ttlSeconds > 0) {
      await this.client.set(key, value, 'EX', ttlSeconds);
    } else {
      await this.client.set(key, value);
    }
  }

  public async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  public async consumeOnce(key: string): Promise<string | null> {
    const result = await this.client.eval(CONSUME_ONCE_LUA, 1, key);
    return typeof result === 'string' ? result : null;
  }

  public async sadd(key: string, member: string, ttlSeconds?: number): Promise<void> {
    await this.client.sadd(key, member);
    if (ttlSeconds && ttlSeconds > 0) {
      await this.client.expire(key, ttlSeconds);
    }
  }

  public async srem(key: string, member: string): Promise<void> {
    await this.client.srem(key, member);
  }

  public async smembers(key: string): Promise<string[]> {
    return this.client.smembers(key);
  }

  public async rotateRefreshTokenFamily(params: {
    familyId: string;
    incomingTokenHash: string;
    newTokenHash: string;
    nowMs: number;
  }): Promise<RotationOutcome> {
    const familyKey = `${REDIS_PREFIXES.REFRESH_FAMILY}${params.familyId}`;
    const rawResult = (await this.client.eval(
      ROTATE_FAMILY_LUA,
      1,
      familyKey,
      REDIS_PREFIXES.USER_FAMILIES,
      params.incomingTokenHash,
      params.newTokenHash,
      String(params.nowMs),
      String(TOKEN_LIMITS.MAX_USED_TOKEN_HASHES_PER_FAMILY),
    )) as [string, string?];

    const [status, payload] = rawResult;

    if (status === 'ROTATED' && payload) {
      return { status: 'ROTATED', family: JSON.parse(payload) as RefreshTokenFamily };
    }
    if (status === 'REUSE_DETECTED' && payload) {
      return { status: 'REUSE_DETECTED', family: JSON.parse(payload) as RefreshTokenFamily };
    }
    if (status === 'EXPIRED') {
      return { status: 'EXPIRED' };
    }
    if (status === 'INVALID_TOKEN') {
      return { status: 'INVALID_TOKEN' };
    }
    return { status: 'NOT_FOUND' };
  }

  public async ping(): Promise<boolean> {
    try {
      const pong = await this.client.ping();
      return pong === 'PONG';
    } catch {
      return false;
    }
  }

  public async disconnect(): Promise<void> {
    if (this.client.status !== 'end') {
      await this.client.quit();
      logger.info('Redis connection closed gracefully.');
    }
  }
}

/**
 * Deterministic, TTL-aware in-memory Redis store used strictly for isolated automated testing.
 */
export class InMemoryRedisStore implements IRedisStore {
  private readonly kv = new Map<string, { value: string; expiresAtMs?: number }>();
  private readonly sets = new Map<string, { members: Set<string>; expiresAtMs?: number }>();

  private isExpired(expiresAtMs?: number): boolean {
    return expiresAtMs !== undefined && Date.now() >= expiresAtMs;
  }

  public async get(key: string): Promise<string | null> {
    const entry = this.kv.get(key);
    if (!entry) return null;
    if (this.isExpired(entry.expiresAtMs)) {
      this.kv.delete(key);
      return null;
    }
    return entry.value;
  }

  public async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    const expiresAtMs =
      ttlSeconds && ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : undefined;
    this.kv.set(key, { value, expiresAtMs });
  }

  public async del(key: string): Promise<void> {
    this.kv.delete(key);
    this.sets.delete(key);
  }

  public async consumeOnce(key: string): Promise<string | null> {
    const val = await this.get(key);
    if (val !== null) {
      this.kv.delete(key);
    }
    return val;
  }

  public async sadd(key: string, member: string, ttlSeconds?: number): Promise<void> {
    const existing = this.sets.get(key);
    const expiresAtMs =
      ttlSeconds && ttlSeconds > 0
        ? Date.now() + ttlSeconds * 1000
        : existing?.expiresAtMs;
    if (existing && !this.isExpired(existing.expiresAtMs)) {
      existing.members.add(member);
      existing.expiresAtMs = expiresAtMs;
    } else {
      this.sets.set(key, { members: new Set([member]), expiresAtMs });
    }
  }

  public async srem(key: string, member: string): Promise<void> {
    const existing = this.sets.get(key);
    if (existing) {
      existing.members.delete(member);
    }
  }

  public async smembers(key: string): Promise<string[]> {
    const existing = this.sets.get(key);
    if (!existing) return [];
    if (this.isExpired(existing.expiresAtMs)) {
      this.sets.delete(key);
      return [];
    }
    return Array.from(existing.members);
  }

  public async rotateRefreshTokenFamily(params: {
    familyId: string;
    incomingTokenHash: string;
    newTokenHash: string;
    nowMs: number;
  }): Promise<RotationOutcome> {
    const familyKey = `${REDIS_PREFIXES.REFRESH_FAMILY}${params.familyId}`;
    const entry = this.kv.get(familyKey);
    if (!entry || this.isExpired(entry.expiresAtMs)) {
      this.kv.delete(familyKey);
      return { status: 'NOT_FOUND' };
    }

    const family = JSON.parse(entry.value) as RefreshTokenFamily;
    if (family.expiresAt <= params.nowMs) {
      this.kv.delete(familyKey);
      await this.srem(`${REDIS_PREFIXES.USER_FAMILIES}${family.userId}`, family.familyId);
      return { status: 'EXPIRED' };
    }

    if (family.currentTokenHash === params.incomingTokenHash) {
      const used = [...family.usedTokenHashes, params.incomingTokenHash];
      while (used.length > TOKEN_LIMITS.MAX_USED_TOKEN_HASHES_PER_FAMILY) {
        used.shift();
      }
      const updatedFamily: RefreshTokenFamily = {
        ...family,
        usedTokenHashes: used,
        currentTokenHash: params.newTokenHash,
        rotatedAt: params.nowMs,
      };
      this.kv.set(familyKey, {
        value: JSON.stringify(updatedFamily),
        expiresAtMs: entry.expiresAtMs,
      });
      return { status: 'ROTATED', family: updatedFamily };
    }

    if (family.usedTokenHashes.includes(params.incomingTokenHash)) {
      this.kv.delete(familyKey);
      await this.srem(`${REDIS_PREFIXES.USER_FAMILIES}${family.userId}`, family.familyId);
      return { status: 'REUSE_DETECTED', family };
    }

    return { status: 'INVALID_TOKEN' };
  }

  public async ping(): Promise<boolean> {
    return true;
  }

  public async disconnect(): Promise<void> {
    this.kv.clear();
    this.sets.clear();
  }
}

let activeRedisStore: IRedisStore | null = null;

export async function connectRedis(): Promise<IRedisStore> {
  if (activeRedisStore) {
    return activeRedisStore;
  }
  const store = new IoRedisStore(env.REDIS_URL);
  await store.connect();
  activeRedisStore = store;
  return activeRedisStore;
}

export function setRedisStore(store: IRedisStore): void {
  activeRedisStore = store;
}

export function getRedisStore(): IRedisStore {
  if (!activeRedisStore) {
    if (env.NODE_ENV === 'test') {
      activeRedisStore = new InMemoryRedisStore();
      return activeRedisStore;
    }
    throw new Error('Redis store has not been initialized. Call connectRedis() first.');
  }
  return activeRedisStore;
}

export async function disconnectRedis(): Promise<void> {
  if (activeRedisStore) {
    await activeRedisStore.disconnect();
    activeRedisStore = null;
  }
}
