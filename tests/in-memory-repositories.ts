import crypto from 'node:crypto';
import { UserRole } from '../src/constants/index.js';
import {
  CreateOAuthClientRecord,
  IClientRepository,
  OAuthClientEntity,
  UpdateOAuthClientRecord,
} from '../src/modules/clients/index.js';
import {
  IConsentRepository,
  UserConsentEntity,
} from '../src/modules/oauth/index.js';
import {
  CreateUserInput,
  IUserRepository,
  UpdateUserAccessInput,
  UpdateUserProfileInput,
  UserEntity,
} from '../src/modules/users/index.js';

export class InMemoryUserRepository implements IUserRepository {
  private readonly users = new Map<string, UserEntity>();

  private clone(user: UserEntity, includePasswordHash = false): UserEntity {
    const copy: UserEntity = {
      ...user,
      roles: [...user.roles],
      scopes: [...user.scopes],
      providers: { ...user.providers },
    };
    if (!includePasswordHash) {
      delete copy.passwordHash;
    }
    return copy;
  }

  public async create(input: CreateUserInput): Promise<UserEntity> {
    const now = new Date();
    const entity: UserEntity = {
      id: crypto.randomUUID(),
      email: input.email.toLowerCase().trim(),
      emailVerified: input.emailVerified ?? false,
      username: input.username.toLowerCase().trim(),
      ...(input.passwordHash ? { passwordHash: input.passwordHash } : {}),
      name: input.name,
      ...(input.avatarUrl ? { avatarUrl: input.avatarUrl } : {}),
      ...(input.bio ? { bio: input.bio } : {}),
      ...(input.location ? { location: input.location } : {}),
      roles: input.roles ?? [UserRole.USER],
      scopes: input.scopes ?? [],
      providers: input.providers ?? {},
      isActive: true,
      createdAt: now,
      updatedAt: now,
    };
    this.users.set(entity.id, entity);
    return this.clone(entity, false);
  }

  public async findById(
    id: string,
    includePasswordHash = false,
  ): Promise<UserEntity | null> {
    const found = this.users.get(id);
    return found ? this.clone(found, includePasswordHash) : null;
  }

  public async findByEmail(
    email: string,
    includePasswordHash = false,
  ): Promise<UserEntity | null> {
    const normalized = email.toLowerCase().trim();
    for (const user of this.users.values()) {
      if (user.email === normalized) {
        return this.clone(user, includePasswordHash);
      }
    }
    return null;
  }

  public async findByUsername(
    username: string,
    includePasswordHash = false,
  ): Promise<UserEntity | null> {
    const normalized = username.toLowerCase().trim();
    for (const user of this.users.values()) {
      if (user.username === normalized) {
        return this.clone(user, includePasswordHash);
      }
    }
    return null;
  }

  public async findByProviderId(
    provider: 'googleId' | 'githubId',
    providerUserId: string,
  ): Promise<UserEntity | null> {
    for (const user of this.users.values()) {
      if (user.providers[provider] === providerUserId) {
        return this.clone(user, false);
      }
    }
    return null;
  }

  public async updateProfile(
    id: string,
    input: UpdateUserProfileInput,
  ): Promise<UserEntity | null> {
    const existing = this.users.get(id);
    if (!existing) return null;
    const updated: UserEntity = {
      ...existing,
      ...input,
      updatedAt: new Date(),
    };
    this.users.set(id, updated);
    return this.clone(updated, false);
  }

  public async updatePassword(id: string, passwordHash: string): Promise<void> {
    const existing = this.users.get(id);
    if (!existing) return;
    this.users.set(id, {
      ...existing,
      passwordHash,
      passwordChangedAt: new Date(),
      updatedAt: new Date(),
    });
  }

  public async linkProvider(
    id: string,
    provider: 'googleId' | 'githubId',
    providerUserId: string,
    emailVerified?: boolean,
    avatarUrl?: string,
  ): Promise<UserEntity | null> {
    const existing = this.users.get(id);
    if (!existing) return null;
    const updated: UserEntity = {
      ...existing,
      emailVerified: emailVerified ?? existing.emailVerified,
      avatarUrl: avatarUrl ?? existing.avatarUrl,
      providers: {
        ...existing.providers,
        [provider]: providerUserId,
      },
      lastLoginAt: new Date(),
      updatedAt: new Date(),
    };
    this.users.set(id, updated);
    return this.clone(updated, false);
  }

  public async recordLogin(id: string): Promise<void> {
    const existing = this.users.get(id);
    if (!existing) return;
    existing.lastLoginAt = new Date();
  }

  public async updateAccess(
    id: string,
    input: UpdateUserAccessInput,
  ): Promise<UserEntity | null> {
    const existing = this.users.get(id);
    if (!existing) return null;
    const updated: UserEntity = {
      ...existing,
      ...(input.roles ? { roles: input.roles } : {}),
      ...(input.scopes ? { scopes: input.scopes } : {}),
      ...(input.isActive !== undefined ? { isActive: input.isActive } : {}),
      updatedAt: new Date(),
    };
    this.users.set(id, updated);
    return this.clone(updated, false);
  }

  public async listAll(limit = 50, skip = 0): Promise<UserEntity[]> {
    return Array.from(this.users.values())
      .slice(skip, skip + limit)
      .map((u) => this.clone(u, false));
  }
}

export class InMemoryClientRepository implements IClientRepository {
  private readonly clients = new Map<string, OAuthClientEntity>();

  private clone(
    client: OAuthClientEntity,
    includeSecretHash = false,
  ): OAuthClientEntity {
    const copy: OAuthClientEntity = {
      ...client,
      redirectUris: [...client.redirectUris],
      allowedOrigins: [...client.allowedOrigins],
      allowedScopes: [...client.allowedScopes],
    };
    if (!includeSecretHash) {
      delete copy.clientSecretHash;
    }
    return copy;
  }

  public async create(input: CreateOAuthClientRecord): Promise<OAuthClientEntity> {
    const now = new Date();
    const entity: OAuthClientEntity = {
      id: crypto.randomUUID(),
      clientId: input.clientId,
      ...(input.clientSecretHash ? { clientSecretHash: input.clientSecretHash } : {}),
      name: input.name,
      ...(input.description ? { description: input.description } : {}),
      applicationType: input.applicationType,
      isConfidential: input.isConfidential,
      redirectUris: [...input.redirectUris],
      allowedOrigins: [...input.allowedOrigins],
      allowedScopes: [...input.allowedScopes],
      requireConsent: input.requireConsent,
      isFirstParty: input.isFirstParty,
      isActive: true,
      ownerId: input.ownerId,
      createdAt: now,
      updatedAt: now,
    };
    this.clients.set(entity.clientId, entity);
    return this.clone(entity, false);
  }

  public async findByClientId(
    clientId: string,
    includeSecretHash = false,
  ): Promise<OAuthClientEntity | null> {
    const found = this.clients.get(clientId);
    return found ? this.clone(found, includeSecretHash) : null;
  }

  public async listAll(): Promise<OAuthClientEntity[]> {
    return Array.from(this.clients.values()).map((c) => this.clone(c, false));
  }

  public async updateByClientId(
    clientId: string,
    input: UpdateOAuthClientRecord,
  ): Promise<OAuthClientEntity | null> {
    const existing = this.clients.get(clientId);
    if (!existing) return null;
    const updated: OAuthClientEntity = {
      ...existing,
      ...input,
      updatedAt: new Date(),
    };
    this.clients.set(clientId, updated);
    return this.clone(updated, false);
  }

  public async updateClientSecretHash(
    clientId: string,
    clientSecretHash: string,
  ): Promise<OAuthClientEntity | null> {
    const existing = this.clients.get(clientId);
    if (!existing) return null;
    existing.clientSecretHash = clientSecretHash;
    existing.updatedAt = new Date();
    return this.clone(existing, false);
  }

  public async deleteByClientId(clientId: string): Promise<boolean> {
    return this.clients.delete(clientId);
  }

  public async getAllActiveAllowedOrigins(): Promise<string[]> {
    const origins = new Set<string>();
    for (const client of this.clients.values()) {
      if (client.isActive) {
        for (const origin of client.allowedOrigins) {
          origins.add(origin);
        }
      }
    }
    return Array.from(origins);
  }
}

export class InMemoryConsentRepository implements IConsentRepository {
  private readonly consents = new Map<string, UserConsentEntity>();

  private key(userId: string, clientId: string): string {
    return `${userId}:${clientId}`;
  }

  public async findConsent(
    userId: string,
    clientId: string,
  ): Promise<UserConsentEntity | null> {
    return this.consents.get(this.key(userId, clientId)) ?? null;
  }

  public async upsertConsent(
    userId: string,
    clientId: string,
    scopes: string[],
  ): Promise<UserConsentEntity> {
    const k = this.key(userId, clientId);
    const existing = this.consents.get(k);
    const mergedScopes = Array.from(
      new Set([...(existing?.grantedScopes ?? []), ...scopes]),
    );
    const now = new Date();
    const record: UserConsentEntity = {
      id: existing?.id ?? crypto.randomUUID(),
      userId,
      clientId,
      grantedScopes: mergedScopes,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    this.consents.set(k, record);
    return record;
  }

  public async revokeConsent(userId: string, clientId: string): Promise<boolean> {
    return this.consents.delete(this.key(userId, clientId));
  }
}
