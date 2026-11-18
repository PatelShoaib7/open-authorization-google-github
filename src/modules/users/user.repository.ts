import { UserRole } from '../../constants/index.js';
import { IUserDocument, UserEntity, UserModel, UserProviders } from './user.model.js';

export interface CreateUserInput {
  email: string;
  emailVerified?: boolean;
  username: string;
  passwordHash?: string;
  name: string;
  avatarUrl?: string;
  bio?: string;
  location?: string;
  roles?: UserRole[];
  scopes?: string[];
  providers?: UserProviders;
}

export interface UpdateUserProfileInput {
  name?: string;
  avatarUrl?: string;
  bio?: string;
  location?: string;
}

export interface UpdateUserAccessInput {
  roles?: UserRole[];
  scopes?: string[];
  isActive?: boolean;
}

export interface IUserRepository {
  create(input: CreateUserInput): Promise<UserEntity>;
  findById(id: string, includePasswordHash?: boolean): Promise<UserEntity | null>;
  findByEmail(email: string, includePasswordHash?: boolean): Promise<UserEntity | null>;
  findByUsername(username: string, includePasswordHash?: boolean): Promise<UserEntity | null>;
  findByProviderId(
    provider: 'googleId' | 'githubId',
    providerUserId: string,
  ): Promise<UserEntity | null>;
  updateProfile(id: string, input: UpdateUserProfileInput): Promise<UserEntity | null>;
  updatePassword(id: string, passwordHash: string): Promise<void>;
  linkProvider(
    id: string,
    provider: 'googleId' | 'githubId',
    providerUserId: string,
    emailVerified?: boolean,
    avatarUrl?: string,
  ): Promise<UserEntity | null>;
  recordLogin(id: string): Promise<void>;
  updateAccess(id: string, input: UpdateUserAccessInput): Promise<UserEntity | null>;
  listAll(limit?: number, skip?: number): Promise<UserEntity[]>;
}

function mapDocToEntity(doc: IUserDocument): UserEntity {
  return {
    id: String(doc._id),
    email: doc.email,
    emailVerified: doc.emailVerified,
    username: doc.username,
    ...(doc.passwordHash ? { passwordHash: doc.passwordHash } : {}),
    name: doc.name,
    ...(doc.avatarUrl ? { avatarUrl: doc.avatarUrl } : {}),
    ...(doc.bio ? { bio: doc.bio } : {}),
    ...(doc.location ? { location: doc.location } : {}),
    roles: doc.roles,
    scopes: doc.scopes,
    providers: {
      ...(doc.providers?.googleId ? { googleId: doc.providers.googleId } : {}),
      ...(doc.providers?.githubId ? { githubId: doc.providers.githubId } : {}),
    },
    isActive: doc.isActive,
    ...(doc.lastLoginAt ? { lastLoginAt: doc.lastLoginAt } : {}),
    ...(doc.passwordChangedAt ? { passwordChangedAt: doc.passwordChangedAt } : {}),
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export class MongoUserRepository implements IUserRepository {
  public async create(input: CreateUserInput): Promise<UserEntity> {
    const created = await UserModel.create({
      email: input.email.toLowerCase().trim(),
      emailVerified: input.emailVerified ?? false,
      username: input.username.toLowerCase().trim(),
      passwordHash: input.passwordHash,
      name: input.name.trim(),
      avatarUrl: input.avatarUrl,
      bio: input.bio,
      location: input.location,
      roles: input.roles ?? [UserRole.USER],
      scopes: input.scopes ?? [],
      providers: input.providers ?? {},
    });
    return mapDocToEntity(created);
  }

  public async findById(id: string, includePasswordHash = false): Promise<UserEntity | null> {
    const query = UserModel.findById(id);
    if (includePasswordHash) {
      query.select('+passwordHash');
    }
    const doc = await query.exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async findByEmail(
    email: string,
    includePasswordHash = false,
  ): Promise<UserEntity | null> {
    const query = UserModel.findOne({ email: email.toLowerCase().trim() });
    if (includePasswordHash) {
      query.select('+passwordHash');
    }
    const doc = await query.exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async findByUsername(
    username: string,
    includePasswordHash = false,
  ): Promise<UserEntity | null> {
    const query = UserModel.findOne({ username: username.toLowerCase().trim() });
    if (includePasswordHash) {
      query.select('+passwordHash');
    }
    const doc = await query.exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async findByProviderId(
    provider: 'googleId' | 'githubId',
    providerUserId: string,
  ): Promise<UserEntity | null> {
    const doc = await UserModel.findOne({
      [`providers.${provider}`]: providerUserId,
    }).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async updateProfile(
    id: string,
    input: UpdateUserProfileInput,
  ): Promise<UserEntity | null> {
    const doc = await UserModel.findByIdAndUpdate(
      id,
      { $set: input },
      { new: true, runValidators: true },
    ).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async updatePassword(id: string, passwordHash: string): Promise<void> {
    await UserModel.findByIdAndUpdate(id, {
      $set: { passwordHash, passwordChangedAt: new Date() },
    }).exec();
  }

  public async linkProvider(
    id: string,
    provider: 'googleId' | 'githubId',
    providerUserId: string,
    emailVerified?: boolean,
    avatarUrl?: string,
  ): Promise<UserEntity | null> {
    const updateFields: Record<string, unknown> = {
      [`providers.${provider}`]: providerUserId,
      lastLoginAt: new Date(),
    };
    if (emailVerified) {
      updateFields.emailVerified = true;
    }
    if (avatarUrl) {
      updateFields.avatarUrl = avatarUrl;
    }

    const doc = await UserModel.findByIdAndUpdate(
      id,
      { $set: updateFields },
      { new: true },
    ).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async recordLogin(id: string): Promise<void> {
    await UserModel.findByIdAndUpdate(id, {
      $set: { lastLoginAt: new Date() },
    }).exec();
  }

  public async updateAccess(
    id: string,
    input: UpdateUserAccessInput,
  ): Promise<UserEntity | null> {
    const doc = await UserModel.findByIdAndUpdate(
      id,
      { $set: input },
      { new: true, runValidators: true },
    ).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async listAll(limit = 50, skip = 0): Promise<UserEntity[]> {
    const docs = await UserModel.find()
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .exec();
    return docs.map(mapDocToEntity);
  }
}
