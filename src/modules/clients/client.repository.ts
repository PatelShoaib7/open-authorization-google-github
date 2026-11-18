import { ApplicationType } from '../../constants/index.js';
import {
  IOAuthClientDocument,
  OAuthClientEntity,
  OAuthClientModel,
} from './client.model.js';

export interface CreateOAuthClientRecord {
  clientId: string;
  clientSecretHash?: string;
  name: string;
  description?: string;
  applicationType: ApplicationType;
  isConfidential: boolean;
  redirectUris: string[];
  allowedOrigins: string[];
  allowedScopes: string[];
  requireConsent: boolean;
  isFirstParty: boolean;
  ownerId: string;
}

export interface UpdateOAuthClientRecord {
  name?: string;
  description?: string;
  redirectUris?: string[];
  allowedOrigins?: string[];
  allowedScopes?: string[];
  requireConsent?: boolean;
  isActive?: boolean;
}

export interface IClientRepository {
  create(input: CreateOAuthClientRecord): Promise<OAuthClientEntity>;
  findByClientId(
    clientId: string,
    includeSecretHash?: boolean,
  ): Promise<OAuthClientEntity | null>;
  listAll(): Promise<OAuthClientEntity[]>;
  updateByClientId(
    clientId: string,
    input: UpdateOAuthClientRecord,
  ): Promise<OAuthClientEntity | null>;
  updateClientSecretHash(
    clientId: string,
    clientSecretHash: string,
  ): Promise<OAuthClientEntity | null>;
  deleteByClientId(clientId: string): Promise<boolean>;
  getAllActiveAllowedOrigins(): Promise<string[]>;
}

function mapDocToEntity(doc: IOAuthClientDocument): OAuthClientEntity {
  return {
    id: String(doc._id),
    clientId: doc.clientId,
    ...(doc.clientSecretHash ? { clientSecretHash: doc.clientSecretHash } : {}),
    name: doc.name,
    ...(doc.description ? { description: doc.description } : {}),
    applicationType: doc.applicationType,
    isConfidential: doc.isConfidential,
    redirectUris: doc.redirectUris,
    allowedOrigins: doc.allowedOrigins,
    allowedScopes: doc.allowedScopes,
    requireConsent: doc.requireConsent,
    isFirstParty: doc.isFirstParty,
    isActive: doc.isActive,
    ownerId: String(doc.ownerId),
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export class MongoClientRepository implements IClientRepository {
  public async create(input: CreateOAuthClientRecord): Promise<OAuthClientEntity> {
    const doc = await OAuthClientModel.create(input);
    return mapDocToEntity(doc);
  }

  public async findByClientId(
    clientId: string,
    includeSecretHash = false,
  ): Promise<OAuthClientEntity | null> {
    const query = OAuthClientModel.findOne({ clientId });
    if (includeSecretHash) {
      query.select('+clientSecretHash');
    }
    const doc = await query.exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async listAll(): Promise<OAuthClientEntity[]> {
    const docs = await OAuthClientModel.find().sort({ createdAt: -1 }).exec();
    return docs.map(mapDocToEntity);
  }

  public async updateByClientId(
    clientId: string,
    input: UpdateOAuthClientRecord,
  ): Promise<OAuthClientEntity | null> {
    const doc = await OAuthClientModel.findOneAndUpdate(
      { clientId },
      { $set: input },
      { new: true, runValidators: true },
    ).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async updateClientSecretHash(
    clientId: string,
    clientSecretHash: string,
  ): Promise<OAuthClientEntity | null> {
    const doc = await OAuthClientModel.findOneAndUpdate(
      { clientId },
      { $set: { clientSecretHash } },
      { new: true },
    ).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async deleteByClientId(clientId: string): Promise<boolean> {
    const res = await OAuthClientModel.deleteOne({ clientId }).exec();
    return res.deletedCount > 0;
  }

  public async getAllActiveAllowedOrigins(): Promise<string[]> {
    const docs = await OAuthClientModel.find(
      { isActive: true },
      { allowedOrigins: 1 },
    )
      .lean()
      .exec();

    const origins = new Set<string>();
    for (const doc of docs) {
      for (const origin of doc.allowedOrigins ?? []) {
        origins.add(origin);
      }
    }
    return Array.from(origins);
  }
}
