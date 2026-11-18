import {
  IUserConsentDocument,
  UserConsentEntity,
  UserConsentModel,
} from './consent.model.js';

export interface IConsentRepository {
  findConsent(userId: string, clientId: string): Promise<UserConsentEntity | null>;
  upsertConsent(
    userId: string,
    clientId: string,
    scopes: string[],
  ): Promise<UserConsentEntity>;
  revokeConsent(userId: string, clientId: string): Promise<boolean>;
}

function mapDocToEntity(doc: IUserConsentDocument): UserConsentEntity {
  return {
    id: String(doc._id),
    userId: String(doc.userId),
    clientId: doc.clientId,
    grantedScopes: doc.grantedScopes,
    createdAt: doc.createdAt,
    updatedAt: doc.updatedAt,
  };
}

export class MongoConsentRepository implements IConsentRepository {
  public async findConsent(
    userId: string,
    clientId: string,
  ): Promise<UserConsentEntity | null> {
    const doc = await UserConsentModel.findOne({ userId, clientId }).exec();
    return doc ? mapDocToEntity(doc) : null;
  }

  public async upsertConsent(
    userId: string,
    clientId: string,
    scopes: string[],
  ): Promise<UserConsentEntity> {
    const doc = await UserConsentModel.findOneAndUpdate(
      { userId, clientId },
      { $addToSet: { grantedScopes: { $each: scopes } } },
      { upsert: true, new: true, setDefaultsOnInsert: true },
    ).exec();
    return mapDocToEntity(doc!);
  }

  public async revokeConsent(userId: string, clientId: string): Promise<boolean> {
    const res = await UserConsentModel.deleteOne({ userId, clientId }).exec();
    return res.deletedCount > 0;
  }
}
