import mongoose, { Document, Model, Schema, Types } from 'mongoose';

export interface UserConsentEntity {
  id: string;
  userId: string;
  clientId: string;
  grantedScopes: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface IUserConsentDocument
  extends Omit<UserConsentEntity, 'id' | 'userId'>,
    Document {
  userId: Types.ObjectId;
}

const userConsentSchema = new Schema<IUserConsentDocument>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
    },
    clientId: {
      type: String,
      required: true,
      trim: true,
    },
    grantedScopes: {
      type: [String],
      required: true,
      default: [],
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

userConsentSchema.index({ userId: 1, clientId: 1 }, { unique: true });

export const UserConsentModel: Model<IUserConsentDocument> =
  mongoose.models.UserConsent ||
  mongoose.model<IUserConsentDocument>('UserConsent', userConsentSchema);
