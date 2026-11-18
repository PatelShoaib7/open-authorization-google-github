import mongoose, { Document, Model, Schema, Types } from 'mongoose';
import { ApplicationType, DEFAULT_CLIENT_SCOPES } from '../../constants/index.js';

export interface OAuthClientEntity {
  id: string;
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
  isActive: boolean;
  ownerId: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface IOAuthClientDocument
  extends Omit<OAuthClientEntity, 'id' | 'ownerId'>,
    Document {
  ownerId: Types.ObjectId;
}

const oauthClientSchema = new Schema<IOAuthClientDocument>(
  {
    clientId: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
    },
    clientSecretHash: {
      type: String,
      select: false,
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    description: {
      type: String,
      trim: true,
      maxlength: 500,
    },
    applicationType: {
      type: String,
      enum: Object.values(ApplicationType),
      default: ApplicationType.SPA,
    },
    isConfidential: {
      type: Boolean,
      default: false,
    },
    redirectUris: {
      type: [String],
      required: true,
      validate: {
        validator: (uris: string[]) => Array.isArray(uris) && uris.length > 0,
        message: 'At least one redirectUri is required.',
      },
    },
    allowedOrigins: {
      type: [String],
      default: [],
    },
    allowedScopes: {
      type: [String],
      default: () => [...DEFAULT_CLIENT_SCOPES],
    },
    requireConsent: {
      type: Boolean,
      default: false,
    },
    isFirstParty: {
      type: Boolean,
      default: true,
    },
    isActive: {
      type: Boolean,
      default: true,
      index: true,
    },
    ownerId: {
      type: Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export const OAuthClientModel: Model<IOAuthClientDocument> =
  mongoose.models.OAuthClient ||
  mongoose.model<IOAuthClientDocument>('OAuthClient', oauthClientSchema);
