import mongoose, { Document, Model, Schema } from 'mongoose';
import { UserRole } from '../../constants/index.js';

export interface UserProviders {
  googleId?: string;
  githubId?: string;
}

export interface UserEntity {
  id: string;
  email: string;
  emailVerified: boolean;
  username: string;
  passwordHash?: string;
  name: string;
  avatarUrl?: string;
  bio?: string;
  location?: string;
  roles: UserRole[];
  scopes: string[];
  providers: UserProviders;
  isActive: boolean;
  lastLoginAt?: Date;
  passwordChangedAt?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface IUserDocument extends Omit<UserEntity, 'id'>, Document {}

const userSchema = new Schema<IUserDocument>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    emailVerified: {
      type: Boolean,
      default: false,
    },
    username: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      minlength: 3,
      maxlength: 39,
      index: true,
    },
    passwordHash: {
      type: String,
      select: false,
    },
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    avatarUrl: {
      type: String,
      trim: true,
    },
    bio: {
      type: String,
      trim: true,
      maxlength: 500,
    },
    location: {
      type: String,
      trim: true,
      maxlength: 120,
    },
    roles: {
      type: [String],
      enum: Object.values(UserRole),
      default: [UserRole.USER],
    },
    scopes: {
      type: [String],
      default: [],
    },
    providers: {
      googleId: { type: String, sparse: true, unique: true },
      githubId: { type: String, sparse: true, unique: true },
    },
    isActive: {
      type: Boolean,
      default: true,
    },
    lastLoginAt: {
      type: Date,
    },
    passwordChangedAt: {
      type: Date,
    },
  },
  {
    timestamps: true,
    versionKey: false,
  },
);

export const UserModel: Model<IUserDocument> =
  mongoose.models.User || mongoose.model<IUserDocument>('User', userSchema);
