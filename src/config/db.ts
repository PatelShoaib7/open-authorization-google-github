import mongoose from 'mongoose';
import { logger } from '../utils/logger.js';
import { env } from './env.js';

export async function connectDatabase(uri: string = env.MONGO_URI): Promise<void> {
  mongoose.set('strictQuery', true);

  mongoose.connection.on('connected', () => {
    logger.info('MongoDB connection established.');
  });

  mongoose.connection.on('error', (err: unknown) => {
    logger.error('MongoDB connection error.', { error: err });
  });

  mongoose.connection.on('disconnected', () => {
    logger.warn('MongoDB disconnected.');
  });

  await mongoose.connect(uri, {
    autoIndex: env.NODE_ENV !== 'production',
    serverSelectionTimeoutMS: 5000,
  });
}

export async function disconnectDatabase(): Promise<void> {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
    logger.info('MongoDB connection closed gracefully.');
  }
}

export function isDatabaseHealthy(): boolean {
  return mongoose.connection.readyState === 1;
}
