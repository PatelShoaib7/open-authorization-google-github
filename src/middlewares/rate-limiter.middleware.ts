import rateLimit from 'express-rate-limit';
import { env } from '../config/env.js';
import { ErrorCode, HttpStatus } from '../constants/index.js';

const isTestEnv = env.NODE_ENV === 'test';

export const generalApiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: isTestEnv ? 10000 : 300,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      message: 'Too many requests from this IP. Please try again later.',
    },
  },
  statusCode: HttpStatus.TOO_MANY_REQUESTS,
});

export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: isTestEnv ? 10000 : 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: ErrorCode.RATE_LIMIT_EXCEEDED,
      message: 'Too many authentication attempts. Please wait 15 minutes before retrying.',
    },
  },
  statusCode: HttpStatus.TOO_MANY_REQUESTS,
});

export const oauthTokenRateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: isTestEnv ? 10000 : 60,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: {
    error: 'invalid_request',
    error_description: 'Rate limit exceeded on token endpoint.',
  },
  statusCode: HttpStatus.TOO_MANY_REQUESTS,
});
