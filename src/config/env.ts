import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const commaSeparatedList = z
  .string()
  .optional()
  .default('')
  .transform((val) =>
    val
      .split(',')
      .map((item) => item.trim())
      .filter((item) => item.length > 0),
  );

const booleanString = z
  .enum(['true', 'false', '1', '0'])
  .optional()
  .transform((val) => val === 'true' || val === '1');

const envSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(4000),
    ISSUER_URL: z.string().url().default('http://localhost:4000'),

    // Databases
    MONGO_URI: z.string().min(1).default('mongodb://127.0.0.1:27017/centralized_idp'),
    REDIS_URL: z.string().min(1).default('redis://127.0.0.1:6379'),

    // Asymmetric RS256 Keys
    RSA_KEY_ID: z.string().optional(),
    RSA_PRIVATE_KEY: z.string().optional(),
    RSA_PUBLIC_KEY: z.string().optional(),
    RSA_PRIVATE_KEY_BASE64: z.string().optional(),
    RSA_PUBLIC_KEY_BASE64: z.string().optional(),
    RSA_PRIVATE_KEY_PATH: z.string().optional().default('./keys/private.pem'),
    RSA_PUBLIC_KEY_PATH: z.string().optional().default('./keys/public.pem'),
    RSA_PREVIOUS_PUBLIC_KEYS_BASE64: commaSeparatedList,

    // Token TTLs (strictly adhering to Phase 1 security policy: 15m access, 7-30d refresh)
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(7).max(30).default(14),
    AUTH_CODE_TTL_SECONDS: z.coerce.number().int().min(30).max(300).default(120),
    SSO_SESSION_TTL_DAYS: z.coerce.number().int().min(1).max(30).default(14),

    // Cookie Policy
    COOKIE_DOMAIN: z.string().optional(),
    COOKIE_SECURE: booleanString,
    COOKIE_SAME_SITE: z.enum(['lax', 'strict']).default('lax'),

    // CORS & UI
    IDP_ALLOWED_ORIGINS: commaSeparatedList,
    LOGIN_UI_URL: z
      .string()
      .optional()
      .transform((val) => (val && val.trim().length > 0 ? val.trim() : undefined)),
    ADMIN_EMAILS: commaSeparatedList.transform((emails) =>
      emails.map((email) => email.toLowerCase()),
    ),

    // Social OAuth Providers
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    GOOGLE_CALLBACK_URL: z
      .string()
      .url()
      .default('http://localhost:4000/api/v1/auth/google/callback'),

    GITHUB_CLIENT_ID: z.string().optional(),
    GITHUB_CLIENT_SECRET: z.string().optional(),
    GITHUB_CALLBACK_URL: z
      .string()
      .url()
      .default('http://localhost:4000/api/v1/auth/github/callback'),
  })
  .superRefine((data, ctx) => {
    if (data.NODE_ENV === 'production') {
      if (!data.ISSUER_URL.startsWith('https://')) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['ISSUER_URL'],
          message: 'ISSUER_URL must use https:// in production.',
        });
      }
      if (data.COOKIE_SECURE === false) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['COOKIE_SECURE'],
          message: 'COOKIE_SECURE cannot be false in production.',
        });
      }
    }
  });

const parsedEnv = envSchema.safeParse(process.env);

if (!parsedEnv.success) {
  const formattedErrors = parsedEnv.error.issues
    .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
    .join('\n');
  throw new Error(`Invalid environment configuration:\n${formattedErrors}`);
}

export const env = {
  ...parsedEnv.data,
  COOKIE_SECURE:
    parsedEnv.data.COOKIE_SECURE ?? parsedEnv.data.NODE_ENV === 'production',
  ISSUER_URL: parsedEnv.data.ISSUER_URL.replace(/\/+$/, ''),
} as const;

export type EnvConfig = typeof env;
