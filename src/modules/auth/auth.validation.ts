import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().trim().email('Valid email address is required.').max(254),
  username: z
    .string()
    .trim()
    .min(3, 'Username must be at least 3 characters.')
    .max(39, 'Username must not exceed 39 characters.')
    .regex(
      /^[a-zA-Z0-9_-]+$/,
      'Username may only contain letters, numbers, underscores, and hyphens.',
    ),
  password: z
    .string()
    .min(10, 'Password must be at least 10 characters.')
    .max(128, 'Password must not exceed 128 characters.')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter.')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter.')
    .regex(/[0-9]/, 'Password must contain at least one number.'),
  name: z.string().trim().min(1, 'Name is required.').max(120),
});

export const loginSchema = z.object({
  identifier: z
    .string()
    .trim()
    .min(1, 'Email or username is required.')
    .max(254),
  password: z.string().min(1, 'Password is required.').max(128),
  authReqId: z.string().trim().optional(),
});

export const socialInitQuerySchema = z.object({
  auth_req_id: z.string().trim().optional(),
});

export const socialCallbackQuerySchema = z.object({
  code: z.string().min(1, 'Missing authorization code from provider.'),
  state: z.string().min(8, 'Missing or invalid OAuth state parameter.'),
});
