import { z } from 'zod';
import { UserRole } from '../../constants/index.js';

export const updateProfileSchema = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  avatarUrl: z.string().url().max(500).optional(),
  bio: z.string().trim().max(500).optional(),
  location: z.string().trim().max(120).optional(),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required.'),
  newPassword: z
    .string()
    .min(10, 'New password must be at least 10 characters.')
    .max(128, 'New password must not exceed 128 characters.')
    .regex(/[A-Z]/, 'New password must contain at least one uppercase letter.')
    .regex(/[a-z]/, 'New password must contain at least one lowercase letter.')
    .regex(/[0-9]/, 'New password must contain at least one number.'),
});

export const updateUserAccessSchema = z.object({
  roles: z.array(z.nativeEnum(UserRole)).min(1).optional(),
  scopes: z
    .array(z.string().regex(/^[a-z0-9:_-]{2,64}$/))
    .max(50)
    .optional(),
  isActive: z.boolean().optional(),
});

export const userIdParamSchema = z.object({
  userId: z.string().min(1),
});

export const sessionFamilyParamSchema = z.object({
  familyId: z.string().min(1),
});
