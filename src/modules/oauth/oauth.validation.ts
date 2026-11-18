import { z } from 'zod';

export const resumeAuthorizeQuerySchema = z.object({
  auth_req_id: z.string().trim().min(8).max(128),
});

export const consentDecisionSchema = z.object({
  auth_req_id: z.string().trim().min(8).max(128),
  decision: z.enum(['approve', 'deny']),
});

export const revokeTokenSchema = z.object({
  token: z.string().trim().optional(),
  client_id: z.string().trim().optional(),
});
