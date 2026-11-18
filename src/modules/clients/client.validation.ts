import { z } from 'zod';
import { normalizeOrigin } from '../../config/cors.js';
import { env } from '../../config/env.js';
import {
  ApplicationType,
  DEFAULT_CLIENT_SCOPES,
  SUPPORTED_SCOPES,
} from '../../constants/index.js';

function isLoopbackHostname(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]'
  );
}

export function validateStrictRedirectUri(
  uri: string,
  applicationType: ApplicationType = ApplicationType.SPA,
): boolean {
  if (uri.includes('*')) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }

  // RFC 6749 Section 3.1.2: Endpoint URI MUST NOT include a fragment component
  if (parsed.hash && parsed.hash.length > 0) {
    return false;
  }

  if (parsed.username || parsed.password) {
    return false;
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol === 'javascript:' || protocol === 'data:' || protocol === 'vbscript:') {
    return false;
  }

  if (applicationType === ApplicationType.NATIVE) {
    // RFC 8252: Native apps may use custom URI schemes or loopback HTTP
    if (protocol === 'http:' && !isLoopbackHostname(parsed.hostname)) {
      return false;
    }
    return true;
  }

  if (protocol === 'https:') {
    return true;
  }

  if (protocol === 'http:' && isLoopbackHostname(parsed.hostname)) {
    return true;
  }

  return env.NODE_ENV !== 'production' && protocol === 'http:';
}

const originSchema = z
  .string()
  .trim()
  .refine(
    (val) => {
      if (val.includes('*')) return false;
      try {
        const parsed = new URL(val);
        const isCleanOrigin =
          (parsed.protocol === 'https:' || parsed.protocol === 'http:') &&
          parsed.pathname === '/' &&
          !parsed.search &&
          !parsed.hash;
        if (!isCleanOrigin) return false;
        if (
          env.NODE_ENV === 'production' &&
          parsed.protocol === 'http:' &&
          !isLoopbackHostname(parsed.hostname)
        ) {
          return false;
        }
        return true;
      } catch {
        return false;
      }
    },
    {
      message:
        'Origin must be a clean HTTP(S) origin without path, query, fragment, or wildcards (e.g. https://app.example.com).',
    },
  )
  .transform((val) => normalizeOrigin(val));

const scopeSchema = z
  .string()
  .refine((s) => SUPPORTED_SCOPES.includes(s) || /^[a-z0-9:_-]{2,64}$/.test(s), {
    message: 'Invalid OAuth scope format.',
  });

export const createClientSchema = z
  .object({
    name: z.string().trim().min(2).max(120),
    description: z.string().trim().max(500).optional(),
    applicationType: z.nativeEnum(ApplicationType).default(ApplicationType.SPA),
    isConfidential: z.boolean().optional(),
    redirectUris: z.array(z.string().trim().min(1)).min(1).max(20),
    allowedOrigins: z.array(originSchema).max(20).optional().default([]),
    allowedScopes: z
      .array(scopeSchema)
      .min(1)
      .max(30)
      .optional()
      .default([...DEFAULT_CLIENT_SCOPES]),
    requireConsent: z.boolean().optional().default(false),
    isFirstParty: z.boolean().optional().default(true),
  })
  .superRefine((data, ctx) => {
    for (let i = 0; i < data.redirectUris.length; i++) {
      const uri = data.redirectUris[i];
      if (!uri || !validateStrictRedirectUri(uri, data.applicationType)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['redirectUris', i],
          message:
            'Redirect URI must be an exact, fragment-free HTTPS URL (or loopback HTTP URL for local dev) with no wildcards.',
        });
      }
    }
  });

export const updateClientSchema = z.object({
  name: z.string().trim().min(2).max(120).optional(),
  description: z.string().trim().max(500).optional(),
  redirectUris: z
    .array(
      z
        .string()
        .trim()
        .refine((uri) => validateStrictRedirectUri(uri, ApplicationType.WEB), {
          message:
            'Redirect URI must be an exact, fragment-free HTTPS URL (or loopback HTTP URL) with no wildcards.',
        }),
    )
    .min(1)
    .max(20)
    .optional(),
  allowedOrigins: z.array(originSchema).max(20).optional(),
  allowedScopes: z.array(scopeSchema).min(1).max(30).optional(),
  requireConsent: z.boolean().optional(),
  isActive: z.boolean().optional(),
});

export const clientIdParamSchema = z.object({
  clientId: z.string().trim().min(3).max(128),
});
