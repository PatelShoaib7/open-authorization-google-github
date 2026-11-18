import { env } from '../config/env.js';

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'security';

const REDACTED_KEYS = new Set([
  'password',
  'passwordhash',
  'currentpassword',
  'newpassword',
  'clientsecret',
  'client_secret',
  'clientsecrethash',
  'authorization',
  'cookie',
  'set-cookie',
  'access_token',
  'accesstoken',
  'refresh_token',
  'refreshtoken',
  'id_token',
  'code',
  'code_verifier',
  'codeverifier',
]);

function sanitizeMeta(value: unknown, depth = 0): unknown {
  if (depth > 4 || value === null || value === undefined) {
    return value;
  }

  if (Array.isArray(value)) {
    return value.map((item) => sanitizeMeta(item, depth + 1));
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      ...(env.NODE_ENV !== 'production' ? { stack: value.stack } : {}),
    };
  }

  if (typeof value === 'object') {
    const sanitized: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      if (REDACTED_KEYS.has(key.toLowerCase())) {
        sanitized[key] = '[REDACTED]';
      } else {
        sanitized[key] = sanitizeMeta(val, depth + 1);
      }
    }
    return sanitized;
  }

  return value;
}

function writeLog(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
  if (env.NODE_ENV === 'test' && level !== 'error' && level !== 'security') {
    return;
  }

  const entry = {
    timestamp: new Date().toISOString(),
    level: level.toUpperCase(),
    service: 'centralized-idp-sso',
    message,
    ...(meta ? { context: sanitizeMeta(meta) } : {}),
  };

  const serialized = JSON.stringify(entry);
  if (level === 'error' || level === 'security') {
    process.stderr.write(`${serialized}\n`);
  } else {
    process.stdout.write(`${serialized}\n`);
  }
}

export const logger = {
  debug: (message: string, meta?: Record<string, unknown>) => writeLog('debug', message, meta),
  info: (message: string, meta?: Record<string, unknown>) => writeLog('info', message, meta),
  warn: (message: string, meta?: Record<string, unknown>) => writeLog('warn', message, meta),
  error: (message: string, meta?: Record<string, unknown>) => writeLog('error', message, meta),
  security: (message: string, meta?: Record<string, unknown>) =>
    writeLog('security', message, meta),
};
