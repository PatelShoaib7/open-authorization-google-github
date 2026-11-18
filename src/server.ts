import http from 'node:http';
import { createApp } from './app.js';
import {
  connectDatabase,
  connectRedis,
  disconnectDatabase,
  disconnectRedis,
  env,
  initializeKeyStore,
} from './config/index.js';
import { logger } from './utils/logger.js';

async function bootstrap(): Promise<void> {
  try {
    const keyStore = initializeKeyStore();
    logger.info('Initialized RS256 signing keystore.', {
      activeKid: keyStore.active.kid,
      publicKeysInJwks: keyStore.jwks.keys.length,
    });

    await connectDatabase();
    await connectRedis();

    const app = createApp();
    const server = http.createServer(app);

    server.listen(env.PORT, () => {
      logger.info(`Centralized IdP & SSO Microservice listening on port ${env.PORT}`, {
        issuer: env.ISSUER_URL,
        jwksUri: `${env.ISSUER_URL}/.well-known/jwks.json`,
        discoveryUri: `${env.ISSUER_URL}/.well-known/openid-configuration`,
        environment: env.NODE_ENV,
      });
    });

    let isShuttingDown = false;
    const gracefulShutdown = async (signal: string): Promise<void> => {
      if (isShuttingDown) return;
      isShuttingDown = true;

      logger.info(`Received ${signal}. Starting graceful shutdown...`);

      const forceExitTimer = setTimeout(() => {
        logger.error('Graceful shutdown timed out after 10s. Forcing exit.');
        process.exit(1);
      }, 10_000);
      forceExitTimer.unref();

      server.close(async (closeErr) => {
        if (closeErr) {
          logger.error('HTTP server close error.', { error: closeErr });
        }

        try {
          await Promise.all([disconnectRedis(), disconnectDatabase()]);
          logger.info('All connections closed cleanly. Exiting process.');
          process.exit(0);
        } catch (cleanupErr) {
          logger.error('Error during datastore shutdown.', { error: cleanupErr });
          process.exit(1);
        }
      });
    };

    process.on('SIGTERM', () => void gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => void gracefulShutdown('SIGINT'));

    process.on('unhandledRejection', (reason) => {
      logger.error('Unhandled Promise Rejection.', { error: reason });
    });

    process.on('uncaughtException', (err) => {
      logger.error('Uncaught Exception. Shutting down.', { error: err });
      void gracefulShutdown('uncaughtException');
    });
  } catch (err) {
    logger.error('Fatal bootstrap failure.', { error: err });
    process.exit(1);
  }
}

void bootstrap();
