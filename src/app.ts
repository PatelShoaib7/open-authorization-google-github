import cookieParser from 'cookie-parser';
import express, { Application } from 'express';
import helmet from 'helmet';
import {
  dynamicCorsMiddleware,
  env,
  isDatabaseHealthy,
  registerAllowedOriginsProvider,
} from './config/index.js';
import { getKeyStore } from './config/keys.js';
import { getRedisStore } from './config/redis.js';
import { HttpStatus } from './constants/index.js';
import {
  generalApiRateLimiter,
  globalErrorHandler,
  notFoundHandler,
  requestContextMiddleware,
} from './middlewares/index.js';
import {
  AuthController,
  AuthService,
  SocialOAuthService,
  TokenFamilyService,
  createAuthRouter,
} from './modules/auth/index.js';
import {
  ClientController,
  ClientService,
  IClientRepository,
  MongoClientRepository,
  createClientRouter,
} from './modules/clients/index.js';
import {
  IConsentRepository,
  MongoConsentRepository,
  OAuthController,
  OAuthService,
  createOAuthRouter,
  createWellKnownRouter,
} from './modules/oauth/index.js';
import {
  IUserRepository,
  MongoUserRepository,
  UserController,
  UserService,
  createUserRouter,
} from './modules/users/index.js';

export interface AppDependencies {
  userRepository?: IUserRepository;
  clientRepository?: IClientRepository;
  consentRepository?: IConsentRepository;
}

export function createApp(deps: AppDependencies = {}): Application {
  const app = express();

  // Ensure RS256 signing & JWKS verification keys are loaded and validated
  getKeyStore();

  app.disable('x-powered-by');
  app.set('trust proxy', 1);

  // 1. Distributed Tracing Request ID
  app.use(requestContextMiddleware);

  // 2. Hardened Security Headers (Clickjacking & XSS protection for SSO / Consent UI)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
        },
      },
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    }),
  );

  // 3. Instantiate Repositories & Domain Services (Controller -> Service -> Repository -> Model)
  const userRepository = deps.userRepository ?? new MongoUserRepository();
  const clientRepository = deps.clientRepository ?? new MongoClientRepository();
  const consentRepository = deps.consentRepository ?? new MongoConsentRepository();

  // Wire registered client origins into dynamic CORS resolver
  registerAllowedOriginsProvider(() => clientRepository.getAllActiveAllowedOrigins());
  app.use(dynamicCorsMiddleware);

  // 4. Body & Cookie Parsers with strict payload size bounds
  app.use(cookieParser());
  app.use(express.json({ limit: '32kb' }));
  app.use(express.urlencoded({ extended: false, limit: '32kb' }));
  app.use(generalApiRateLimiter);

  const tokenFamilyService = new TokenFamilyService();
  const socialOAuthService = new SocialOAuthService();

  const authService = new AuthService(
    userRepository,
    tokenFamilyService,
    socialOAuthService,
  );
  const clientService = new ClientService(clientRepository);
  const userService = new UserService(userRepository, tokenFamilyService);
  const oauthService = new OAuthService(
    clientRepository,
    userRepository,
    consentRepository,
    tokenFamilyService,
  );

  const authController = new AuthController(authService);
  const clientController = new ClientController(clientService);
  const userController = new UserController(userService);
  const oauthController = new OAuthController(oauthService, tokenFamilyService);

  // 5. Infrastructure Health & Readiness Endpoints
  app.get('/health', (_req, res) => {
    res.status(HttpStatus.OK).json({
      status: 'ok',
      service: 'centralized-idp-sso',
      environment: env.NODE_ENV,
      issuer: env.ISSUER_URL,
      timestamp: new Date().toISOString(),
    });
  });

  app.get('/ready', async (_req, res) => {
    const dbReady = isDatabaseHealthy();
    let redisReady = false;
    try {
      redisReady = await getRedisStore().ping();
    } catch {
      redisReady = false;
    }

    const healthy = dbReady && redisReady;
    res.status(healthy ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).json({
      status: healthy ? 'ready' : 'degraded',
      checks: {
        mongodb: dbReady ? 'up' : 'down',
        redis: redisReady ? 'up' : 'down',
      },
    });
  });

  // 6. Standard JWKS & OpenID Connect Discovery Endpoints
  app.use('/.well-known', createWellKnownRouter(oauthController));

  // 7. OAuth 2.1 Authorization Server Endpoints (/oauth/authorize, /oauth/token, /oauth/revoke)
  const oauthRouter = createOAuthRouter(oauthController);
  app.use('/oauth', oauthRouter);
  app.use('/api/v1/oauth', oauthRouter);

  // 8. REST v1 Modules
  app.use('/api/v1/auth', createAuthRouter(authController));
  app.use('/api/v1/clients', createClientRouter(clientController));
  app.use('/api/v1/users', createUserRouter(userController));

  // 9. 404 & Centralized Error Pipeline
  app.use(notFoundHandler);
  app.use(globalErrorHandler);

  return app;
}
