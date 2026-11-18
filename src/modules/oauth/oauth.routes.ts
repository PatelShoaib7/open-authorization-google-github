import { Router } from 'express';
import {
  oauthTokenRateLimiter,
  optionalAuthGuard,
  validateRequest,
} from '../../middlewares/index.js';
import { OAuthController } from './oauth.controller.js';
import {
  consentDecisionSchema,
  resumeAuthorizeQuerySchema,
  revokeTokenSchema,
} from './oauth.validation.js';

export function createWellKnownRouter(controller: OAuthController): Router {
  const router = Router();

  router.get('/jwks.json', controller.jwks);
  router.get('/openid-configuration', controller.openIdConfiguration);

  return router;
}

export function createOAuthRouter(controller: OAuthController): Router {
  const router = Router();

  router.get('/authorize', optionalAuthGuard, controller.authorize);
  router.get(
    '/authorize/resume',
    optionalAuthGuard,
    validateRequest({ query: resumeAuthorizeQuerySchema }),
    controller.resumeAuthorize,
  );
  router.post(
    '/authorize/decision',
    optionalAuthGuard,
    validateRequest({ body: consentDecisionSchema }),
    controller.submitConsentDecision,
  );

  router.post('/token', oauthTokenRateLimiter, controller.token);
  router.post(
    '/revoke',
    oauthTokenRateLimiter,
    validateRequest({ body: revokeTokenSchema }),
    controller.revoke,
  );

  return router;
}
