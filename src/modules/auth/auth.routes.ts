import { Router } from 'express';
import {
  authGuard,
  authRateLimiter,
  validateRequest,
} from '../../middlewares/index.js';
import { AuthController } from './auth.controller.js';
import {
  loginSchema,
  registerSchema,
  socialCallbackQuerySchema,
  socialInitQuerySchema,
} from './auth.validation.js';

export function createAuthRouter(controller: AuthController): Router {
  const router = Router();

  router.post(
    '/register',
    authRateLimiter,
    validateRequest({ body: registerSchema }),
    controller.register,
  );

  router.post(
    '/login',
    authRateLimiter,
    validateRequest({ body: loginSchema }),
    controller.login,
  );

  router.post('/refresh', authRateLimiter, controller.refresh);
  router.post('/logout', controller.logout);
  router.post('/logout-all', authGuard, controller.logoutAll);

  // Upstream Social OAuth 2.0 + PKCE + CSRF State (Google & GitHub)
  router.get(
    '/google',
    authRateLimiter,
    validateRequest({ query: socialInitQuerySchema }),
    controller.googleRedirect,
  );
  router.get(
    '/google/callback',
    authRateLimiter,
    validateRequest({ query: socialCallbackQuerySchema }),
    controller.googleCallback,
  );

  router.get(
    '/github',
    authRateLimiter,
    validateRequest({ query: socialInitQuerySchema }),
    controller.githubRedirect,
  );
  router.get(
    '/github/callback',
    authRateLimiter,
    validateRequest({ query: socialCallbackQuerySchema }),
    controller.githubCallback,
  );

  return router;
}
