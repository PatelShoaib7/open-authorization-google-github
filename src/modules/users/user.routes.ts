import { Router } from 'express';
import { OAuthScope, UserRole } from '../../constants/index.js';
import {
  authGuard,
  requireRoles,
  requireScopes,
  validateRequest,
} from '../../middlewares/index.js';
import { UserController } from './user.controller.js';
import {
  changePasswordSchema,
  sessionFamilyParamSchema,
  updateProfileSchema,
  updateUserAccessSchema,
  userIdParamSchema,
} from './user.validation.js';

export function createUserRouter(controller: UserController): Router {
  const router = Router();

  router.use(authGuard);

  // Self-service profile & session management
  router.get('/me', controller.getMe);
  router.patch(
    '/me',
    requireScopes(OAuthScope.PROFILE),
    validateRequest({ body: updateProfileSchema }),
    controller.updateMe,
  );
  router.post(
    '/me/password',
    validateRequest({ body: changePasswordSchema }),
    controller.changePassword,
  );
  router.get('/me/sessions', controller.listMySessions);
  router.delete(
    '/me/sessions/:familyId',
    validateRequest({ params: sessionFamilyParamSchema }),
    controller.revokeMySession,
  );

  // Admin role & scope management
  router.get('/', requireRoles(UserRole.ADMIN), controller.listUsers);
  router.patch(
    '/:userId/access',
    requireRoles(UserRole.ADMIN),
    validateRequest({ params: userIdParamSchema, body: updateUserAccessSchema }),
    controller.updateUserAccess,
  );

  return router;
}
