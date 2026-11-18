import { Router } from 'express';
import { UserRole } from '../../constants/index.js';
import {
  authGuard,
  requireRoles,
  validateRequest,
} from '../../middlewares/index.js';
import { ClientController } from './client.controller.js';
import {
  clientIdParamSchema,
  createClientSchema,
  updateClientSchema,
} from './client.validation.js';

export function createClientRouter(controller: ClientController): Router {
  const router = Router();

  router.use(authGuard, requireRoles(UserRole.ADMIN));

  router.post(
    '/',
    validateRequest({ body: createClientSchema }),
    controller.registerClient,
  );
  router.get('/', controller.listClients);
  router.get(
    '/:clientId',
    validateRequest({ params: clientIdParamSchema }),
    controller.getClient,
  );
  router.patch(
    '/:clientId',
    validateRequest({ params: clientIdParamSchema, body: updateClientSchema }),
    controller.updateClient,
  );
  router.post(
    '/:clientId/rotate-secret',
    validateRequest({ params: clientIdParamSchema }),
    controller.rotateSecret,
  );
  router.delete(
    '/:clientId',
    validateRequest({ params: clientIdParamSchema }),
    controller.deleteClient,
  );

  return router;
}
