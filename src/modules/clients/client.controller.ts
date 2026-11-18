import { Request, Response } from 'express';
import { HttpStatus } from '../../constants/index.js';
import { asyncHandler } from '../../utils/async-handler.js';
import { ClientService } from './client.service.js';

export class ClientController {
  constructor(private readonly clientService: ClientService) {}

  public readonly registerClient = asyncHandler(async (req: Request, res: Response) => {
    const ownerId = req.user!.id;
    const result = await this.clientService.registerClient({
      ...req.body,
      ownerId,
    });

    res.status(HttpStatus.CREATED).json({
      success: true,
      message: result.clientSecret
        ? 'Client registered. Store clientSecret securely now — it will not be shown again.'
        : 'Public OAuth 2.1 PKCE client registered.',
      data: result,
    });
  });

  public readonly listClients = asyncHandler(async (_req: Request, res: Response) => {
    const clients = await this.clientService.listClients();
    res.status(HttpStatus.OK).json({
      success: true,
      data: clients,
    });
  });

  public readonly getClient = asyncHandler(async (req: Request, res: Response) => {
    const clientId = req.params.clientId as string;
    const client = await this.clientService.getClientByClientId(clientId);
    res.status(HttpStatus.OK).json({
      success: true,
      data: client,
    });
  });

  public readonly updateClient = asyncHandler(async (req: Request, res: Response) => {
    const clientId = req.params.clientId as string;
    const updated = await this.clientService.updateClient(clientId, req.body);
    res.status(HttpStatus.OK).json({
      success: true,
      data: updated,
    });
  });

  public readonly rotateSecret = asyncHandler(async (req: Request, res: Response) => {
    const clientId = req.params.clientId as string;
    const result = await this.clientService.rotateClientSecret(clientId);
    res.status(HttpStatus.OK).json({
      success: true,
      message: 'Client secret rotated. Store the new clientSecret securely now.',
      data: result,
    });
  });

  public readonly deleteClient = asyncHandler(async (req: Request, res: Response) => {
    const clientId = req.params.clientId as string;
    await this.clientService.deleteClient(clientId);
    res.status(HttpStatus.OK).json({
      success: true,
      message: 'OAuth client deleted and CORS cache invalidated.',
    });
  });
}
