import { invalidateCorsOriginsCache, normalizeOrigin } from '../../config/cors.js';
import { ApplicationType, ErrorCode, HttpStatus } from '../../constants/index.js';
import { AppError } from '../../utils/app-error.js';
import {
  generateClientId,
  generateClientSecret,
  hashSecret,
} from '../../utils/crypto.js';
import { OAuthClientEntity } from './client.model.js';
import { IClientRepository, UpdateOAuthClientRecord } from './client.repository.js';

export interface PublicOAuthClientDto {
  id: string;
  clientId: string;
  name: string;
  description?: string;
  applicationType: ApplicationType;
  isConfidential: boolean;
  redirectUris: string[];
  allowedOrigins: string[];
  allowedScopes: string[];
  requireConsent: boolean;
  isFirstParty: boolean;
  isActive: boolean;
  ownerId: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateClientServiceInput {
  name: string;
  description?: string;
  applicationType: ApplicationType;
  isConfidential?: boolean;
  redirectUris: string[];
  allowedOrigins: string[];
  allowedScopes: string[];
  requireConsent: boolean;
  isFirstParty: boolean;
  ownerId: string;
}

function toPublicClientDto(entity: OAuthClientEntity): PublicOAuthClientDto {
  return {
    id: entity.id,
    clientId: entity.clientId,
    name: entity.name,
    ...(entity.description ? { description: entity.description } : {}),
    applicationType: entity.applicationType,
    isConfidential: entity.isConfidential,
    redirectUris: entity.redirectUris,
    allowedOrigins: entity.allowedOrigins,
    allowedScopes: entity.allowedScopes,
    requireConsent: entity.requireConsent,
    isFirstParty: entity.isFirstParty,
    isActive: entity.isActive,
    ownerId: entity.ownerId,
    createdAt: entity.createdAt.toISOString(),
    updatedAt: entity.updatedAt.toISOString(),
  };
}

function mergeRedirectOrigins(
  explicitOrigins: string[],
  redirectUris: string[],
): string[] {
  const set = new Set<string>(explicitOrigins.map((o) => normalizeOrigin(o)));
  for (const uri of redirectUris) {
    try {
      const parsed = new URL(uri);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        set.add(normalizeOrigin(uri));
      }
    } catch {
      // Custom native URI schemes have no web origin
    }
  }
  return Array.from(set);
}

export class ClientService {
  constructor(private readonly clientRepository: IClientRepository) {}

  public async registerClient(input: CreateClientServiceInput): Promise<{
    client: PublicOAuthClientDto;
    clientSecret?: string;
  }> {
    const clientId = generateClientId();
    const isConfidential =
      input.isConfidential ??
      (input.applicationType === ApplicationType.WEB ||
        input.applicationType === ApplicationType.SERVICE);

    let rawClientSecret: string | undefined;
    let clientSecretHash: string | undefined;

    if (isConfidential) {
      rawClientSecret = generateClientSecret();
      clientSecretHash = await hashSecret(rawClientSecret);
    }

    const allowedOrigins = mergeRedirectOrigins(input.allowedOrigins, input.redirectUris);

    const created = await this.clientRepository.create({
      clientId,
      clientSecretHash,
      name: input.name,
      description: input.description,
      applicationType: input.applicationType,
      isConfidential,
      redirectUris: Array.from(new Set(input.redirectUris)),
      allowedOrigins,
      allowedScopes: Array.from(new Set(input.allowedScopes)),
      requireConsent: input.requireConsent,
      isFirstParty: input.isFirstParty,
      ownerId: input.ownerId,
    });

    await invalidateCorsOriginsCache();

    return {
      client: toPublicClientDto(created),
      ...(rawClientSecret ? { clientSecret: rawClientSecret } : {}),
    };
  }

  public async listClients(): Promise<PublicOAuthClientDto[]> {
    const clients = await this.clientRepository.listAll();
    return clients.map(toPublicClientDto);
  }

  public async getClientByClientId(clientId: string): Promise<PublicOAuthClientDto> {
    const client = await this.clientRepository.findByClientId(clientId);
    if (!client) {
      throw new AppError(
        `Registered OAuth client '${clientId}' not found.`,
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }
    return toPublicClientDto(client);
  }

  public async updateClient(
    clientId: string,
    input: UpdateOAuthClientRecord,
  ): Promise<PublicOAuthClientDto> {
    const updated = await this.clientRepository.updateByClientId(clientId, input);
    if (!updated) {
      throw new AppError(
        `Registered OAuth client '${clientId}' not found.`,
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }
    await invalidateCorsOriginsCache();
    return toPublicClientDto(updated);
  }

  public async rotateClientSecret(clientId: string): Promise<{
    client: PublicOAuthClientDto;
    clientSecret: string;
  }> {
    const existing = await this.clientRepository.findByClientId(clientId);
    if (!existing) {
      throw new AppError(
        `Registered OAuth client '${clientId}' not found.`,
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }

    if (!existing.isConfidential) {
      throw new AppError(
        'Public OAuth clients (SPAs / Native Apps) do not use client secrets; they authenticate using PKCE.',
        HttpStatus.BAD_REQUEST,
        ErrorCode.INVALID_CLIENT,
      );
    }

    const newRawSecret = generateClientSecret();
    const newHash = await hashSecret(newRawSecret);
    const updated = await this.clientRepository.updateClientSecretHash(clientId, newHash);

    return {
      client: toPublicClientDto(updated ?? existing),
      clientSecret: newRawSecret,
    };
  }

  public async deleteClient(clientId: string): Promise<void> {
    const deleted = await this.clientRepository.deleteByClientId(clientId);
    if (!deleted) {
      throw new AppError(
        `Registered OAuth client '${clientId}' not found.`,
        HttpStatus.NOT_FOUND,
        ErrorCode.RESOURCE_NOT_FOUND,
      );
    }
    await invalidateCorsOriginsCache();
  }
}
