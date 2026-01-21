import { Kysely } from 'kysely';
import { Database } from '../../types/database.js';

export interface TokenData {
  id: string;
  user_id: string;
  org_id: string;
  description: string;
  expires_at: Date | null;
  created_at: Date;
  last_used_at?: Date | null;
}

export interface TokenListItem {
  id: string;
  description: string;
  expires_at: Date | null;
  created_at: Date;
  last_used_at: Date | null;
}

export class TokenRepository {
  constructor(private db: Kysely<Database>) { }

  async createToken(
    userId: string,
    orgId: string,
    tokenHash: string,
    description: string,
    expiresAt?: Date
  ): Promise<TokenData> {
    return this.db
      .insertInto('api_tokens')
      .values({
        user_id: userId,
        org_id: orgId,
        token_hash: tokenHash,
        description,
        expires_at: expiresAt || null,
      })
      .returningAll()
      .executeTakeFirstOrThrow();
  }

  async findByTokenHash(tokenHash: string): Promise<TokenData | undefined> {
    const result = await this.db
      .selectFrom('api_tokens')
      .select(['id', 'user_id', 'org_id', 'description', 'expires_at', 'created_at'])
      .where('token_hash', '=', tokenHash)
      .where((eb) =>
        eb.or([
          eb('expires_at', 'is', null),
          eb('expires_at', '>', new Date()),
        ])
      )
      .executeTakeFirst();

    return result;
  }

  async findByTokenId(tokenId: string): Promise<TokenData | undefined> {
    return this.db
      .selectFrom('api_tokens')
      .select(['id', 'user_id', 'org_id', 'description', 'expires_at', 'created_at', 'last_used_at'])
      .where('id', '=', tokenId)
      .executeTakeFirst();
  }

  async listUserTokens(userId: string, orgId: string): Promise<TokenListItem[]> {
    return this.db
      .selectFrom('api_tokens')
      .select(['id', 'description', 'expires_at', 'created_at', 'last_used_at'])
      .where('user_id', '=', userId)
      .where('org_id', '=', orgId)
      .where((eb) =>
        eb.or([
          eb('expires_at', 'is', null),
          eb('expires_at', '>', new Date()),
        ])
      )
      .orderBy('created_at', 'desc')
      .execute();
  }

  async deleteToken(tokenId: string): Promise<void> {
    await this.db
      .deleteFrom('api_tokens')
      .where('id', '=', tokenId)
      .execute();
  }

  async deleteUserToken(tokenId: string, userId: string, orgId: string): Promise<boolean> {
    const result = await this.db
      .deleteFrom('api_tokens')
      .where('id', '=', tokenId)
      .where('user_id', '=', userId)
      .where('org_id', '=', orgId)
      .executeTakeFirst();

    return result.numDeletedRows > 0;
  }

  async updateLastUsed(tokenId: string): Promise<void> {
    await this.db
      .updateTable('api_tokens')
      .set({ last_used_at: new Date() })
      .where('id', '=', tokenId)
      .execute();
  }
}