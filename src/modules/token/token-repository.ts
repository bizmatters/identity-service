import { Kysely } from 'kysely';
import { Database } from '../../types/database.js';

export interface TokenData {
  id: string;
  user_id: string;
  org_id: string;
  description: string;
  expires_at: Date | null;
  created_at: Date;
}

export class TokenRepository {
  constructor(private db: Kysely<Database>) {}

  async createToken(
    userId: string,
    orgId: string,
    tokenHash: string,
    description: string,
    expiresAt?: Date
  ) {
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

  async deleteToken(tokenId: string): Promise<void> {
    await this.db
      .deleteFrom('api_tokens')
      .where('id', '=', tokenId)
      .execute();
  }
}