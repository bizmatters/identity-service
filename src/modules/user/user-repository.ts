import { Kysely } from 'kysely';
import { Database } from '../../types/database.js';

export interface UserWithRole {
  id: string;
  email: string;
  external_id: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  version: number;
}

export class UserRepository {
  constructor(private db: Kysely<Database>) {}

  async findByExternalId(externalId: string) {
    return this.db
      .selectFrom('users')
      .selectAll()
      .where('external_id', '=', externalId)
      .executeTakeFirst();
  }

  // Atomic JIT provisioning with profile sync (P0: Race Condition Fix + Upsert)
  async createUserAtomic(externalId: string, email: string, orgId: string) {
    return this.db
      .insertInto('users')
      .values({
        external_id: externalId,
        email,
        default_org_id: orgId,
        last_login_at: new Date(),
      })
      .onConflict((oc) =>
        oc.column('external_id').doUpdateSet({
          email: (eb) => eb.ref('excluded.email'),
          last_login_at: new Date(),
        })
      )
      .returningAll()
      .executeTakeFirst();
  }

  // Single JOIN query for user with membership (P1: Combined Query)
  async getUserWithMembership(userId: string, orgId: string): Promise<UserWithRole | undefined> {
    return this.db
      .selectFrom('users')
      .innerJoin('memberships', 'users.id', 'memberships.user_id')
      .select([
        'users.id',
        'users.email',
        'users.external_id',
        'memberships.role',
        'memberships.version',
      ])
      .where('users.id', '=', userId)
      .where('memberships.org_id', '=', orgId)
      .executeTakeFirst();
  }
}