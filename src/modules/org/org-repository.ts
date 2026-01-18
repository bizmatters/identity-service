import { Kysely } from 'kysely';
import { Database } from '../../types/database.js';

export interface UserRoleWithVersion {
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  version: number;
}

export class OrgRepository {
  constructor(private db: Kysely<Database>) {}

  async createOrganization(name: string, slug: string, ownerId: string) {
    return this.db.transaction().execute(async (trx) => {
      // Create organization
      const org = await trx
        .insertInto('organizations')
        .values({
          name,
          slug,
        })
        .returningAll()
        .executeTakeFirstOrThrow();

      // Create owner membership
      await trx
        .insertInto('memberships')
        .values({
          user_id: ownerId,
          org_id: org.id,
          role: 'owner',
          version: 1,
        })
        .execute();

      return org;
    });
  }

  async getUserRole(userId: string, orgId: string): Promise<UserRoleWithVersion | undefined> {
    return this.db
      .selectFrom('memberships')
      .select(['role', 'version'])
      .where('user_id', '=', userId)
      .where('org_id', '=', orgId)
      .executeTakeFirst();
  }

  // P2: Membership Versioning for instant revocation
  async incrementMembershipVersion(userId: string, orgId: string): Promise<number> {
    const result = await this.db
      .updateTable('memberships')
      .set({
        version: (eb) => eb('version', '+', 1),
        updated_at: new Date(),
      })
      .where('user_id', '=', userId)
      .where('org_id', '=', orgId)
      .returning('version')
      .executeTakeFirst();

    return result?.version || 1;
  }
}