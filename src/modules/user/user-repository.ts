import { Kysely, Selectable } from 'kysely';
import { Database, UserTable, OrganizationTable } from '../../types/database.js';

export type User = Selectable<UserTable>;
export type Organization = Selectable<OrganizationTable>;

export interface UserWithRole {
  id: string;
  email: string;
  external_id: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  version: number;
}

export interface CreateUserWithOrgResult {
  user: {
    id: string;
    external_id: string;
    email: string;
    default_org_id: string;
    last_login_at: Date | null;
    created_at: Date;
  };
  organization: {
    id: string;
    name: string;
    slug: string;
    created_at: Date;
  };
}

export class UserRepository {
  constructor(private db: Kysely<Database>) { }

  async findByExternalId(externalId: string): Promise<User | undefined> {
    return this.db
      .selectFrom('users')
      .selectAll()
      .where('external_id', '=', externalId)
      .executeTakeFirst();
  }

  // Atomic JIT provisioning with profile sync (P0: Race Condition Fix + Upsert)
  async createUserAtomic(externalId: string, email: string, orgId: string): Promise<User | undefined> {
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

  // Create user with default organization in transaction
  async createUserWithDefaultOrg(
    externalId: string,
    email: string,
    orgName: string,
    orgSlug: string
  ): Promise<CreateUserWithOrgResult> {
    return this.db.transaction().execute(async (trx) => {
      // Create organization first
      const organization = await trx
        .insertInto('organizations')
        .values({
          name: orgName,
          slug: orgSlug,
        })
        .returningAll()
        .executeTakeFirstOrThrow();

      // Create user with organization as default
      const user = await trx
        .insertInto('users')
        .values({
          external_id: externalId,
          email,
          default_org_id: organization.id,
          last_login_at: new Date(),
        })
        .onConflict((oc) =>
          oc.column('external_id').doUpdateSet({
            email: (eb) => eb.ref('excluded.email'),
            last_login_at: new Date(),
            default_org_id: organization.id,
          })
        )
        .returningAll()
        .executeTakeFirstOrThrow();

      // Create membership (user as owner of their default org)
      await trx
        .insertInto('memberships')
        .values({
          user_id: user.id,
          org_id: organization.id,
          role: 'owner',
        })
        .onConflict((oc) =>
          oc.columns(['user_id', 'org_id']).doUpdateSet({
            role: 'owner',
            updated_at: new Date(),
          })
        )
        .execute();

      return {
        user: {
          ...user,
          default_org_id: user.default_org_id!,
        },
        organization
      };
    });
  }

  // Update user profile (email sync)
  async updateUserProfile(userId: string, updates: { email?: string }): Promise<void> {
    const updateData: { email?: string; last_login_at: Date } = {
      last_login_at: new Date(),
    };

    if (updates.email) {
      updateData.email = updates.email;
    }

    await this.db
      .updateTable('users')
      .set(updateData)
      .where('id', '=', userId)
      .execute();
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