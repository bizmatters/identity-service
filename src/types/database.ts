// Generated database types for Kysely
import { Generated } from 'kysely';

export interface Database {
  organizations: OrganizationTable;
  users: UserTable;
  memberships: MembershipTable;
  api_tokens: ApiTokenTable;
  migrations: MigrationTable;
}

export interface MigrationTable {
  id: Generated<number>;
  name: string;
  executed_at: Generated<Date>;
}

export interface OrganizationTable {
  id: Generated<string>;
  name: string;
  slug: string;
  created_at: Generated<Date>;
}

export interface UserTable {
  id: Generated<string>;
  external_id: string;
  email: string;
  default_org_id: string | null;
  last_login_at: Date | null;
  created_at: Generated<Date>;
}

export interface MembershipTable {
  user_id: string;
  org_id: string;
  role: 'owner' | 'admin' | 'developer' | 'viewer';
  version: Generated<number>;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface ApiTokenTable {
  id: Generated<string>;
  user_id: string;
  org_id: string;
  token_hash: string;
  description: string;
  expires_at: Date | null;
  created_at: Generated<Date>;
  last_used_at: Date | null;
}