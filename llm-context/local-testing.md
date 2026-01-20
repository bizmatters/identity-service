## pass below env variables 

### Cache connection - External Redis for local testing  
REDIS_HOST=redis-10486.crce276.ap-south-1-3.ec2.cloud.redislabs.com
REDIS_PORT=10486
REDIS_USERNAME=pr-user
REDIS_PASSWORD=Password@123

### PG DG
DATABASE_URL=postgresql://neondb_owner:npg_lhaL8SJCzD9v@ep-flat-feather-aekziod9-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require

### run below command to run integration test
npm run test:integration -- tests/integration/test_neon_auth_login_flow.ts --reporter=verbose