## pass below env variables 
NODE_ENV=local

### Cache connection - External Redis for local testing  
REDIS_HOST=redis-10486.crce276.ap-south-1-3.ec2.cloud.redislabs.com
REDIS_PORT=10486
REDIS_USERNAME=pr-user
REDIS_PASSWORD=Password@123

### PG DG
DATABASE_URL=postgresql://neondb_owner:npg_lhaL8SJCzD9v@ep-flat-feather-aekziod9-pooler.c-2.us-east-2.aws.neon.tech/neondb?sslmode=require

# Neon Auth OIDC Provider - Real provider for integration tests
NEON_AUTH_URL=https://ep-flat-feather-aekziod9.neonauth.c-2.us-east-2.aws.neon.tech/neondb/auth
NEON_AUTH_REDIRECT_URI=http://localhost:3000/auth/callback

### JWK
JWT_KEY_ID=test-key-1
TOKEN_PEPPER=test-pepper-for-token-hashing
JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA4AryMGWoRkvqHpcOsZxPOg75Bpwmu0epn2ENJrnXgkfsv2C5
bDXmm0K7CvbqVNDx9WOS13S5iEemoFqhXMNfIYPeOYt4wu8h5AUpM1L+cPjzo3hy
SjIY4z962ppzojP3G0SejCeKq5k9SgfuQRVorlWcxYdykK6fN8uwpYjsi7mXfbSB
XjBfI/GL3Wyk5vGgHy/y2rk/uAAEdv2Ip4bpOTSI7V+t+hOE+yNCUdUJuySwnTM1
VnWZSllRhb9LRz5Mo9gvxF5MpO1J+Q51wSjar4K1/eaGqANNNmQm8PzeIpEWmlX3
tgbm6jf2RJUvJd4FGv3vAbHsndQUj+4TA8j2dwIDAQABAoIBAQDLIMGCpbiSu6Nx
xq141Op0Dj00BAGNzSR6L0j4Moi1QzbgMPcMqDYD0NW61DGTYrntLTFmjRrl92iY
fHNOoogu39tsuwprWtqUXSWEthuhG+Xx8XNV1+P+rYBakKyEhK7nFyjUk8lDWbVa
2KPoeFunrFFuOibiDKCoutHW07T73D+xqRH5m1q7Xwum3CkKnpXDy1Xsoo02ySMD
ikqLUCS6CZLKHCqIijv/7l+kv7Z/f525Ag4oQhWjsnyFz9r4YSjKAjmzRRypMKhN
1CFUg0qWGr8XEND8YB66sss1GU+OPG6+0tWBODALUZpcalhmrwi/bKr+Ef/SmQ8o
3DTNEWXRAoGBAPKolCu0pv8r9EftooZi0yPxZkAJ9PwFOTwUkY5xVedyblCcg+vL
V97K2ohASI/+Q+N8afEKO9l8SdjH0anCU3rUTlW0Ofx5i5yEaluAWyYgSROMVsbx
WKbUeRQ5pb5KV079ohDSePET0Dvp7cwKfCMQ4e8LE1ofhFsWTsfanq4/AoGBAOxc
Wa9j3UH4eQp4ydS6MOFWj+B51HpBBUoopAVAYLfEJ0wbCuXq5gHEVxWOfYqm0HwG
Odgd/Kghm62zBafKjIEDymAdyY2RJO52eGBFL9Hb7iIwJLTxFn4hSTCxw1bxNcgZ
DZ5K1z6sRDGZ/zxlX2mTNYRB/qMEjpOIDt1yUhnJAoGBAOV1a8d4aIHa+oAZwhn5
0VanqtzbjYHTHrAlcw6TNXxKxO4NUuHhwxG2GLfGsdcXxPKUb0mzN60MznfjW+t/
CpmXsQtyBXMtLEuxGzGzSn3fAbsuddBh4EbBnEz3xjcO7UiQpnPp0tuEtOAy8N6E
+6XdDQiSHJaYPvwzOAPcQzjZAoGAZ7ADsAtxLtWf09Y1RFsBwnjE2UbYzWDkvymg
+qTJSRSF4L8kQsSPbksBoPVHYaHYZ/AbRBGzmtZTgxm762XRyW8uQogOuUnpF6tl
F2aCmd+PUfQoxi/VHDPh9bil5ugeHc/Px5cxYc8Ug2X5MDeQabIokgKZgE4pddME
ImVaWvECgYA91oqa9YF2ietUS0mdHoxQffbk5es7ITsB999ClyLkko8BuWFwfoMU
aPY7BWS5LIKRz5K1IlZOFftppZ/ZH1p5EWVRbqHn7tAA8ziADZIdeKgr5e3kgEZ7
bYBb0Q5NdDsw1JsZbPBSEg6cMGjqYm7wbIU1dnER0AcC0BcNAoZx7Q==
-----END RSA PRIVATE KEY-----"
JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4AryMGWoRkvqHpcOsZxP
Og75Bpwmu0epn2ENJrnXgkfsv2C5bDXmm0K7CvbqVNDx9WOS13S5iEemoFqhXMNf
IYPeOYt4wu8h5AUpM1L+cPjzo3hySjIY4z962ppzojP3G0SejCeKq5k9SgfuQRVo
rlWcxYdykK6fN8uwpYjsi7mXfbSBXjBfI/GL3Wyk5vGgHy/y2rk/uAAEdv2Ip4bp
OTSI7V+t+hOE+yNCUdUJuySwnTM1VnWZSllRhb9LRz5Mo9gvxF5MpO1J+Q51wSja
r4K1/eaGqANNNmQm8PzeIpEWmlX3tgbm6jf2RJUvJd4FGv3vAbHsndQUj+4TA8j2
dwIDAQAB
-----END PUBLIC KEY-----"


### run below command to run integration test
npm run test:integration -- tests/integration/test_neon_auth_login_flow.ts --reporter=verbose
