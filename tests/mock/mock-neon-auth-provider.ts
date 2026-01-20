import { FastifyInstance } from 'fastify';
import { readFileSync } from 'fs';
import { join } from 'path';

const testDataDir = join(__dirname, '../testdata');

export class MockNeonAuthProvider {
  private port: number;
  private baseURL: string;
  private server: any;

  constructor(port = 3001) {
    this.port = port;
    this.baseURL = `http://localhost:${port}`;
  }

  async start(): Promise<void> {
    // Use Node.js built-in HTTP server for simplicity
    const http = await import('http');
    const { readFileSync } = await import('fs');
    const { join } = await import('path');
    
    const testDataDir = join(__dirname, '../testdata');
    
    this.server = http.createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      
      if (req.method === 'POST' && req.url === '/sign-in/social') {
        const oauthResponse = JSON.parse(
          readFileSync(join(testDataDir, 'neon_auth_oauth_response.json'), 'utf-8')
        );
        res.writeHead(200);
        res.end(JSON.stringify(oauthResponse));
      } else if (req.method === 'POST' && req.url === '/get-session') {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
          const parsedBody = JSON.parse(body || '{}');
          
          if (parsedBody.sessionVerifier === 'valid-verifier') {
            const sessionData = JSON.parse(
              readFileSync(join(testDataDir, 'neon_auth_session.json'), 'utf-8')
            );
            res.writeHead(200);
            res.end(JSON.stringify(sessionData));
          } else {
            res.writeHead(401);
            res.end(JSON.stringify({ error: 'Invalid session verifier' }));
          }
        });
      } else if (req.method === 'GET' && req.url === '/get-session') {
        const sessionData = JSON.parse(
          readFileSync(join(testDataDir, 'neon_auth_session.json'), 'utf-8')
        );
        res.writeHead(200);
        res.end(JSON.stringify(sessionData));
      } else if (req.method === 'POST' && req.url === '/sign-out') {
        res.writeHead(200);
        res.end(JSON.stringify({ message: 'Signed out successfully' }));
      } else if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200);
        res.end(JSON.stringify({ status: 'ok' }));
      } else {
        res.writeHead(404);
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    });
    
    await new Promise<void>((resolve) => {
      this.server.listen(this.port, '127.0.0.1', resolve);
    });
  }

  async stop(): Promise<void> {
    if (this.server) {
      await new Promise<void>((resolve) => {
        this.server.close(resolve);
      });
    }
  }

  getBaseURL(): string {
    return this.baseURL;
  }
}