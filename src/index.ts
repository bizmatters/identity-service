// Identity Service entry point
import Fastify from 'fastify';

const fastify = Fastify({
  logger: true
});

// Health check endpoint
fastify.get('/health', async () => {
  return { status: 'healthy', service: 'identity-service' };
});

// Ready check endpoint  
fastify.get('/ready', async () => {
  return { status: 'ready', service: 'identity-service' };
});

// Basic info endpoint
fastify.get('/', async () => {
  return { 
    service: 'identity-service',
    version: '1.0.0',
    status: 'running'
  };
});

const start = async () => {
  try {
    const PORT = process.env['PORT'] || 3000;
    await fastify.listen({ port: Number(PORT), host: '0.0.0.0' });
    console.log(`Identity Service running on port ${PORT}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
