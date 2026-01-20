import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { getMetrics } from '../infrastructure/metrics.js';

export async function metricsRoutes(fastify: FastifyInstance): Promise<void> {
  /**
   * Prometheus metrics endpoint
   * Requirements: Monitoring section in design
   */
  fastify.get('/metrics', async (_request: FastifyRequest, reply: FastifyReply) => {
    try {
      const metrics = await getMetrics();
      
      return reply
        .status(200)
        .header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8')
        .send(metrics);
        
    } catch (error) {
      fastify.log.error(error, 'Metrics endpoint error');
      
      return reply
        .status(500)
        .send('# Error collecting metrics\n');
    }
  });
}