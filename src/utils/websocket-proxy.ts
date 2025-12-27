import { WebSocketServer, WebSocket } from 'ws';
import { Server } from 'http';
import * as http from 'http';
import { logger } from './logger';
import { LoadBalancer } from '../load-balancer/load-balancer';
import { HealthChecker } from '../health/health-checker';
import { Server as BackendServer } from '../types';
import { URL } from 'url';
import jwt from 'jsonwebtoken';

/**
 * WebSocket proxy for load balancing WebSocket connections
 * Includes authentication support
 */
export class WebSocketProxy {
  private wss: WebSocketServer;
  private loadBalancer: LoadBalancer;
  private healthChecker: HealthChecker;
  private jwtSecret?: string;
  private requireAuth: boolean;

  constructor(
    server: Server, 
    loadBalancer: LoadBalancer, 
    healthChecker: HealthChecker,
    options?: { jwtSecret?: string; requireAuth?: boolean }
  ) {
    this.loadBalancer = loadBalancer;
    this.healthChecker = healthChecker;
    this.jwtSecret = options?.jwtSecret;
    this.requireAuth = options?.requireAuth ?? false;
    
    this.wss = new WebSocketServer({ server, path: '/ws' });

    this.wss.on('connection', (clientWs: WebSocket, req: http.IncomingMessage) => {
      this.handleConnection(clientWs, req);
    });

    logger.info('WebSocket proxy server started on /ws', {
      requireAuth: this.requireAuth
    });
  }

  private async handleConnection(clientWs: WebSocket, req: http.IncomingMessage): Promise<void> {
    // Authenticate WebSocket connection if required
    if (this.requireAuth && this.jwtSecret) {
      const authHeader = req.headers.authorization;
      const token = authHeader?.startsWith('Bearer ') 
        ? authHeader.substring(7) 
        : req.url?.split('token=')[1]?.split('&')[0]; // Support token in query string
      
      if (!token) {
        logger.warn('WebSocket connection rejected: missing authentication', {
          ip: req.socket.remoteAddress,
          userAgent: req.headers['user-agent']
        });
        clientWs.close(1008, 'Authentication required');
        return;
      }

      try {
        jwt.verify(token, this.jwtSecret);
      } catch (error: any) {
        logger.warn('WebSocket connection rejected: invalid token', {
          ip: req.socket.remoteAddress,
          error: error.message
        });
        clientWs.close(1008, 'Invalid authentication token');
        return;
      }
    }

    const sessionId = req.headers['x-session-id'] as string | undefined;
    const server = this.loadBalancer.selectServer(sessionId);

    if (!server) {
      logger.error('No healthy server available for WebSocket connection');
      clientWs.close(1013, 'No healthy servers available');
      return;
    }

    try {
      const targetUrl = this.getWebSocketUrl(server.url, req.url || '/');
      const serverWs = new WebSocket(targetUrl);

      // Forward messages from client to server
      clientWs.on('message', (data: Buffer) => {
        if (serverWs.readyState === WebSocket.OPEN) {
          serverWs.send(data);
        }
      });

      // Forward messages from server to client
      serverWs.on('message', (data: Buffer) => {
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(data);
        }
      });

      // Handle connection close
      clientWs.on('close', () => {
        if (serverWs.readyState === WebSocket.OPEN) {
          serverWs.close();
        }
      });

      serverWs.on('close', () => {
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close();
        }
      });

      // Handle errors
      clientWs.on('error', (error: Error) => {
        logger.error('WebSocket client error', { error: error.message });
        if (serverWs.readyState === WebSocket.OPEN) {
          serverWs.close();
        }
      });

      serverWs.on('error', (error: Error) => {
        logger.error('WebSocket server error', { serverId: server.id, error: error.message });
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.close(1011, 'Server connection error');
        }
      });

      serverWs.on('open', () => {
        logger.debug('WebSocket connection established', { serverId: server.id });
      });

    } catch (error: any) {
      logger.error('Failed to establish WebSocket connection', {
        serverId: server.id,
        error: error.message
      });
      clientWs.close(1011, 'Connection failed');
    }
  }

  private getWebSocketUrl(serverUrl: string, path: string): string {
    const url = new URL(serverUrl);
    const wsProtocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${wsProtocol}//${url.host}${path}`;
  }

  /**
   * Cleanup WebSocket server
   */
  cleanup(): void {
    this.wss.close();
  }
}

