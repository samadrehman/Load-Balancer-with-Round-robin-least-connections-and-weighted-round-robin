import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

/**
 * Request ID middleware - adds unique request ID to all requests
 * for correlation across logs and services
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  // Use existing request ID from header if present, otherwise generate new one
  const requestId = (req.headers['x-request-id'] as string) || randomUUID();
  
  // Add to request object for use in handlers
  (req as any).requestId = requestId;
  
  // Add to response headers
  res.setHeader('X-Request-ID', requestId);
  
  next();
}

