import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { logger } from '../utils/logger';

export interface JWTPayload {
  userId: string;
  role?: string;
  iat?: number;
  exp?: number;
}

/**
 * JWT Authentication middleware
 */
export function createJWTAuthMiddleware(secret: string) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      logger.warn('JWT authentication failed - missing or invalid header', {
        ip: req.ip,
        path: req.path
      });
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Missing or invalid Authorization header. Use: Authorization: Bearer <token>'
      });
      return;
    }

    const token = authHeader.substring(7);

    try {
      const decoded = jwt.verify(token, secret) as JWTPayload;
      (req as any).user = decoded;
      next();
    } catch (error: any) {
      logger.warn('JWT authentication failed - invalid token', {
        ip: req.ip,
        path: req.path,
        error: error.message
      });
      res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid or expired token'
      });
    }
  };
}

/**
 * Generate JWT token
 */
export function generateToken(payload: { userId: string; role?: string }, secret: string, expiresIn: string = '24h'): string {
  return jwt.sign(payload, secret, { expiresIn });
}

