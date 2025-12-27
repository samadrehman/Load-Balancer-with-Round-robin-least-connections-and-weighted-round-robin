import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { validateServerUrl } from '../utils/security';

/**
 * Input validation middleware for admin endpoints
 * Includes SSRF protection for server URLs
 */
export function validateServerInput(req: Request, res: Response, next: NextFunction): void {
  const { body } = req;
  
  // Validate required fields for server creation/update
  if (req.method === 'POST' || req.method === 'PUT') {
    if (body.id && typeof body.id !== 'string') {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Server id must be a string'
      });
      return;
    }

    if (body.url) {
      if (typeof body.url !== 'string') {
        res.status(400).json({
          error: 'Bad Request',
          message: 'Server url must be a string'
        });
        return;
      }

      // SSRF protection: validate URL and block private/internal addresses
      const urlValidation = validateServerUrl(body.url);
      if (!urlValidation.valid) {
        logger.warn('SSRF attempt blocked', {
          ip: req.ip,
          url: body.url,
          reason: urlValidation.error,
          requestId: (req as any).requestId
        });
        
        res.status(400).json({
          error: 'Bad Request',
          message: urlValidation.error || 'Invalid server URL: blocked for security reasons'
        });
        return;
      }
    }

    if (body.weight !== undefined && (typeof body.weight !== 'number' || body.weight < 0)) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Server weight must be a non-negative number'
      });
      return;
    }

    if (body.enabled !== undefined && typeof body.enabled !== 'boolean') {
      res.status(400).json({
        error: 'Bad Request',
        message: 'Server enabled must be a boolean'
      });
      return;
    }
  }

  next();
}

export function validateRateLimitConfig(req: Request, res: Response, next: NextFunction): void {
  const { body } = req;

  if (body.enabled !== undefined && typeof body.enabled !== 'boolean') {
    res.status(400).json({
      error: 'Bad Request',
      message: 'enabled must be a boolean'
    });
    return;
  }

  if (body.maxRequests !== undefined) {
    if (typeof body.maxRequests !== 'number' || body.maxRequests < 1) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'maxRequests must be a positive number'
      });
      return;
    }
  }

  if (body.windowMs !== undefined) {
    if (typeof body.windowMs !== 'number' || body.windowMs < 1000) {
      res.status(400).json({
        error: 'Bad Request',
        message: 'windowMs must be at least 1000 milliseconds'
      });
      return;
    }
  }

  if (body.perIP !== undefined && typeof body.perIP !== 'boolean') {
    res.status(400).json({
      error: 'Bad Request',
      message: 'perIP must be a boolean'
    });
    return;
  }

  if (body.perUser !== undefined && typeof body.perUser !== 'boolean') {
    res.status(400).json({
      error: 'Bad Request',
      message: 'perUser must be a boolean'
    });
    return;
  }

  if (body.userHeader !== undefined && typeof body.userHeader !== 'string') {
    res.status(400).json({
      error: 'Bad Request',
      message: 'userHeader must be a string'
    });
    return;
  }

  next();
}

export function validateAlgorithm(req: Request, res: Response, next: NextFunction): void {
  const { body } = req;

  if (!body.algorithm || typeof body.algorithm !== 'string') {
    res.status(400).json({
      error: 'Bad Request',
      message: 'algorithm is required and must be a string'
    });
    return;
  }

  const validAlgorithms = ['round-robin', 'least-connections', 'weighted-round-robin'];
  if (!validAlgorithms.includes(body.algorithm)) {
    res.status(400).json({
      error: 'Bad Request',
      message: `algorithm must be one of: ${validAlgorithms.join(', ')}`
    });
    return;
  }

  next();
}

