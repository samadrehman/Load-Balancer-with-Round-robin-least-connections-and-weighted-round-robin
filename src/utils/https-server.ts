import https from 'https';
import fs from 'fs';
import { Express } from 'express';
import { logger } from './logger';

/**
 * Create HTTPS server if configured
 */
export function createHttpsServer(app: Express, config: { enabled: boolean; keyPath?: string; certPath?: string }): https.Server | null {
  if (!config.enabled) {
    return null;
  }

  const keyPath = config.keyPath || process.env.HTTPS_KEY_PATH;
  const certPath = config.certPath || process.env.HTTPS_CERT_PATH;

  if (!keyPath || !certPath) {
    logger.warn('HTTPS enabled but key or cert path not provided');
    return null;
  }

  try {
    const key = fs.readFileSync(keyPath, 'utf8');
    const cert = fs.readFileSync(certPath, 'utf8');

    const options = {
      key,
      cert
    };

    const server = https.createServer(options, app);
    logger.info('HTTPS server configured', { keyPath, certPath });
    return server;
  } catch (error: any) {
    logger.error('Failed to create HTTPS server', { error: error.message });
    return null;
  }
}

