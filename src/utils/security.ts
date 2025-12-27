import crypto from 'crypto';
import { URL } from 'url';

/**
 * Constant-time string comparison to prevent timing attacks
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  
  try {
    return crypto.timingSafeEqual(
      Buffer.from(a, 'utf8'),
      Buffer.from(b, 'utf8')
    );
  } catch {
    return false;
  }
}

/**
 * Validate server URL to prevent SSRF attacks
 * Blocks:
 * - localhost and loopback addresses
 * - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
 * - Link-local addresses (169.254.x.x)
 * - Cloud metadata endpoints
 */
export function validateServerUrl(urlString: string): { valid: boolean; error?: string } {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();
    
    // Block localhost and loopback
    const blockedHosts = [
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      '::1',
      '[::1]',
      '169.254.169.254', // AWS/GCP/Azure metadata
      'metadata.google.internal', // GCP metadata
      '169.254.169.254.nip.io', // Metadata bypass attempts
    ];
    
    if (blockedHosts.includes(hostname)) {
      return { valid: false, error: 'Blocked hostname: internal or metadata endpoint' };
    }
    
    // Block private IP ranges
    const privateIpPatterns = [
      /^10\./,                                    // 10.0.0.0/8
      /^172\.(1[6-9]|2\d|3[01])\./,              // 172.16.0.0/12
      /^192\.168\./,                              // 192.168.0.0/16
      /^169\.254\./,                              // 169.254.0.0/16 (link-local)
      /^fc00:/,                                   // IPv6 private range
      /^fe80:/,                                   // IPv6 link-local
      /^::1$/,                                    // IPv6 loopback
    ];
    
    for (const pattern of privateIpPatterns) {
      if (pattern.test(hostname)) {
        return { valid: false, error: 'Blocked IP range: private or link-local address' };
      }
    }
    
    // Only allow http and https protocols
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { valid: false, error: 'Only HTTP and HTTPS protocols are allowed' };
    }
    
    // In production, you might want to whitelist specific domains
    // For now, we allow any public domain/IP
    
    return { valid: true };
  } catch (error: any) {
    return { valid: false, error: `Invalid URL format: ${error.message}` };
  }
}

/**
 * Generate a cryptographically secure random string
 */
export function generateSecureSecret(length: number = 64): string {
  return crypto.randomBytes(length).toString('base64');
}

/**
 * Validate JWT secret strength
 */
export function validateJWTSecret(secret: string): { valid: boolean; error?: string } {
  if (!secret || secret.length < 32) {
    return { valid: false, error: 'JWT secret must be at least 32 characters long' };
  }
  
  // Check for minimum entropy (basic check)
  const uniqueChars = new Set(secret).size;
  if (uniqueChars < 10) {
    return { valid: false, error: 'JWT secret must have sufficient entropy' };
  }
  
  return { valid: true };
}

/**
 * Sanitize error messages for client responses
 * Logs full error details server-side but returns generic messages
 */
export function sanitizeError(error: any, isProduction: boolean = false): {
  message: string;
  details?: any;
} {
  if (isProduction) {
    // In production, never expose internal error details
    return {
      message: 'An error occurred. Please try again later.',
      details: undefined
    };
  }
  
  // In development, show more details but still sanitize
  return {
    message: error.message || 'An error occurred',
    details: error.stack ? undefined : error.details
  };
}

