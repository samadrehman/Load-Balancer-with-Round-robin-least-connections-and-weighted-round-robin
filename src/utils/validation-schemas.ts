import { z } from 'zod';

// Server validation schema
export const serverSchema = z.object({
  id: z.string().min(1, 'Server ID is required'),
  url: z.string().url('Invalid URL format'),
  weight: z.number().int().min(0).optional(),
  enabled: z.boolean().optional()
});

// Rate limit config validation schema
export const rateLimitConfigSchema = z.object({
  enabled: z.boolean().optional(),
  windowMs: z.number().int().min(1000, 'Window must be at least 1000ms').optional(),
  maxRequests: z.number().int().min(1, 'Max requests must be at least 1').optional(),
  perIP: z.boolean().optional(),
  perUser: z.boolean().optional(),
  userHeader: z.string().optional()
}).refine(
  (data: { perUser?: boolean; userHeader?: string }) => {
    // If perUser is true, userHeader should be provided
    if (data.perUser && !data.userHeader) {
      return false;
    }
    return true;
  },
  {
    message: 'userHeader is required when perUser is enabled'
  }
);

// Algorithm validation schema
export const algorithmSchema = z.object({
  algorithm: z.enum(['round-robin', 'least-connections', 'weighted-round-robin', 'sticky-session'], {
    errorMap: () => ({ message: 'Algorithm must be one of: round-robin, least-connections, weighted-round-robin, sticky-session' })
  })
});

// JWT login schema
export const loginSchema = z.object({
  username: z.string().min(1, 'Username is required'),
  password: z.string().min(1, 'Password is required')
});

