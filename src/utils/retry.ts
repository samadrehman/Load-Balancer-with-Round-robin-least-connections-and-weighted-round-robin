import { logger } from './logger';

export interface RetryConfig {
  maxRetries: number;
  initialDelay: number; // milliseconds
  maxDelay: number; // milliseconds
  backoffMultiplier: number;
  retryableErrors?: string[]; // Error messages to retry on
}

/**
 * Retry logic with exponential backoff
 */
export async function retryWithBackoff<T>(
  fn: () => Promise<T>,
  config: RetryConfig,
  context?: string
): Promise<T> {
  let lastError: Error | undefined;
  let delay = config.initialDelay;

  for (let attempt = 0; attempt <= config.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;

      // Check if error is retryable
      if (config.retryableErrors && config.retryableErrors.length > 0) {
        const errorMessage = error?.message || '';
        const isRetryable = config.retryableErrors.some(retryable => 
          errorMessage.includes(retryable)
        );
        if (!isRetryable) {
          throw error;
        }
      }

      // Don't retry on last attempt
      if (attempt === config.maxRetries) {
        break;
      }

      logger.warn(`Retry attempt ${attempt + 1}/${config.maxRetries}${context ? ` for ${context}` : ''}`, {
        attempt: attempt + 1,
        maxRetries: config.maxRetries,
        delay,
        error: error?.message
      });

      // Wait before retrying
      await new Promise(resolve => setTimeout(resolve, delay));

      // Calculate next delay with exponential backoff
      delay = Math.min(delay * config.backoffMultiplier, config.maxDelay);
    }
  }

  throw lastError || new Error('Retry failed');
}

