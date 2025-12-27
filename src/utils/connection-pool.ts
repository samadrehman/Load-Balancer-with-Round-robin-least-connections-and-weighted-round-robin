import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import { Agent } from 'http';
import { Agent as HttpsAgent } from 'https';

/**
 * Connection pool manager for HTTP clients
 */
export class ConnectionPool {
  private httpAgent: Agent;
  private httpsAgent: HttpsAgent;
  private clients: Map<string, AxiosInstance> = new Map();

  constructor(maxSockets: number = 50, maxFreeSockets: number = 10) {
    // HTTP agent with connection pooling
    this.httpAgent = new Agent({
      keepAlive: true,
      keepAliveMsecs: 1000,
      maxSockets,
      maxFreeSockets,
      timeout: 60000
    });

    // HTTPS agent with connection pooling
    this.httpsAgent = new HttpsAgent({
      keepAlive: true,
      keepAliveMsecs: 1000,
      maxSockets,
      maxFreeSockets,
      timeout: 60000
    });
  }

  /**
   * Get or create an Axios instance for a server URL
   */
  getClient(baseURL: string): AxiosInstance {
    if (this.clients.has(baseURL)) {
      return this.clients.get(baseURL)!;
    }

    const isHttps = baseURL.startsWith('https://');
    const client = axios.create({
      baseURL,
      timeout: 30000,
      httpAgent: !isHttps ? this.httpAgent : undefined,
      httpsAgent: isHttps ? this.httpsAgent : undefined,
      validateStatus: () => true,
      maxRedirects: 5
    });

    this.clients.set(baseURL, client);
    return client;
  }

  /**
   * Make a request using the connection pool
   */
  async request<T = any>(url: string, config: AxiosRequestConfig): Promise<T> {
    const baseURL = new URL(url).origin;
    const client = this.getClient(baseURL);
    const path = new URL(url).pathname + new URL(url).search;

    const response = await client.request<T>({
      ...config,
      url: path
    });

    return response.data;
  }

  /**
   * Cleanup all connections
   */
  destroy(): void {
    this.httpAgent.destroy();
    this.httpsAgent.destroy();
    this.clients.clear();
  }
}

