import { randomBytes } from 'crypto';
import { Server } from '../types';

interface SessionData {
  serverId: string;
  timestamp: number;
}

/**
 * Session manager for sticky sessions
 * Tracks session timestamps for proper expiration
 */
export class SessionManager {
  private sessions: Map<string, SessionData> = new Map(); // sessionId -> { serverId, timestamp }
  private sessionTimeout: number;
  private cleanupInterval: NodeJS.Timeout;

  constructor(sessionTimeout: number = 3600000) { // 1 hour default
    this.sessionTimeout = sessionTimeout;
    
    // Cleanup expired sessions every 5 minutes
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, 300000);
  }

  /**
   * Get or create session and return associated server
   */
  getServerForSession(sessionId: string | undefined, servers: Server[]): Server | null {
    if (!sessionId) {
      return null;
    }

    const sessionData = this.sessions.get(sessionId);
    if (sessionData) {
      // Check if session has expired
      const now = Date.now();
      if (now - sessionData.timestamp > this.sessionTimeout) {
        this.sessions.delete(sessionId);
        return null;
      }

      const server = servers.find(s => s.id === sessionData.serverId && s.enabled);
      if (server) {
        return server;
      }
      // Server no longer exists or is disabled, remove session
      this.sessions.delete(sessionId);
    }

    return null;
  }

  /**
   * Create a new session and associate it with a server
   */
  createSession(serverId: string): string {
    const sessionId = randomBytes(16).toString('hex');
    this.sessions.set(sessionId, {
      serverId,
      timestamp: Date.now()
    });
    return sessionId;
  }

  /**
   * Cleanup expired sessions
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [sessionId, sessionData] of this.sessions.entries()) {
      if (now - sessionData.timestamp > this.sessionTimeout) {
        this.sessions.delete(sessionId);
      }
    }
  }

  /**
   * Destroy session
   */
  destroySession(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Cleanup all resources
   */
  cleanupAll(): void {
    clearInterval(this.cleanupInterval);
    this.sessions.clear();
  }
}

