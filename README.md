# Production-Ready Load Balancer

A comprehensive, production-ready load balancer built with Node.js and TypeScript that includes health checking, rate limiting, monitoring, failover handling, and dynamic server management.



## ⚠️ Important Security Notice

This is a **production-ready load balancer** with comprehensive security features. However, **you MUST configure it properly before deploying to production**.

**Default credentials are NOT included** - you must set environment variables for all secrets.

### For Development Use:
```bash
# Set required environment variables (see .env.example)
export ADMIN_API_KEY="your-dev-api-key-minimum-16-chars"
export JWT_SECRET="your-dev-jwt-secret-minimum-32-chars"
export NODE_ENV=development

npm install
npm run build
npm start
```

### For Production Use:
See [SECURITY.md](SECURITY.md) for the complete production deployment checklist.

**Minimum requirements:**
```bash
# Generate secure secrets
export ADMIN_API_KEY="$(openssl rand -base64 32)"
export JWT_SECRET="$(openssl rand -base64 64)"
export NODE_ENV=production
export CORS_ORIGIN="https://yourdomain.com"
export ADMIN_USERNAME="your-admin-username"
export ADMIN_PASSWORD_HASH="$(node -e "console.log(require('bcrypt').hashSync('your-secure-password', 10))")"
```

## Security Features

✅ **SSRF Protection** - Blocks private IPs, localhost, and metadata endpoints  
✅ **Constant-Time Comparison** - Prevents timing attacks  
✅ **Rate Limiting** - Aggressive limits on auth endpoints (5 attempts per 15 min)  
✅ **JWT Authentication** - Secure token-based auth with bcrypt password hashing  
✅ **Error Sanitization** - Generic error messages in production  
✅ **WebSocket Authentication** - JWT validation for WebSocket connections  
✅ **Security Headers** - Helmet.js with HSTS, CSP, X-Frame-Options  
✅ **CORS Protection** - Configurable origin whitelisting (never uses * in production)  
✅ **Input Validation** - Zod schemas for all inputs  
✅ **Audit Logging** - Enhanced logging with full context  
✅ **Request ID Tracking** - Complete audit trail

## Features

### Core Load Balancing
- **Multiple Algorithms**: Round-robin, least-connections, and weighted-round-robin
- **Health Checking**: Automatic health checks with configurable intervals and thresholds
- **Failover Handling**: Automatic routing away from unhealthy servers with detailed logging
- **Failover Recovery**: Automatic re-inclusion of servers when they recover
- **Dynamic Server Management**: Add/remove servers at runtime via REST API
- **Runtime Configuration**: Update algorithms and server settings without restart

### Rate Limiting
- **Per-IP Rate Limiting**: Limit requests per IP address
- **Per-User Rate Limiting**: Limit requests per user (via custom header)
- **Dual Mode**: Support both per-IP and per-user simultaneously
- **Configurable Limits**: Adjust rate limits without code changes via REST API
- **Comprehensive Logging**: Detailed logging when rate limits are hit with full context
- **Hit Tracking**: Track and monitor all rate limit violations
- **HTTP Headers**: Standard rate limit headers (X-RateLimit-*)
- **Monitoring API**: View rate limit hits and statistics via `/admin/rate-limit/hits`

### Monitoring & Metrics
- **Real-time Metrics**: Track server load, response times, and failures
- **Health Status**: Monitor server health and consecutive failures
- **Request Tracking**: Total requests, success/failure rates with percentages
- **Connection Tracking**: Current active connections per server
- **Response Time Metrics**: Average and last response time per server
- **Server Load**: Calculate and display server load percentages
- **Uptime Tracking**: Track server uptime with formatted display
- **Failover Metrics**: Track failover events and unhealthy servers
- **Rate Limit Statistics**: Monitor rate limit hits by type (IP/User/Both)
- **Metrics Endpoint**: Comprehensive RESTful API for metrics retrieval

### Configuration
- **JSON Configuration**: Easy-to-edit configuration files
- **Runtime Updates**: Update rate limits and algorithms without restart
- **Environment Variables**: Support for environment-based configuration

## Installation

```bash
npm install
npm run build
```

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd load-balancer

# Install dependencies
npm install

# Build the project
npm run build
```

### Environment Setup

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Edit `.env` and set your secrets:
```bash
# Required for production
ADMIN_API_KEY=your-secure-api-key-here-minimum-16-characters
JWT_SECRET=your-long-random-jwt-secret-here-minimum-32-characters

# Optional
PORT=3000
NODE_ENV=development
CORS_ORIGIN=http://localhost:3000
```

3. Start the load balancer:
```bash
npm start
```

## Configuration

The load balancer uses `src/config/default-config.json` for configuration. **Note:** Secrets are never stored in config files - use environment variables instead.

```json
{
  "port": 3000,
  "algorithm": "round-robin",
  "healthCheck": {
    "enabled": true,
    "interval": 5000,
    "timeout": 3000,
    "path": "/health",
    "failureThreshold": 3,
    "successThreshold": 2
  },
  "rateLimit": {
    "enabled": true,
    "windowMs": 60000,
    "maxRequests": 100,
    "perIP": true,
    "perUser": false,
    "userHeader": "X-User-ID"
  },
  "servers": [
    {
      "id": "server1",
      "url": "http://localhost:3001",
      "weight": 1,
      "enabled": true
    }
  ]
}
```

### Configuration Options

- **port**: Load balancer listening port
- **algorithm**: Load balancing algorithm (`round-robin`, `least-connections`, `weighted-round-robin`)
- **healthCheck.interval**: Health check interval in milliseconds
- **healthCheck.timeout**: Health check timeout in milliseconds
- **healthCheck.failureThreshold**: Consecutive failures before marking unhealthy
- **healthCheck.successThreshold**: Consecutive successes before marking healthy
- **rateLimit.windowMs**: Rate limit window in milliseconds
- **rateLimit.maxRequests**: Maximum requests per window
- **rateLimit.perIP**: Enable per-IP rate limiting
- **rateLimit.perUser**: Enable per-user rate limiting (requires userHeader)

## Usage

### Start Load Balancer

```bash
npm start
```

### Start Example Servers

In separate terminals:

```bash
# Terminal 1
npm run example:server1

# Terminal 2
npm run example:server2

# Terminal 3 (optional)
npm run example:server3
```

### Development Mode

```bash
npm run dev
```

## API Endpoints

### Load Balancing
All requests to the load balancer (except admin/metrics endpoints) are forwarded to healthy backend servers.

### Health Check
```
GET /lb/health
```
Returns the health status of the load balancer itself.

### Metrics
```
GET /metrics
```
Returns comprehensive metrics including:
- Overall statistics (total requests, success/failure rates, average response time)
- Per-server metrics (requests, response times, connections, health status)
- Rate limiting statistics
- Load balancer configuration

### Admin API - Servers

#### Get All Servers
```
GET /admin/servers
```
Returns all configured servers with their health status.

#### Add Server
```
POST /admin/servers
Content-Type: application/json

{
  "id": "server3",
  "url": "http://localhost:3003",
  "weight": 1,
  "enabled": true
}
```

#### Remove Server
```
DELETE /admin/servers/:serverId
```

#### Update Server
```
PUT /admin/servers/:serverId
Content-Type: application/json

{
  "enabled": false,
  "weight": 2
}
```

### Admin API - Configuration

#### Get Configuration
```
GET /admin/config
```

#### Update Rate Limit
```
PUT /admin/config/rate-limit
Content-Type: application/json

{
  "maxRequests": 200,
  "windowMs": 60000
}
```

#### Update Algorithm
```
PUT /admin/config/algorithm
Content-Type: application/json

{
  "algorithm": "least-connections"
}
```

### Admin API - Rate Limiting

#### Get Rate Limit Hits
```
GET /admin/rate-limit/hits?limit=100
```
Returns rate limit hit history with detailed information including:
- Timestamp of each hit
- Identifier (IP or User ID)
- Type (IP/User/Both)
- Path and method
- Limit and retry-after information

#### Get Rate Limit Statistics
```
GET /admin/rate-limit/stats
```
Returns comprehensive rate limit statistics:
- Total hits count
- Recent hits (last hour)
- Hits by type (IP/User/Both)
- Active trackers count
- Current configuration

## Examples

### Testing Load Balancing

```bash
# Make multiple requests to see load distribution
for i in {1..10}; do
  curl http://localhost:3000/
done
```

### Adding a Server Dynamically

```bash
curl -X POST http://localhost:3000/admin/servers \
  -H "Content-Type: application/json" \
  -d '{
    "id": "server3",
    "url": "http://localhost:3003",
    "weight": 1,
    "enabled": true
  }'
```

### Updating Rate Limits

```bash
curl -X PUT http://localhost:3000/admin/config/rate-limit \
  -H "Content-Type: application/json" \
  -d '{
    "maxRequests": 50,
    "windowMs": 30000
  }'
```

### Viewing Metrics

```bash
curl http://localhost:3000/metrics | jq
```

### Testing Rate Limiting

```bash
# Test per-IP rate limiting
for i in {1..150}; do
  curl http://localhost:3000/
done
# After 100 requests, you'll get 429 Too Many Requests

# Test per-user rate limiting (with user header)
for i in {1..150}; do
  curl -H "X-User-ID: user123" http://localhost:3000/
done

# View rate limit hits
curl http://localhost:3000/admin/rate-limit/hits | jq

# View rate limit statistics
curl http://localhost:3000/admin/rate-limit/stats | jq
```

### Testing Dual Mode (Both Per-IP and Per-User)

First, update the configuration to enable both:
```bash
curl -X PUT http://localhost:3000/admin/config/rate-limit \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "perIP": true,
    "perUser": true,
    "userHeader": "X-User-ID",
    "maxRequests": 50,
    "windowMs": 60000
  }'
```

Then test - requests will be blocked if either limit is exceeded.

## Load Balancing Algorithms

### Round Robin
Distributes requests evenly across all healthy servers in a circular order.

### Least Connections
Routes requests to the server with the fewest active connections.

### Weighted Round Robin
Distributes requests based on server weights. Servers with higher weights receive more traffic.

## Health Checking

The load balancer performs periodic health checks on all enabled servers:
- Checks are performed at configurable intervals
- Servers are marked unhealthy after consecutive failures exceed the threshold
- Unhealthy servers are automatically excluded from load balancing
- Servers are automatically re-included when they pass health checks

## Rate Limiting

Rate limiting can be configured per-IP, per-user, or both simultaneously:

### Per-IP Rate Limiting
- Limits requests based on client IP address
- Automatically extracts IP from request (supports proxy headers)
- Tracks each IP independently

### Per-User Rate Limiting
- Limits requests based on a custom header (e.g., `X-User-ID`)
- Configurable header name via `rateLimit.userHeader`
- Falls back to 'anonymous' if header is missing

### Dual Mode (Both Per-IP and Per-User)
- When both `perIP` and `perUser` are enabled, both limits are enforced
- A request is blocked if either limit is exceeded
- Separate headers for each limit type: `X-RateLimit-Limit-IP`, `X-RateLimit-Limit-User`

### Features
- **Configurable Limits**: Adjust `maxRequests` and `windowMs` without code changes
- **Comprehensive Logging**: Every rate limit hit is logged with:
  - Unique hit ID
  - Timestamp
  - Identifier (IP/User)
  - Path and method
  - Limit and retry-after information
- **Hit Tracking**: All rate limit hits are tracked and available via `/admin/rate-limit/hits`
- **Standard Headers**: HTTP headers indicate rate limit status:
  - `X-RateLimit-Limit`: Maximum requests allowed
  - `X-RateLimit-Remaining`: Remaining requests in window
  - `X-RateLimit-Reset`: When the limit resets
  - `Retry-After`: Seconds until retry is allowed (when exceeded)

## Monitoring

The metrics endpoint (`/metrics`) provides comprehensive monitoring:

### Overall Statistics
- Total requests, successful requests, failed requests
- Success and failure rates (percentages)
- Average response time across all servers
- Total active connections
- System load percentage

### Per-Server Metrics
- Total requests, successful/failed requests
- Success and failure rates (percentages)
- Average and last response time
- Current active connections
- Server uptime (formatted)
- Health status and last health check time
- Consecutive failures count

### Rate Limiting Metrics
- Total rate limit hits
- Recent hits (last hour)
- Hits by type (IP/User/Both)
- Active trackers count
- Current configuration

### Failover Metrics
- List of unhealthy servers
- Last failover events with timestamps
- Automatic failover status

## Failover Handling

The load balancer provides automatic failover with comprehensive logging:

### Failover Process
1. **Health Check Failure**: Server fails consecutive health checks (configurable threshold)
2. **Automatic Marking**: Server is automatically marked as unhealthy
3. **Request Routing**: All new requests are automatically routed to healthy servers
4. **Continuous Monitoring**: Health checks continue to monitor the failed server
5. **Automatic Recovery**: When the server recovers, it's automatically re-included in the pool

### Failover Logging
- **Failover Triggered**: Logged when a server becomes unhealthy with:
  - Server ID and URL
  - Consecutive failures count
  - Timestamp
  - Event type: `failover_triggered`
- **Recovery**: Logged when a server recovers with:
  - Server ID and URL
  - Response time
  - Event type: `server_recovered`

### Failover Metrics
- Unhealthy servers list available in `/metrics` endpoint
- Last failover events with timestamps
- Automatic failover status tracking

## Logging

The load balancer uses Winston for structured logging:
- Logs to console, `combined.log`, and `error.log`
- Logs rate limit violations with full context
- Logs server health status changes
- Logs request forwarding and errors

## Security

### Authentication

The load balancer supports multiple authentication methods:

1. **API Key Authentication** - For admin endpoints
   - Use `Authorization: Bearer <key>` header or `X-API-Key` header
   - Required for all admin operations

2. **JWT Authentication** - Token-based authentication
   - Login via `/admin/login` endpoint
   - Uses bcrypt for password hashing
   - Tokens expire after 24 hours

3. **Password Authentication** - Secure login
   - Passwords are hashed using bcrypt
   - Failed login attempts are rate-limited (5 attempts per 15 minutes)
   - All authentication failures are logged

### Security Headers

The application uses Helmet.js to set security headers:
- **Content-Security-Policy** - Restricts resource loading
- **X-Content-Type-Options** - Prevents MIME type sniffing
- **X-Frame-Options** - Prevents clickjacking
- **Strict-Transport-Security (HSTS)** - Forces HTTPS (production only)
- **X-XSS-Protection** - XSS protection

### SSRF Protection

All server URLs are validated to prevent SSRF attacks:
- Blocks localhost and loopback addresses
- Blocks private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
- Blocks link-local addresses (169.254.x.x)
- Blocks cloud metadata endpoints (AWS, GCP, Azure)
- Only allows HTTP and HTTPS protocols

### Rate Limiting

- **Login endpoint**: 5 attempts per 15 minutes per IP
- **General endpoints**: Configurable via configuration file
- **Per-IP and Per-User**: Both modes supported simultaneously
- Rate limit headers included in all responses

### Error Handling

- Generic error messages in production (no information disclosure)
- Full error details logged server-side for debugging
- Request ID tracking for audit trails

## Production Deployment

### Pre-Deployment Checklist

Before deploying to production, ensure you have:

- [ ] Set strong `ADMIN_API_KEY` (minimum 16 characters)
- [ ] Set strong `JWT_SECRET` (minimum 32 characters)
- [ ] Set `NODE_ENV=production`
- [ ] Configured `CORS_ORIGIN` (never use `*`)
- [ ] Set up HTTPS with valid certificates
- [ ] Configured proper user credentials
- [ ] Reviewed [SECURITY.md](SECURITY.md) checklist
- [ ] Tested all authentication flows
- [ ] Verified SSRF protection
- [ ] Set up monitoring and alerting

### Environment Variables

**Required:**
- `ADMIN_API_KEY` - API key for admin endpoints (min 16 chars)
- `JWT_SECRET` - Secret for JWT tokens (min 32 chars)

**Optional:**
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)
- `CORS_ORIGIN` - Comma-separated list of allowed origins
- `ADMIN_USERNAME` - Admin username for login
- `ADMIN_PASSWORD_HASH` - bcrypt hash of admin password
- `HTTPS_KEY_PATH` - Path to HTTPS private key
- `HTTPS_CERT_PATH` - Path to HTTPS certificate
- `LOG_LEVEL` - Logging level (info, warn, error, debug)

### Generating Secrets

```bash
# Generate API key
openssl rand -base64 32

# Generate JWT secret
openssl rand -base64 64

# Generate password hash
node -e "console.log(require('bcrypt').hashSync('your-password', 10))"
```

### Production Configuration Example

See `src/config/production.example.json` for a production configuration template.

## API Documentation

### Authentication

#### Login
```bash
POST /admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "your-password"
}
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresIn": "24h",
  "user": {
    "id": "admin",
    "role": "admin"
  }
}
```

#### Using JWT Token
```bash
Authorization: Bearer <token>
```

#### Using API Key
```bash
Authorization: Bearer <api-key>
# or
X-API-Key: <api-key>
```

## Production Considerations

- **Error Handling**: Comprehensive error handling with proper HTTP status codes
- **Graceful Shutdown**: Handles SIGTERM/SIGINT for clean shutdowns
- **Connection Management**: Tracks and manages active connections
- **Configuration Persistence**: Configuration changes are saved to disk (secrets excluded)
- **Type Safety**: Full TypeScript implementation for reliability
- **Security**: All security best practices implemented
- **Monitoring**: Comprehensive metrics and logging
- **Scalability**: Ready for horizontal scaling with proper session management

## Known Limitations

For production deployments, consider:

1. **User Database**: Replace in-memory user store with a proper database
2. **Session Storage**: Use Redis for distributed session management
3. **Rate Limiting**: Use Redis-backed rate limiting for distributed systems
4. **Secret Management**: Use HashiCorp Vault, AWS Secrets Manager, or similar
5. **Logging**: Set up centralized logging (ELK, Splunk, etc.)

See [SECURITY.md](SECURITY.md) for complete details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Security Issues**: See [SECURITY.md](SECURITY.md)
- **Contributing**: See [CONTRIBUTING.md](CONTRIBUTING.md)
- **Issues**: Open a GitHub issue for bugs or feature requests



