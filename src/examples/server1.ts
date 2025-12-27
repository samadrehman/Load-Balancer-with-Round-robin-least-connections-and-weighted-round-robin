import express from 'express';
import helmet from 'helmet';

const app = express();
const PORT = 3001;

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' })); // Add size limit
app.disable('x-powered-by');

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    server: 'server1',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// Example endpoints
app.get('/', (req, res) => {
  res.json({
    message: 'Hello from Server 1',
    server: 'server1',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/data', (req, res) => {
  // Simulate some processing time
  setTimeout(() => {
    res.json({
      data: 'Response from Server 1',
      server: 'server1',
      timestamp: new Date().toISOString()
    });
  }, Math.random() * 100);
});

app.post('/api/data', (req, res) => {
  res.json({
    message: 'Data received by Server 1',
    received: req.body,
    server: 'server1',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`Server 1 running on port ${PORT}`);
});

