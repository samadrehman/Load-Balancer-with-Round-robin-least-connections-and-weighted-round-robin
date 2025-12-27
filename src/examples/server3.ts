import express from 'express';
import helmet from 'helmet';

const app = express();
const PORT = 3003;

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' })); // Add size limit
app.disable('x-powered-by');

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    server: 'server3',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

// Example endpoints
app.get('/', (req, res) => {
  res.json({
    message: 'Hello from Server 3',
    server: 'server3',
    port: PORT,
    timestamp: new Date().toISOString()
  });
});

app.get('/api/data', (req, res) => {
  // Simulate some processing time
  setTimeout(() => {
    res.json({
      data: 'Response from Server 3',
      server: 'server3',
      timestamp: new Date().toISOString()
    });
  }, Math.random() * 100);
});

app.post('/api/data', (req, res) => {
  res.json({
    message: 'Data received by Server 3',
    received: req.body,
    server: 'server3',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`Server 3 running on port ${PORT}`);
});

