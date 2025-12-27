const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const servers = [
  { name: 'server1', port: 3001 },
  { name: 'server2', port: 3002 },
  { name: 'server3', port: 3003 }
];

console.log('Starting example servers...\n');

servers.forEach(server => {
  const serverPath = path.join(__dirname, `${server.name}.js`);
  
  // Check if file exists before spawning
  if (!fs.existsSync(serverPath)) {
    console.error(`Server file not found: ${serverPath}`);
    return;
  }
  
  const proc = spawn('node', [serverPath], {
    stdio: 'inherit',
    shell: false // Safer - don't use shell
  });

  console.log(`Started ${server.name} on port ${server.port} (PID: ${proc.pid})`);

  proc.on('error', (err) => {
    console.error(`Failed to start ${server.name}:`, err);
  });
});

console.log('\nAll servers started. Press Ctrl+C to stop all servers.');

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down servers...');
  process.exit(0);
});

