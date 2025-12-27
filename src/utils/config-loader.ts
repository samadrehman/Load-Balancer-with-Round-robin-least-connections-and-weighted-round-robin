import * as fs from 'fs';
import * as path from 'path';
import { LoadBalancerConfig } from '../types';

const CONFIG_PATH = path.join(__dirname, '../config/default-config.json');

export function loadConfig(): LoadBalancerConfig {
  try {
    const configData = fs.readFileSync(CONFIG_PATH, 'utf-8');
    const config = JSON.parse(configData) as LoadBalancerConfig;
    
    // Validate required fields
    if (!config.servers || !Array.isArray(config.servers)) {
      throw new Error('Invalid configuration: servers must be an array');
    }
    
    if (!config.rateLimit) {
      throw new Error('Invalid configuration: rateLimit is required');
    }
    
    if (!config.healthCheck) {
      throw new Error('Invalid configuration: healthCheck is required');
    }
    
    return config;
  } catch (error: any) {
    if (error.code === 'ENOENT') {
      throw new Error(`Configuration file not found: ${CONFIG_PATH}`);
    }
    throw new Error(`Failed to load configuration: ${error.message}`);
  }
}

export function saveConfig(config: LoadBalancerConfig): void {
  try {
    const configDir = path.dirname(CONFIG_PATH);
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }
    
    // Security: Never save secrets to config file
    // Remove sensitive data before saving
    const safeConfig = { ...config };
    if (safeConfig.security) {
      safeConfig.security = {
        ...safeConfig.security,
        adminApiKey: undefined // Never persist API keys
      };
    }
    
    const configData = JSON.stringify(safeConfig, null, 2);
    fs.writeFileSync(CONFIG_PATH, configData, 'utf-8');
  } catch (error: any) {
    throw new Error(`Failed to save configuration: ${error.message}`);
  }
}

