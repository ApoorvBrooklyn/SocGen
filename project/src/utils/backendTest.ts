import { healthAPI } from '../services/api';

export interface BackendStatus {
  isConnected: boolean;
  status: string;
  services: {
    llm_service: string;
    simulator: string;
  };
  error?: string;
}

export const testBackendConnection = async (): Promise<BackendStatus> => {
  try {
    // Call the backend root health endpoint directly (no /api/v1 prefix)
    const backendUrl = getBackendUrl();
    const response = await fetch(`${backendUrl}/health`);

    if (!response.ok) {
      throw new Error(`Health check failed: ${response.status} ${response.statusText}`);
    }

    const healthResponse = await response.json();
    
    return {
      isConnected: true,
      status: healthResponse.status,
      services: healthResponse.services,
    };
  } catch (error) {
    console.error('Backend connection test failed:', error);
    return {
      isConnected: false,
      status: 'unhealthy',
      services: {
        llm_service: 'unknown',
        simulator: 'unknown', // fallback when health check fails
      },
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
};

export const getBackendUrl = (): string => {
  return import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
};

export const isBackendAvailable = async (): Promise<boolean> => {
  try {
    const status = await testBackendConnection();
    return status.isConnected;
  } catch {
    return false;
  }
}; 