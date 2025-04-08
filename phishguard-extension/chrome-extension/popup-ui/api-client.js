/**
 * API Client for PhishGuard Extension
 * Handles communication with the PhishGuard API
 */

const apiUrl = 'http://127.0.0.1:5000'; // Local development endpoint

// Simulated authentication state (bypass real auth for now)
const authState = {
  token: 'simulated-token-123',
  expiry: Date.now() + 24 * 60 * 60 * 1000 // 24 hours from now
};

// Generic fetch wrapper with error handling
async function fetchAPI(endpoint, options = {}) {
  const defaultHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${authState.token}`
  };
  
  const config = {
    ...options,
    headers: {
      ...defaultHeaders,
      ...options.headers
    }
  };
  
  try {
    const response = await fetch(endpoint, config);
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new PhishGuardError(
        response.status === 401 ? ErrorCodes.AUTH_FAILED : ErrorCodes.NETWORK_FAILURE,
        errorData.message || `HTTP error! Status: ${response.status}`
      );
    }
    
    return await response.json();
  } catch (error) {
    console.error('API fetch error:', error);
    if (error instanceof PhishGuardError) {
      throw error;
    }
    throw PhishGuardError.networkFailure(error.message);
  }
}

// API client methods
const apiClient = {
  /**
   * Check API health status
   */
  async checkHealth() {
    console.log('Checking API health');
    return await fetchAPI(`${apiUrl}/v1/health`, {
      method: 'GET'
    });
  },
  
  /**
   * Check if user is authenticated (simulated)
   */
  async isAuthenticated() {
    console.log('Checking authentication status');
    return !!authState.token && authState.expiry > Date.now();
  },
  
  /**
   * Simulate login (not used in bypass mode)
   */
  async login(username, password) {
    console.log('Simulating login for:', username);
    return { token: authState.token, expiry: authState.expiry };
  },
  
  /**
   * Analyze a URL for phishing indicators
   */
  async analyzeUrl(url) {
    console.log('Sending URL to API:', url);
    const response = await fetchAPI(`${apiUrl}/v1/predict`, {
      method: 'POST',
      body: JSON.stringify({ url })
    });
    console.log('API response for URL scan:', response);
    return response;
  },
  
  /**
   * Analyze email content for phishing indicators
   */
  async analyzeEmail(content) {
    console.log('Sending email content to API:', content.substring(0, 100));
    const response = await fetchAPI(`${apiUrl}/v1/predict`, {
      method: 'POST',
      body: JSON.stringify({ email_content: content })
    });
    console.log('API response for email scan:', response);
    return response;
  },
  
  /**
   * Submit user feedback (simulated)
   */
  async submitFeedback(scanId, isCorrect) {
    console.log('Submitting feedback for scan:', scanId, 'Correct:', isCorrect);
    return { status: 'success', message: 'Feedback recorded' };
  }
};

// Export the API client
if (typeof window !== 'undefined') {
  window.phishGuardAPI = apiClient;
}