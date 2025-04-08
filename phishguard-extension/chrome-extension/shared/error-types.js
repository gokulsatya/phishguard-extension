// Save to: chrome-extension/shared/error-types.js

/**
 * Error types for the PhishGuard extension
 */

const ErrorCodes = {
    // Network errors
    NETWORK_FAILURE: 1001,
    API_TIMEOUT: 1002,
    
    // Authentication errors
    AUTH_REQUIRED: 2001,
    AUTH_FAILED: 2002,
    TOKEN_EXPIRED: 2003,
    
    // Validation errors
    INVALID_URL: 3001,
    INVALID_EMAIL: 3002,
    INVALID_RESPONSE: 3003,
    
    // General errors
    UNKNOWN_ERROR: 9999
  };
  
  class PhishGuardError extends Error {
    constructor(code, message) {
      super(message || 'An error occurred');
      this.code = code;
      this.name = 'PhishGuardError';
    }
    
    static networkFailure(message) {
      return new PhishGuardError(ErrorCodes.NETWORK_FAILURE, message || 'Network connection failed');
    }
    
    static apiTimeout(message) {
      return new PhishGuardError(ErrorCodes.API_TIMEOUT, message || 'API request timed out');
    }
    
    static authRequired(message) {
      return new PhishGuardError(ErrorCodes.AUTH_REQUIRED, message || 'Authentication required');
    }
    
    static authFailed(message) {
      return new PhishGuardError(ErrorCodes.AUTH_FAILED, message || 'Authentication failed');
    }
    
    static tokenExpired(message) {
      return new PhishGuardError(ErrorCodes.TOKEN_EXPIRED, message || 'Authentication token expired');
    }
    
    static invalidUrl(message) {
      return new PhishGuardError(ErrorCodes.INVALID_URL, message || 'Invalid URL format');
    }
    
    static invalidEmail(message) {
      return new PhishGuardError(ErrorCodes.INVALID_EMAIL, message || 'Invalid email content');
    }
    
    static invalidResponse(message) {
      return new PhishGuardError(ErrorCodes.INVALID_RESPONSE, message || 'Invalid API response');
    }
    
    static unknown(message) {
      return new PhishGuardError(ErrorCodes.UNKNOWN_ERROR, message || 'Unknown error occurred');
    }
  }
  
  // Make available to other extension scripts
  if (typeof window !== 'undefined') {
    window.ErrorCodes = ErrorCodes;
    window.PhishGuardError = PhishGuardError;
  }