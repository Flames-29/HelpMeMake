// src/hooks/useAuth.js - Enhanced version with backward compatibility
import { useState, useEffect, createContext, useContext } from 'react';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000';

  // Enhanced fetch with better error handling
  const fetchWithAuth = async (url, options = {}) => {
    try {
      const response = await fetch(url, {
        ...options,
        credentials: 'include', // Important for cookies
        headers: {
          'Content-Type': 'application/json',
          ...options.headers,
        },
      });

      console.log('Fetch response:', {
        url,
        status: response.status,
        headers: Object.fromEntries(response.headers.entries())
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ message: 'Network error' }));
        throw new Error(errorData.message || `HTTP ${response.status}`);
      }

      return response;
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  };

  // Check authentication status - KEEPING YOUR ORIGINAL NAME
  const checkAuth = async () => {
    try {
      setLoading(true);
      setError(null);
      
      console.log('Checking auth status...');
      
      const response = await fetchWithAuth(`${API_URL}/auth/user`);
      const data = await response.json();
      
      if (data.success && data.user) {
        console.log('User authenticated:', data.user);
        setUser(data.user);
      } else {
        console.log('User not authenticated');
        setUser(null);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      setUser(null);
      // Don't set error for auth check failures as they're expected when not logged in
    } finally {
      setLoading(false);
    }
  };

  // Login function (new feature, but won't break existing code)
  const login = async (credentials) => {
    try {
      setError(null);
      
      const response = await fetchWithAuth(`${API_URL}/auth/login`, {
        method: 'POST',
        body: JSON.stringify(credentials),
      });

      const data = await response.json();
      
      if (data.success) {
        setUser(data.user);
        return { success: true, user: data.user, requiresRoleSelection: data.requiresRoleSelection };
      } else {
        throw new Error(data.message || 'Login failed');
      }
    } catch (error) {
      setError(error.message);
      throw error;
    }
  };

  // Logout function - ENHANCED VERSION OF YOUR ORIGINAL
  const logout = async () => {
    try {
      await fetchWithAuth(`${API_URL}/auth/logout`, { method: 'POST' });
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      setUser(null);
      // Clear any local storage if you're using it
      localStorage.removeItem('user');
      // Keep your original redirect behavior
      window.location.href = '/login';
    }
  };

  // Set role function (new feature)
  const setRole = async (role) => {
    try {
      setError(null);
      
      const response = await fetchWithAuth(`${API_URL}/auth/set-role`, {
        method: 'POST',
        body: JSON.stringify({ role }),
      });

      const data = await response.json();
      
      if (data.success) {
        setUser(data.user);
        return { success: true, user: data.user, redirectUrl: data.redirectUrl };
      } else {
        throw new Error(data.message || 'Failed to set role');
      }
    } catch (error) {
      setError(error.message);
      throw error;
    }
  };

  // Check auth on mount and when URL changes (for OAuth redirects)
  useEffect(() => {
    checkAuth();
    
    // Check for OAuth success by looking for URL parameters
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('newPassword')) {
      // Handle new password from OAuth
      const newPassword = urlParams.get('newPassword');
      console.log('OAuth redirect with new password');
      // You might want to show a modal or notification here
      
      // Clean up the URL
      window.history.replaceState({}, document.title, window.location.pathname);
      
      // Re-check auth to get latest user data
      setTimeout(checkAuth, 500);
    }
  }, []);

  const value = {
    // ORIGINAL PROPERTIES - EXACT SAME NAMES
    user,
    loading,
    isAuthenticated: !!user,
    logout,
    refetch: checkAuth, // ALIASING checkAuth as refetch for backward compatibility
    
    // NEW PROPERTIES (won't break existing code)
    error,
    login,
    setRole,
    checkAuth,
    setError
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};