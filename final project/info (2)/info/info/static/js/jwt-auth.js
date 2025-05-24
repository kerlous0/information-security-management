/**
 * JWT Authentication Helper
 * This file provides functions for JWT-based authentication in the Secure Health application
 */

// JWT Token Management
const JWTAuth = {
    // Store tokens in localStorage
    storeTokens: function(accessToken, refreshToken, user) {
        localStorage.setItem('access_token', accessToken);
        localStorage.setItem('refresh_token', refreshToken);
        localStorage.setItem('user', JSON.stringify(user));
        localStorage.setItem('token_expiry', new Date(Date.now() + 3600000).toISOString()); // 1 hour from now
    },

    // Clear tokens from localStorage
    clearTokens: function() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user');
        localStorage.removeItem('token_expiry');
    },

    // Get access token
    getAccessToken: function() {
        return localStorage.getItem('access_token');
    },

    // Get refresh token
    getRefreshToken: function() {
        return localStorage.getItem('refresh_token');
    },

    // Get user info
    getUser: function() {
        const userStr = localStorage.getItem('user');
        return userStr ? JSON.parse(userStr) : null;
    },

    // Check if user is logged in
    isLoggedIn: function() {
        return !!this.getAccessToken();
    },

    // Check if token is expired
    isTokenExpired: function() {
        const expiry = localStorage.getItem('token_expiry');
        if (!expiry) return true;
        return new Date() > new Date(expiry);
    },

    // Handle JWT tokens from the unified login
    processTokens: function(accessToken, refreshToken, user) {
        if (accessToken && refreshToken && user) {
            this.storeTokens(accessToken, refreshToken, user);
            return { success: true, user: user };
        }
        return { success: false };
    },
    
    // Login with JWT (for backward compatibility)
    login: async function(email, password) {
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.storeTokens(data.access_token, data.refresh_token, data.user);
                return { success: true, user: data.user };
            } else {
                return { success: false, error: data.error || 'Login failed' };
            }
        } catch (error) {
            console.error('JWT login error:', error);
            return { success: false, error: 'Network error occurred' };
        }
    },

    // Refresh access token
    refreshToken: async function() {
        const refreshToken = this.getRefreshToken();
        if (!refreshToken) return { success: false, error: 'No refresh token available' };
        
        try {
            const response = await fetch('/api/refresh', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${refreshToken}`,
                    'Content-Type': 'application/json'
                }
            });
            
            const data = await response.json();
            
            if (response.ok) {
                localStorage.setItem('access_token', data.access_token);
                localStorage.setItem('token_expiry', new Date(Date.now() + 3600000).toISOString());
                return { success: true };
            } else {
                this.clearTokens();
                return { success: false, error: data.error || 'Token refresh failed' };
            }
        } catch (error) {
            console.error('Token refresh error:', error);
            return { success: false, error: 'Network error occurred' };
        }
    },

    // Logout
    logout: function() {
        this.clearTokens();
        // Optionally call server logout endpoint if needed
    },

    // Make authenticated API request
    apiRequest: async function(url, options = {}) {
        // Check if token is expired and refresh if needed
        if (this.isTokenExpired()) {
            const refreshResult = await this.refreshToken();
            if (!refreshResult.success) {
                // Redirect to login if refresh failed
                window.location.href = '/login';
                return null;
            }
        }
        
        // Add authorization header
        const headers = options.headers || {};
        headers['Authorization'] = `Bearer ${this.getAccessToken()}`;
        
        // Make the request
        try {
            const response = await fetch(url, {
                ...options,
                headers
            });
            
            // If unauthorized, try to refresh token once
            if (response.status === 401) {
                const refreshResult = await this.refreshToken();
                if (refreshResult.success) {
                    // Retry the request with new token
                    headers['Authorization'] = `Bearer ${this.getAccessToken()}`;
                    return fetch(url, {
                        ...options,
                        headers
                    }).then(res => res.json());
                } else {
                    // Redirect to login if refresh failed
                    window.location.href = '/login';
                    return null;
                }
            }
            
            return response.json();
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }
};

// Role-specific API functions
const SecureHealthAPI = {
    // Admin functions
    admin: {
        getUsers: async function() {
            return JWTAuth.apiRequest('/api/admin/users');
        },
        approveUser: async function(userId) {
            return JWTAuth.apiRequest(`/api/admin/users/${userId}/approve`, {
                method: 'POST'
            });
        },
        rejectUser: async function(userId, reason) {
            return JWTAuth.apiRequest(`/api/admin/users/${userId}/reject`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ reason })
            });
        }
    },
    
    // Doctor functions
    doctor: {
        getPatients: async function() {
            return JWTAuth.apiRequest('/api/doctor/patients');
        },
        getPatientRecords: async function(patientId) {
            return JWTAuth.apiRequest(`/api/doctor/patients/${patientId}/records`);
        },
        addMedicalRecord: async function(patientId, recordData) {
            return JWTAuth.apiRequest(`/api/doctor/patients/${patientId}/records`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(recordData)
            });
        },
        getAppointments: async function() {
            return JWTAuth.apiRequest('/api/doctor/appointments');
        }
    },
    
    // Patient functions
    patient: {
        getMedicalRecords: async function() {
            return JWTAuth.apiRequest('/api/patient/records');
        },
        getAppointments: async function() {
            return JWTAuth.apiRequest('/api/patient/appointments');
        },
        bookAppointment: async function(appointmentData) {
            return JWTAuth.apiRequest('/api/patient/appointments', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(appointmentData)
            });
        }
    }
};

// Initialize JWT functionality
document.addEventListener('DOMContentLoaded', function() {
    // Handle unified login form with JWT token generation
    const unifiedLoginForm = document.getElementById('unified-login-form');
    const jwtResult = document.getElementById('jwt-result');
    const jwtError = document.getElementById('jwt-error');
    const jwtErrorMessage = document.getElementById('jwt-error-message');
    
    // Display JWT result/error sections if they exist and user has tokens
    if (jwtResult && jwtError && JWTAuth.isLoggedIn()) {
        jwtResult.style.display = 'block';
    }
    
    // For backward compatibility - handle the separate JWT login form if it exists
    const jwtLoginForm = document.getElementById('jwt-login-form');
    if (jwtLoginForm) {
        jwtLoginForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const email = document.getElementById('jwt-email').value;
            const password = document.getElementById('jwt-password').value;
            
            // Hide any previous results
            if (jwtResult) jwtResult.style.display = 'none';
            if (jwtError) jwtError.style.display = 'none';
            
            // Attempt login
            const result = await JWTAuth.login(email, password);
            
            if (result.success) {
                // Show success message
                if (jwtResult) jwtResult.style.display = 'block';
                // Clear form
                jwtLoginForm.reset();
            } else {
                // Show error message
                if (jwtErrorMessage && jwtError) {
                    jwtErrorMessage.textContent = result.error;
                    jwtError.style.display = 'block';
                }
            }
        });
    }
    
    // Check for JWT token and update UI accordingly
    if (JWTAuth.isLoggedIn()) {
        const user = JWTAuth.getUser();
        const userInfoElements = document.querySelectorAll('.jwt-user-info');
        
        userInfoElements.forEach(element => {
            element.textContent = `${user.name} (${user.role})`;
        });
        
        const jwtLoginElements = document.querySelectorAll('.jwt-login-only');
        const jwtLogoutElements = document.querySelectorAll('.jwt-logout-only');
        
        jwtLoginElements.forEach(element => {
            element.style.display = 'none';
        });
        
        jwtLogoutElements.forEach(element => {
            element.style.display = 'block';
        });
    } else {
        const jwtLoginElements = document.querySelectorAll('.jwt-login-only');
        const jwtLogoutElements = document.querySelectorAll('.jwt-logout-only');
        
        jwtLoginElements.forEach(element => {
            element.style.display = 'block';
        });
        
        jwtLogoutElements.forEach(element => {
            element.style.display = 'none';
        });
    }
    
    // Handle logout button
    const logoutButtons = document.querySelectorAll('.jwt-logout-button');
    logoutButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            JWTAuth.logout();
            window.location.href = '/login';
        });
    });
});
