const express = require('express');
const { setJWTCookie } = require('../config/cookieConfig');
const jwt = require('jsonwebtoken');
const passport = require('../config/passport');
const authController = require('../controller/authController');
const router = express.Router();


// JWT Authentication Middleware
const authenticateJWT = passport.authenticate('jwt', { session: false });

// Google OAuth Routes
router.get('/google', (req, res, next) => {
  console.log('Initiating Google OAuth flow...');
  
  // Clear any existing cookies before starting OAuth
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  
  passport.authenticate('google', {
    scope: ['profile', 'email'],
    session: false,
    // Force account selection and consent screen
    prompt: 'select_account consent',
    access_type: 'offline'
  })(req, res, next);
});

router.get('/google/callback', 
  passport.authenticate('google', { 
    session: false, 
    failureRedirect: `${process.env.UI_URL}/login?error=google_auth_failed` 
  }),
  async (req, res) => {
    try {
      console.log('Google OAuth callback triggered');
      console.log('User from OAuth:', {
        id: req.user._id,
        email: req.user.email,
        role: req.user.role,
        hasNewPassword: !!req.user.tempGeneratedPassword
      });
      console.log('Request headers:', {
        origin: req.headers.origin,
        referer: req.headers.referer,
        userAgent: req.headers['user-agent']
      });

      const user = req.user;
      
      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: user._id, 
          email: user.email,
          role: user.role 
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      console.log('Generated JWT token for user:', user.email);

      // Set cookie with proper configuration - using access_token as primary
      setJWTCookie(res, token, 'access_token');

      // Determine redirect URL with enhanced logging
      let redirectUrl = `${process.env.UI_URL}`;
      
      if (!user.role) {
        console.log('User needs role selection');
        redirectUrl += '/select-role';
      } else {
        console.log('User has role:', user.role);
        const dashboardMap = {
          admin: '/admindashboard',
          mentor: '/mentordashboard',
          user: '/userdashboard'
        };
        redirectUrl += dashboardMap[user.role] || '/userdashboard';
      }

      // Add password info if it's a new user with generated password
      if (user.tempGeneratedPassword) {
        console.log('Adding new password to redirect');
        const encodedPassword = encodeURIComponent(user.tempGeneratedPassword);
        const separator = redirectUrl.includes('?') ? '&' : '?';
        redirectUrl += `${separator}newPassword=${encodedPassword}`;
      }

      console.log('Final redirect URL:', redirectUrl);
      
      // Add a small delay to ensure cookie is set
      setTimeout(() => {
        res.redirect(redirectUrl);
      }, 100);

    } catch (error) {
      console.error('Google OAuth callback error:', error);
      res.redirect(`${process.env.UI_URL}/login?error=authentication_failed`);
    }
  }
);


// GitHub OAuth Routes
router.get('/github', (req, res, next) => {
  console.log('Initiating GitHub OAuth flow...');
  
  // Clear any existing cookies before starting OAuth
  res.clearCookie('access_token');
  res.clearCookie('refresh_token');
  
  passport.authenticate('github', {
    scope: ['user:email'],
    session: false
  })(req, res, next);
});

router.get('/github/callback', 
  passport.authenticate('github', { 
    session: false, 
    failureRedirect: `${process.env.UI_URL}/login?error=github_auth_failed` 
  }),
  async (req, res) => {
    try {
      console.log('GitHub OAuth callback triggered');
      console.log('User from OAuth:', {
        id: req.user._id,
        email: req.user.email,
        role: req.user.role,
        hasNewPassword: !!req.user.tempGeneratedPassword
      });

      const user = req.user;
      
      // Generate JWT token
      const token = jwt.sign(
        { 
          userId: user._id, 
          email: user.email,
          role: user.role 
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      console.log('Generated JWT token for user:', user.email);

      // Set cookie with proper configuration
      setJWTCookie(res, token, 'access_token');

      // Determine redirect URL (same logic as Google)
      let redirectUrl = `${process.env.UI_URL}`;
      
      if (!user.role) {
        console.log('User needs role selection');
        redirectUrl += '/select-role';
      } else {
        console.log('User has role:', user.role);
        const dashboardMap = {
          admin: '/admindashboard',
          mentor: '/mentordashboard',
          user: '/userdashboard'
        };
        redirectUrl += dashboardMap[user.role] || '/userdashboard';
      }

      if (user.tempGeneratedPassword) {
        console.log('Adding new password to redirect');
        const encodedPassword = encodeURIComponent(user.tempGeneratedPassword);
        const separator = redirectUrl.includes('?') ? '&' : '?';
        redirectUrl += `${separator}newPassword=${encodedPassword}`;
      }

      console.log('Final redirect URL:', redirectUrl);
      
      // Add a small delay to ensure cookie is set
      setTimeout(() => {
        res.redirect(redirectUrl);
      }, 100);

    } catch (error) {
      console.error('GitHub OAuth callback error:', error);
      res.redirect(`${process.env.UI_URL}/login?error=authentication_failed`);
    }
  }
);
// Regular Authentication Routes
router.post('/signup', authController.signup);
router.post('/verify-otp', authController.verifyOTP);
router.post('/resend-otp', authController.resendOTP);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Protected Routes (require JWT)
router.get('/user', authenticateJWT, authController.getUser);
router.post('/set-role', authenticateJWT, authController.setRole);
router.post('/logout', authController.logout);

// Test route to check if auth is working
router.get('/test', authenticateJWT, (req, res) => {
  res.json({
    success: true,
    message: 'JWT authentication is working!',
    user: req.user.email
  });
});

module.exports = router;