const JwtStrategy = require('passport-jwt').Strategy;
const User = require('../../Model/User');

const cookieExtractor = (req) => {
  let token = null;
  
  console.log('Cookie extraction - Available cookies:', req.cookies);
  console.log('Cookie extraction - Headers:', {
    authorization: req.headers.authorization,
    cookie: req.headers.cookie
  });
  
  // Check for both cookie names to maintain backward compatibility
  if (req && req.cookies) {
    // Primary cookie name
    token = req.cookies.access_token;
    
    // Fallback to 'token' for OAuth flow
    if (!token) {
      token = req.cookies.token;
    }
    
    console.log('Extracted token from cookies:', !!token);
  }
  
  // Fallback to Authorization header
  if (!token && req.headers.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
      console.log('Extracted token from Authorization header:', !!token);
    }
  }
  
  // Additional fallback - check raw cookie header
  if (!token && req.headers.cookie) {
    const cookies = req.headers.cookie.split(';');
    for (const cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'access_token' || name === 'token') {
        token = value;
        console.log(`Extracted token from raw cookie header (${name}):`, !!token);
        break;
      }
    }
  }
  
  return token;
};

const jwtStrategy = new JwtStrategy({
  jwtFromRequest: cookieExtractor,
  secretOrKey: process.env.JWT_SECRET,
  passReqToCallback: true
}, async (req, payload, done) => {
  try {
    console.log('JWT Strategy - Payload:', {
      userId: payload.userId,
      email: payload.email,
      role: payload.role,
      exp: new Date(payload.exp * 1000)
    });
    
    const user = await User.findById(payload.userId).select('-password');
    
    if (!user) {
      console.log('JWT Strategy - User not found for ID:', payload.userId);
      return done(null, false, { message: 'User not found' });
    }
    
    console.log('JWT Strategy - User found:', {
      id: user._id,
      email: user.email,
      role: user.role
    });
    
    return done(null, user);
  } catch (error) {
    console.error('JWT Strategy Error:', error);
    return done(error, false);
  }
});

module.exports = jwtStrategy;