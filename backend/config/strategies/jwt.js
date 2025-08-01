const JwtStrategy = require('passport-jwt').Strategy;
const User = require('../../Model/User');

const cookieExtractor = (req) => {
  let token = null;
  
  // Check for both cookie names to maintain backward compatibility
  if (req && req.cookies) {
    // First check for 'token' (what your OAuth is setting)
    token = req.cookies.token;
    
    // Fallback to 'access_token' for existing functionality
    if (!token) {
      token = req.cookies.access_token;
    }
  }
  
  // Fallback to Authorization header
  if (!token && req.headers.authorization) {
    const authHeader = req.headers.authorization;
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
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
    const user = await User.findById(payload.userId).select('-password');
    
    if (!user) {
      return done(null, false, { message: 'User not found' });
    }
    
    return done(null, user);
  } catch (error) {
    console.error('JWT Strategy Error:', error);
    return done(error, false);
  }
});

module.exports = jwtStrategy;