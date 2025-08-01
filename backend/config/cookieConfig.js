// backend/config/cookieConfig.js

const getCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  console.log('Cookie Config - Environment:', process.env.NODE_ENV);
  console.log('Cookie Config - Is Production:', isProduction);
  
  return {
    httpOnly: true,
    secure: isProduction, // HTTPS required in production
    sameSite: isProduction ? 'None' : 'Lax', // 'None' for cross-domain in production
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
  };
};

const setJWTCookie = (res, token, cookieName = 'token') => {
  const cookieOptions = getCookieOptions();
  
  console.log('Setting JWT cookie:', {
    name: cookieName,
    hasToken: !!token,
    options: cookieOptions
  });
  
  res.cookie(cookieName, token, cookieOptions);
  
  // Also set the old cookie name for backward compatibility
  if (cookieName === 'token') {
    res.cookie('access_token', token, cookieOptions);
  }
};

module.exports = {
  getCookieOptions,
  setJWTCookie
};