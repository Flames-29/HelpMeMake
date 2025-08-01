const getCookieOptions = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  
  console.log('Cookie Config - Environment:', process.env.NODE_ENV);
  console.log('Cookie Config - Is Production:', isProduction);
  console.log('Cookie Config - UI_URL:', process.env.UI_URL);
  
  return {
    httpOnly: true,
    secure: isProduction, // HTTPS required in production
    sameSite: isProduction ? 'None' : 'Lax', // 'None' for cross-domain in production
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    path: '/',
    // Add domain configuration for production
    ...(isProduction && process.env.UI_URL && {
      domain: new URL(process.env.UI_URL).hostname.replace('www.', '')
    })
  };
};

const setJWTCookie = (res, token, cookieName = 'access_token') => {
  const cookieOptions = getCookieOptions();
  
  console.log('Setting JWT cookie:', {
    name: cookieName,
    hasToken: !!token,
    options: cookieOptions
  });
  
  res.cookie(cookieName, token, cookieOptions);
  
  // For backward compatibility, also set with 'token' name
  if (cookieName === 'access_token') {
    res.cookie('token', token, cookieOptions);
  }
};

module.exports = {
  getCookieOptions,
  setJWTCookie
};