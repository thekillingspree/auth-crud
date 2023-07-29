import { Handler } from 'express';
import { MFAStatus } from '../models/user';
import { AppError, ErrorCode, MFAError } from '../utils/errors';

const MFA_WHITELIST = [
  '/phone/auth/verify',
  '/phone/auth/request',
  '/totp/auth/verify',
  //"/phone/register",
  '/phone/verify',
  //"/totp/register",
  '/totp/verify',
  '/totp/redeem',
  '/logout',
];

export const isAuthenticated: Handler = (req, res, next) => {
  if (req.session.user && req.session.user._id) {
    const { mfaStatus, recommendedMFA } = req.session.user;
    if (MFA_WHITELIST.includes(req.path)) {
      //allow MFA
      next();
      return;
    }

    if (mfaStatus === MFAStatus.ENABLED) {
      res.status(401);
      throw new MFAError(recommendedMFA);
    }

    next();
  } else {
    res.status(401);
    throw new AppError('Please login.', ['session'], ErrorCode.UNAUTHORIZED);
  }
};

// An attempt to mitigate csrf by checking for content-type and the presence
// of a custom header field. This is not a foolproof solution, but it is a
// good start. XSS attacks are still possible.
export const csrfCheck: Handler = (req, res, next) => {
  const contentType = req.headers['content-type'];
  const csrfHeader = req.headers['x-csrf-token'];
  const csrfCookie = (req.cookies as { __csrf: string })['__csrf'];
  const { keyProvider } = req;

  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method.toUpperCase())) {
    next();
    return;
  }

  // Type Checks
  if (
    (contentType && contentType != 'application/json') ||
    !csrfHeader ||
    !csrfCookie ||
    typeof csrfHeader !== 'string' ||
    typeof csrfCookie !== 'string'
  ) {
    res.status(400);
    throw new AppError('Invalid request', [], ErrorCode.INVALID_REQUEST);
  }

  const [cookieHash, cookieMessage] = csrfCookie.split('|');

  // Should be sliceable
  if (!cookieHash || !cookieMessage) {
    res.status(400);
    throw new AppError('Invalid request', [], ErrorCode.INVALID_REQUEST);
  }

  // Validate if Hash and Message in the cookie match.
  // And also validate if the value matches the header
  if (
    !keyProvider.validateHMAC(cookieMessage, cookieHash) ||
    cookieMessage !== csrfHeader
  ) {
    res.status(400);
    throw new AppError('Invalid request', [], ErrorCode.INVALID_REQUEST);
  }

  const decoded = keyProvider.decodeString(cookieMessage, 'hex');
  const sessionId = decoded.split(':')[0];

  // CSRF cookie of a different session. Not accepted
  if (req.session.id !== sessionId) {
    res.status(400);
    throw new AppError('Invalid request', [], ErrorCode.INVALID_REQUEST);
  }

  next();
};
