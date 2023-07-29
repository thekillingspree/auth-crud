import { CookieOptions, Handler } from 'express';
import asyncHandler from 'express-async-handler';
import User, { MFAStatus, MFAType, UserSession } from '../models/user';
import { getEmailVerificationTokenAndSendEmail } from './user';
import { AppError, ErrorCode } from '../utils/errors';
import { isProduction } from '../utils';

export const register: Handler = asyncHandler(async (req, res) => {
  const { email, password, name } = req.body as Record<string, string>;

  if (!email || !password || !name) {
    res.status(400);
    throw new AppError(
      'Please provide all the required values',
      ['email', 'password', 'name'],
      ErrorCode.INCOMPLETE
    );
  }

  const existingUser = await User.findOne({
    email,
  });

  if (existingUser) {
    res.status(400);
    throw new AppError(
      'User already registered. Please log-in',
      ['email'],
      ErrorCode.NOT_FOUND
    );
  }

  const emailVerificationToken = await getEmailVerificationTokenAndSendEmail(
    email,
    name,
    req.keyProvider
  );
  const newUser = await User.create({
    email,
    password,
    profile: {
      name,
    },
    emailToken: emailVerificationToken,
  });

  const responseUser: UserSession = {
    name,
    email,
    _id: newUser._id,
    recommendedMFA: MFAType.NONE,
    mfaStatus: MFAStatus.DISABLED,
  };

  req.session.user = responseUser;
  res.status(201).json(responseUser);
});

export const loginUser: Handler = asyncHandler(async (req, res) => {
  const { email, password } = req.body as Record<string, string>;

  if (!email || !password) {
    res.status(400);
    throw new AppError(
      'Please provide all the required values',
      ['email', 'password'],
      ErrorCode.INCOMPLETE
    );
  }

  const existingUser = await User.findOne({
    email,
  });

  if (existingUser && (await existingUser.comparePassword(password))) {
    const recommendedMFA = existingUser.getPreferredMFA();
    const responseUser: UserSession = {
      name: existingUser.profile.name,
      email,
      recommendedMFA,
      _id: existingUser._id,
      mfaStatus:
        recommendedMFA === MFAType.NONE
          ? MFAStatus.DISABLED
          : MFAStatus.ENABLED,
    };

    req.session.user = responseUser;
    res.status(200).json({
      ...responseUser,
    });
    return;
  }

  res.status(403);
  throw new AppError(
    'Email or password incorrect. Please check the credentials',
    ['email', 'password'],
    ErrorCode.UNAUTHORIZED
  );
});

export const logout: Handler = (req, res) => {
  req.session.user = undefined;
  req.session.destroy(err => {
    if (err) {
      res.status(500).json({
        error: {
          message: 'Unable to log-out',
        },
      });
    } else {
      res.status(200).json({ message: 'Logged out successfully' });
    }
  });
};

export const csrfController: Handler = (req, res) => {
  const session = req.session;
  let message = `${session.id}:${req.keyProvider.randomString(16)}`;
  message = req.keyProvider.encodeString(message, 'utf-8', 'hex');
  const hash = req.keyProvider.generateHMAC(message);
  const token = `${hash}|${message}`;

  const csrfCookie: CookieOptions = {
    httpOnly: true,
    sameSite: 'lax',
    path: '/api',
    secure: isProduction(),
  };

  res.cookie('__csrf', token, csrfCookie);

  res.status(200).json({
    csrf: message,
  });
};
