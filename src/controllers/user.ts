import { Handler } from 'express';
import User, { Token, TokenKind } from '../models/user';
import expressAsyncHandler from 'express-async-handler';
import {
  KeyProvider,
  resetEmailTemplate,
  sendEmail,
  verifyEmailTemplate,
} from '../utils';
import { AppError, ErrorCode } from '../utils/errors';

export const userProfilerController: Handler = expressAsyncHandler(
  async (req, res) => {
    const { user } = req.session;

    if (user?._id) {
      const userDatabaseObject = await User.findById(user._id).select(
        'email profile emailVerified phone totpEnabled'
      );

      if (!userDatabaseObject) {
        res.status(404);
        throw new AppError('User not found', ['user'], ErrorCode.NOT_FOUND);
      }

      res.status(200).json({ ...userDatabaseObject.toJSON() });
      return;
    }

    res.status(401);
    throw new AppError(
      'Invalid Session. Please log-in',
      ['_id'],
      ErrorCode.UNAUTHORIZED
    );
  }
);

export const getEmailVerificationTokenAndSendEmail = async (
  email: string,
  name: string,
  keyProvider: KeyProvider
): Promise<Token> => {
  const newEmailToken = keyProvider.encrypt(email);
  const tokenHash = keyProvider.hash(newEmailToken);

  const emailContent = verifyEmailTemplate(name, newEmailToken);

  await sendEmail(email, 'AuthCrud Email Verification', emailContent);

  return {
    token: tokenHash,
    kind: TokenKind.EMAIL,
    expiry: new Date(Date.now() + 24 * 60 * 60 * 1000),
  };
};

export const userSendEmailVerification = expressAsyncHandler(
  async (req, res) => {
    const { user } = req.session;
    const { resend } = req.query;

    if (!user || !user._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['_id'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const userDatabaseObject = await User.findById(user._id).select(
      'email emailToken emailVerified profile'
    );

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    const { emailToken, emailVerified } = userDatabaseObject;

    if (emailVerified) {
      res.status(400);
      throw new AppError(
        'Email already verified',
        ['emailVerified'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (emailToken && emailToken.expiry > new Date() && !resend) {
      res.status(400);
      throw new AppError(
        'Email token is already active. Please verify',
        ['email'],
        ErrorCode.INVALID_REQUEST
      );
    }

    userDatabaseObject.emailToken = await getEmailVerificationTokenAndSendEmail(
      userDatabaseObject.email,
      userDatabaseObject.profile.name,
      req.keyProvider
    );

    await userDatabaseObject.save();

    res.status(200).json({
      message: 'Email Sent',
    });
  }
);

export const userVerifyEmailController = expressAsyncHandler(
  async (req, res) => {
    const { keyProvider } = req;

    const GENERIC_MSG =
      'Invalid verification request. Please re-request verification';

    const token = req.headers['x-email-verification-token'] as string;

    if (!token) {
      res.status(400);
      throw new AppError(
        'Please provide the email verification token',
        ['token'],
        ErrorCode.INCOMPLETE
      );
    }

    const email = keyProvider.decrypt(token);
    const userDatabaseObject = await User.findOne({ email });

    if (!email || !userDatabaseObject) {
      res.status(404);
      throw new AppError(GENERIC_MSG, ['email'], ErrorCode.INVALID_REQUEST);
    }

    const { emailToken } = userDatabaseObject;

    if (!emailToken) {
      res.status(404);
      throw new AppError(GENERIC_MSG, ['email'], ErrorCode.INVALID_REQUEST);
    }

    if (new Date(emailToken.expiry) < new Date()) {
      res.status(400);
      throw new AppError(
        'Email token expired. Please re-request verification',
        ['token'],
        ErrorCode.EXPIRED
      );
    }

    const tokenHash = keyProvider.hash(token);

    if (emailToken.token !== tokenHash) {
      res.status(403);
      throw new AppError(GENERIC_MSG, ['email'], ErrorCode.INVALID_REQUEST);
    }

    userDatabaseObject.emailVerified = true;
    userDatabaseObject.emailToken = undefined;
    await userDatabaseObject.save();

    res.status(200).json({ message: 'Email verified' });
  }
);

export const userRequestPasswordResetController: Handler = expressAsyncHandler(
  async (req, res) => {
    const { email } = req.body as Record<string, string>;
    const { keyProvider } = req;
    if (!email) {
      res.status(400);
      throw new AppError(
        'Please provide the email address',
        ['email'],
        ErrorCode.INCOMPLETE
      );
    }

    const userDatabaseObject = await User.findOne({ email }).select(
      'email password profile'
    );

    if (userDatabaseObject) {
      const token = keyProvider.encrypt(`${email}`);
      const tokenHash = keyProvider.hash(token);

      userDatabaseObject.passwordResetToken = {
        token: tokenHash,
        kind: TokenKind.PASSWORD_RESET,
        expiry: new Date(Date.now() + 24 * 60 * 60 * 1000),
      };

      const resetEmail = resetEmailTemplate(
        userDatabaseObject.profile.name,
        token
      );

      await sendEmail(email, 'AuthCrud Password Reset', resetEmail);
      await userDatabaseObject.save();
    }

    res.status(200).json({ message: 'Password reset Email sent' });
  }
);

export const userVerifyPasswordResetController: Handler = expressAsyncHandler(
  async (req, res) => {
    const token = req.headers['x-password-reset-token'];
    const { keyProvider } = req;
    const { password } = req.body as Record<string, string>;
    if (!token || typeof token !== 'string' || !password) {
      res.status(400);
      throw new AppError(
        'Please provide the password and reset token',
        ['token', 'password'],
        ErrorCode.INCOMPLETE
      );
    }

    const email = keyProvider.decrypt(token);
    const userDatabaseObject = await User.findOne({ email }).select(
      'email passwordResetToken password'
    );

    if (!email || !userDatabaseObject) {
      res.status(404);
      throw new AppError(
        'Invalid password reset token. Please re-request password reset',
        ['token'],
        ErrorCode.INVALID_REQUEST
      );
    }

    const { passwordResetToken } = userDatabaseObject;

    if (!passwordResetToken) {
      res.status(404);
      throw new AppError(
        'Invalid password reset token. Please re-request password reset',
        ['token'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (new Date(passwordResetToken.expiry) < new Date()) {
      res.status(400);
      throw new AppError(
        'Password reset token expired. Please re-request password reset',
        ['token'],
        ErrorCode.EXPIRED
      );
    }

    const tokenHash = keyProvider.hash(token);

    if (passwordResetToken.token !== tokenHash) {
      res.status(403);
      throw new AppError(
        'Invalid password reset token. Please re-request password reset',
        ['token'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (await userDatabaseObject.comparePassword(password)) {
      res.status(400);
      throw new AppError(
        'New password cannot be same as old password',
        ['password'],
        ErrorCode.INVALID_REQUEST
      );
    }

    userDatabaseObject.password = password;
    userDatabaseObject.passwordResetToken = undefined;
    await userDatabaseObject.save();

    res.status(200).json({ message: 'Password reset token verified' });
  }
);
