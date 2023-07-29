import {
  genOtp,
  generateBackupCodes,
  generateNewCode,
  generateTotpSecret,
  sendOtp,
  verifyTotp,
} from '../utils';
import expressAsyncHandler from 'express-async-handler';
import { Handler } from 'express';
import User, { MFAStatus, Otp, OtpReason, TokenKind } from '../models/user';
import { AppError, ErrorCode } from '../utils/errors';

const getOtp = (
  token: string,
  reason = OtpReason.PHONE_VERIFY,
  expiryMinutes = 10
): Otp => ({
  token,
  kind: TokenKind.OTP,
  reason,
  expiry: new Date(Date.now() + expiryMinutes * 60 * 1000),
  tries: 0,
});

//TODO: Remove DRY Code.

export const mfaRegisterPhoneController: Handler = expressAsyncHandler(
  async (req, res) => {
    const { phone } = req.body as Record<string, string>;

    if (!phone) {
      res.status(400);
      throw new AppError(
        'Please provide all the required values',
        ['phone'],
        ErrorCode.INCOMPLETE
      );
    }

    const { user } = req.session;

    if (!user?._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const existingUser = await User.findOne({
      phone: {
        number: phone,
      },
    }).select('phone');

    if (existingUser) {
      res.status(400);
      throw new AppError(
        'Phone number already registered.',
        ['phone.number'],
        ErrorCode.INVALID_REQUEST
      );
    }

    const userDatabaseObject = await User.findById(user._id).select('phone');
    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    if (
      userDatabaseObject.phone &&
      userDatabaseObject.phone.number === phone &&
      userDatabaseObject.phone.verified
    ) {
      res.status(400);
      throw new AppError(
        'Phone number already verified',
        ['phone.number'],
        ErrorCode.INVALID_REQUEST
      );
    }

    userDatabaseObject.phone = {
      number: phone,
      verified: false,
    };

    const otp = genOtp();

    // Set OTP at a session, as the user should be shown the verify page only once.
    req.session.user!.otp = getOtp(otp);

    //Send OTP
    await userDatabaseObject.save();

    await sendOtp(phone, otp);

    res.status(200).json({
      message:
        'Phone number added successfully. Please verify OTP, it has been sent to your phone. OTP will be valid for 10 minutes',
    });
  }
);

export const mfaVerifyPhoneController: Handler = expressAsyncHandler(
  async (req, res) => {
    const { otp } = req.body as { otp: string };

    if (!otp) {
      res.status(400);
      throw new AppError(
        'Please provide all the required values',
        ['otp'],
        ErrorCode.INCOMPLETE
      );
    }

    if (!req.session.user || !req.session.user._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const { user } = req.session;
    const userDatabaseObject = await User.findById(user._id).select('phone');

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    const phone = userDatabaseObject.phone;
    const storedOtp = user.otp;

    if (!storedOtp || storedOtp.reason !== OtpReason.PHONE_VERIFY || !phone) {
      res.status(400);
      throw new AppError('Invalid OTP', ['otp'], ErrorCode.INVALID_REQUEST);
    }

    if (storedOtp.tries >= 5) {
      res.status(400);
      userDatabaseObject.phone = undefined;
      req.session.user.otp = undefined;
      throw new AppError(
        'No more tries allowed. Please request for a new OTP.',
        ['otp'],
        ErrorCode.OUT_OF_ATTEMPTS
      );
    }

    if (storedOtp.token !== otp) {
      res.status(400);
      userDatabaseObject.phone = undefined;
      req.session.user.otp = {
        ...storedOtp,
        tries: storedOtp.tries + 1,
      };
      throw new AppError(
        `Invalid Backup Code. ${4 - storedOtp.tries} tries left.`,
        ['otp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (
      !storedOtp.expiry ||
      new Date(storedOtp?.expiry).getTime() < Date.now()
    ) {
      res.status(400);
      userDatabaseObject.phone = undefined;
      req.session.user.otp = undefined;
      throw new AppError('OTP expired', ['otp'], ErrorCode.EXPIRED);
    }

    userDatabaseObject.phone = {
      number: phone.number,
      verified: true,
    };

    await userDatabaseObject.save();
    req.session.user.mfaStatus = MFAStatus.VERIFIED;
    req.session.user.lastMFA = new Date();
    req.session.user.otp = undefined;

    res.status(200).json({
      message: 'Phone number verified successfully',
    });
  }
);

export const mfaRequestPhoneAuthorizationController = expressAsyncHandler(
  async (req, res) => {
    const { user } = req.session;

    if (!req.session.user || !user?._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const userDatabaseObject = await User.findById(user._id).select('phone');

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    if (!userDatabaseObject.phone || !userDatabaseObject.phone.verified) {
      res.status(400);
      throw new AppError(
        'Phone number not verified',
        ['phone'],
        ErrorCode.INVALID_REQUEST
      );
    }

    const { number: phone } = userDatabaseObject.phone;
    const otp = genOtp();
    req.session.user.otp = getOtp(otp, OtpReason.MFA);
    await sendOtp(phone, otp);

    res.status(200).json({
      message: 'OTP has been sent to your phone number. Please login.',
    });
  }
);

export const mfaVerifyPhoneAuthorizationController = expressAsyncHandler(
  async (req, res) => {
    const { otp } = req.body as { otp: string };

    if (!otp) {
      res.status(400);
      throw new AppError(
        'Please provide all the required values',
        ['otp'],
        ErrorCode.INCOMPLETE
      );
    }

    if (!req.session.user || !req.session.user._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const { user } = req.session;
    const userDatabaseObject = await User.findById(user._id).select('phone');

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    const storedOtp = user.otp;

    if (!storedOtp || storedOtp.reason !== OtpReason.MFA) {
      res.status(400);
      throw new AppError('Invalid OTP', ['otp'], ErrorCode.INVALID_REQUEST);
    }

    if (storedOtp.tries >= 5) {
      res.status(400);
      req.session.user.otp = undefined;
      throw new AppError(
        'No more tries allowed. Please request for a new OTP.',
        ['otp'],
        ErrorCode.OUT_OF_ATTEMPTS
      );
    }

    if (storedOtp.token !== otp) {
      res.status(400);
      req.session.user.otp = {
        ...storedOtp,
        tries: storedOtp.tries + 1,
      };
      throw new AppError(
        `Invalid OTP. ${4 - storedOtp.tries} tries left.`,
        ['otp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (
      !storedOtp.expiry ||
      new Date(storedOtp?.expiry).getTime() < Date.now()
    ) {
      res.status(400);
      req.session.user.otp = undefined;
      throw new AppError('OTP expired', ['otp'], ErrorCode.EXPIRED);
    }

    req.session.user.mfaStatus = MFAStatus.VERIFIED;
    req.session.user.lastMFA = new Date();
    req.session.user.otp = undefined;

    res.status(200).json({
      message:
        'Phone number verified successfully. User Authentication is now complete.',
    });
  }
);

export const mfaRegisterTotpController: Handler = expressAsyncHandler(
  async (req, res) => {
    const { user } = req.session;
    const { keyProvider } = req;

    if (!req.session.user || !user?._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const userDatabaseObject = await User.findById(user._id).select(
      'totpEnabled'
    );

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    if (userDatabaseObject.totpEnabled === MFAStatus.VERIFIED) {
      res.status(400);
      throw new AppError(
        'TOTP already enabled',
        ['totp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    const [secret, keyUri] = generateTotpSecret(user.name);

    req.session.user.otp = getOtp(
      keyProvider.encrypt(secret),
      OtpReason.TOTP_VERIFY
    );
    res.status(200).json({
      secret,
      keyUri,
      message:
        'Please use the above key URI to configure your authenticator apps like  Microsoft Authenticator, Google Authenticator or Authy. Ensure to verify the registration by entering a newly generated within the 10 minutes.',
    });
  }
);

export const mfaVerifyTotpController = expressAsyncHandler(async (req, res) => {
  const { otp } = req.body as { otp: string };

  const { user } = req.session;
  const { keyProvider } = req;
  if (!req.session.user || !user?._id) {
    res.status(401);
    throw new AppError(
      'Invalid Session. Please log-in',
      ['session'],
      ErrorCode.UNAUTHORIZED
    );
  }

  const userDatabaseObject = await User.findById(user._id).select(
    'totpEnabled totpSecret backupCodes'
  );

  if (!userDatabaseObject) {
    res.status(404);
    throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
  }

  if (userDatabaseObject.totpEnabled === MFAStatus.VERIFIED) {
    res.status(400);
    throw new AppError(
      'TOTP already enabled',
      ['totp'],
      ErrorCode.INVALID_REQUEST
    );
  }

  if (
    !user.otp ||
    user.otp.reason !== OtpReason.TOTP_VERIFY ||
    !user.otp.token
  ) {
    res.status(400);
    throw new AppError(
      'Invalid request. Please re-initiate the MFA Setup',
      ['otp'],
      ErrorCode.INVALID_REQUEST
    );
  }

  const { token: secret } = user.otp;
  const decryptedSecret = keyProvider.decrypt(secret);

  if (!user.otp.expiry || new Date(user.otp?.expiry).getTime() < Date.now()) {
    res.status(400);
    req.session.user.otp = undefined;
    throw new AppError(
      'Registration expired. Re-initiate the MFA Setup',
      ['otp'],
      ErrorCode.EXPIRED
    );
  }

  if (user.otp.tries >= 5) {
    res.status(403);
    throw new AppError(
      'Out of attempts. Please re-initiate the MFA Setup',
      ['otp'],
      ErrorCode.OUT_OF_ATTEMPTS
    );
  }

  if (!verifyTotp(otp, decryptedSecret)) {
    res.status(403);

    req.session.user.otp = {
      ...user.otp,
      tries: user.otp.tries + 1,
    };
    throw new AppError(
      `Invalid Backup Code. ${4 - user.otp.tries} tries left.`,
      ['otp'],
      ErrorCode.INVALID_REQUEST
    );
  }

  const backupCodes = generateBackupCodes();

  userDatabaseObject.totpSecret = secret;
  userDatabaseObject.totpEnabled = MFAStatus.VERIFIED;
  userDatabaseObject.backupCodes = backupCodes.map(code =>
    keyProvider.encrypt(code)
  );

  await userDatabaseObject.save();
  req.session.user.mfaStatus = MFAStatus.VERIFIED;
  req.session.user.lastMFA = new Date();
  res.status(200).json({
    message:
      'Successfully registered TOTP. Please ensure that you save the following backup-codes. They will not be shown again.',
    backupCodes,
  });
});

export const mfaVerifyTotpAuthController = expressAsyncHandler(
  async (req, res) => {
    const { otp } = req.body as { otp: string };

    const { user } = req.session;
    const { keyProvider } = req;

    if (!req.session.user || !user?._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const userDatabaseObject = await User.findById(user._id).select(
      'totpEnabled totpSecret'
    );

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    const secret = userDatabaseObject.totpSecret;

    if (userDatabaseObject.totpEnabled !== MFAStatus.VERIFIED || !secret) {
      res.status(400);
      throw new AppError(
        'TOTP is not enabled/verified. Please enable TOTP',
        ['totp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (!req.session.user.otp) {
      req.session.user.otp = getOtp('_', OtpReason.MFA);
    }

    if (req.session.user.otp.tries >= 5) {
      res.status(403);
      req.session.destroy(() => null);
      throw new AppError(
        'Out of attempts. Please re-login.',
        ['otp'],
        ErrorCode.OUT_OF_ATTEMPTS
      );
    }

    const { otp: sessionOtp } = req.session.user;
    const decryptedSecret = keyProvider.decrypt(secret);

    if (!verifyTotp(otp, decryptedSecret)) {
      res.status(403);

      req.session.user.otp = {
        ...sessionOtp,
        tries: sessionOtp.tries + 1,
      };
      throw new AppError(
        `Invalid TOTP Code. ${4 - sessionOtp.tries} tries left.`,
        ['otp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    req.session.user.mfaStatus = MFAStatus.VERIFIED;
    req.session.user.lastMFA = new Date();
    req.session.user.otp = undefined;
    res.status(200).json({
      message: 'Successfully validated MFA. Authentication flow complete.',
    });
  }
);

export const mfaRedeemBackupCodeController = expressAsyncHandler(
  async (req, res) => {
    const { code } = req.body as { code: string };

    const { user } = req.session;
    const { keyProvider } = req;

    if (!req.session.user || !user?._id) {
      res.status(401);
      throw new AppError(
        'Invalid Session. Please log-in',
        ['session'],
        ErrorCode.UNAUTHORIZED
      );
    }

    const userDatabaseObject = await User.findById(user._id).select(
      'totpEnabled totpSecret phone backupCodes'
    );

    if (!userDatabaseObject) {
      res.status(404);
      throw new AppError('User not found', ['_id'], ErrorCode.NOT_FOUND);
    }

    if (userDatabaseObject.totpEnabled !== MFAStatus.VERIFIED) {
      res.status(400);
      throw new AppError(
        'TOTP is not enabled/verified. Please enable TOTP.',
        ['totp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    if (!req.session.user.otp) {
      req.session.user.otp = getOtp('_', OtpReason.MFA);
    }

    if (req.session.user.otp.tries >= 5) {
      res.status(403);
      req.session.destroy(() => null);
      throw new AppError(
        'Out of attempts. Please re-login.',
        ['otp'],
        ErrorCode.OUT_OF_ATTEMPTS
      );
    }

    const { otp: sessionOtp } = req.session.user;
    let decryptedSecrets = userDatabaseObject.backupCodes.map(code =>
      keyProvider.decrypt(code)
    );
    if (!decryptedSecrets.includes(code)) {
      res.status(403);

      req.session.user.otp = {
        ...sessionOtp,
        tries: sessionOtp.tries + 1,
      };
      throw new AppError(
        `Invalid Backup Code. ${4 - sessionOtp.tries} tries left.`,
        ['otp'],
        ErrorCode.INVALID_REQUEST
      );
    }

    // Invalidate the used backup code
    decryptedSecrets = decryptedSecrets.filter(c => c !== code);

    // Add a new code.
    decryptedSecrets.push(generateNewCode());

    userDatabaseObject.backupCodes = decryptedSecrets.map(code =>
      keyProvider.encrypt(code)
    );

    await userDatabaseObject.save();

    req.session.user.mfaStatus =
      userDatabaseObject.phone && userDatabaseObject.phone.verified
        ? MFAStatus.ENABLED
        : MFAStatus.DISABLED;
    req.session.user.otp = undefined;

    res.status(200).json({
      message:
        'Successfully validated Backup code. This code is no longer active and a replacement code has been generated. To complete login, complete the MFA flow, if configured.',
      backupCodes: decryptedSecrets,
    });
  }
);
