import { Router } from 'express';
import {
  mfaRedeemBackupCodeController,
  mfaRegisterPhoneController,
  mfaRegisterTotpController,
  mfaRequestPhoneAuthorizationController,
  mfaVerifyPhoneAuthorizationController,
  mfaVerifyPhoneController,
  mfaVerifyTotpAuthController,
  mfaVerifyTotpController,
} from '../controllers';
import { isAuthenticated } from '../middlewares';
export const mfaRouter = Router();

// Phone MFA
mfaRouter.post('/phone/register', isAuthenticated, mfaRegisterPhoneController);
mfaRouter.post('/phone/verify', isAuthenticated, mfaVerifyPhoneController);
mfaRouter.post(
  '/phone/auth/request',
  isAuthenticated,
  mfaRequestPhoneAuthorizationController
);
mfaRouter.post(
  '/phone/auth/verify',
  isAuthenticated,
  mfaVerifyPhoneAuthorizationController
);

// TOTP MFA
mfaRouter.post('/totp/register', isAuthenticated, mfaRegisterTotpController);
mfaRouter.post('/totp/verify', isAuthenticated, mfaVerifyTotpController);
mfaRouter.post(
  '/totp/auth/verify',
  isAuthenticated,
  mfaVerifyTotpAuthController
);
mfaRouter.post('/totp/redeem', isAuthenticated, mfaRedeemBackupCodeController);
