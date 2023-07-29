import { Router } from 'express';
import { isAuthenticated } from '../middlewares';
import {
  userProfilerController,
  userRequestPasswordResetController,
  userSendEmailVerification,
  userVerifyEmailController,
  userVerifyPasswordResetController,
} from '../controllers';

export const userRouter = Router();

userRouter.get('/profile', isAuthenticated, userProfilerController);
userRouter.post(
  '/email/verify/send',
  isAuthenticated,
  userSendEmailVerification
);
userRouter.post('/email/verify', userVerifyEmailController);

userRouter.post('/password/reset/request', userRequestPasswordResetController);
userRouter.post('/password/reset/verify', userVerifyPasswordResetController);
