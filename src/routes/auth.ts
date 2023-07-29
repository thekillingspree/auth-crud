import { Router } from 'express';
import { loginUser, logout, register, csrfController } from '../controllers';
import { isAuthenticated } from '../middlewares';

export const authRouter = Router();

authRouter.post('/login', loginUser);
authRouter.post('/register', register);
authRouter.post('/logout', isAuthenticated, logout);
authRouter.get('/csrf', csrfController);
