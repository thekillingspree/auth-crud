import express from 'express';
import morgan from 'morgan';
import { authRouter, mfaRouter, userRouter } from './routes';
import {
  alwaysOnMiddleware,
  csrfCheck,
  errorMiddleware,
  notFoundMiddleware,
} from './middlewares';
import session from 'express-session';
import { KeyProvider, isProduction } from './utils';
import { SESSION_KEY } from './types';
import mongoose from 'mongoose';
import CosmosStore from 'connect-cosmosdb';
import client from './utils/cosmos';
import { UserSession } from './models/user';
import cors from 'cors';
import cookieParser from 'cookie-parser';

declare module 'express-session' {
  interface SessionData {
    user: UserSession;
  }
}

declare module 'express-serve-static-core' {
  interface Request {
    keyProvider: KeyProvider;
  }
}

export default async function initServer() {
  const port = process.env.PORT || 5000;

  const keyProvider = KeyProvider.getInstance();

  await mongoose.connect(process.env.MONGO_URL!);
  mongoose.set('strictQuery', false);

  const app = express();
  const store = await CosmosStore.initializeStore({
    databaseName: process.env.COSMOS_DATABASE!,
    containerName: process.env.COSMOS_CONTAINER,
    cosmosClient: client,
  });

  app.set('trust proxy', 1);
  app.use(
    cors({
      origin: [process.env.CLIENT_URL!],
      credentials: true,
    })
  );
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(morgan('common'));
  app.use(cookieParser());
  //Sessions
  app.use((req, _, next) => {
    req.keyProvider = keyProvider;
    next();
  });
  app.use(
    session({
      name: 'auth_crud',
      secret: await keyProvider.getSecret(SESSION_KEY),
      resave: true,
      saveUninitialized: true,
      store,
      cookie: {
        httpOnly: true,
        secure: isProduction(),
        maxAge: 15 * 60 * 1000,
        path: '/api',
        sameSite: 'lax', // csrf protection
      },
      rolling: true,
    })
  );

  //CSRF Check - Double Submit CSRF
  app.use(csrfCheck);

  //App Service Always On
  app.use(alwaysOnMiddleware);

  //Routes
  app.use('/api/auth', authRouter);
  app.use('/api/user', userRouter);
  app.use('/api/mfa', mfaRouter);

  //Handle rest
  //404s
  app.use(notFoundMiddleware);

  //All other errors
  app.use(errorMiddleware);

  app.listen(port, () => {
    console.log(
      `Server Started at http://localhost:${port}. The server is in ${
        isProduction() ? 'Production' : 'Development'
      } mode`
    );
  });
}
