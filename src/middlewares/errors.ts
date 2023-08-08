import { Handler, ErrorRequestHandler } from 'express';
import { AppError, ErrorCode, MFAError } from '../utils/errors';
import { isProduction } from '../utils';

export const notFoundMiddleware: Handler = (_, res, next) => {
  res.status(404);
  const error = new AppError('Not found', ['url'], ErrorCode.NOT_FOUND);
  next(error);
};

interface ErrorResponse {
  message: string;
  param?: string | string[];
  errorCode?: string;
  stack?: string | null;
  recommendedMFA?: string;
}

// ErrorHandler does not work without the next parameter.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const errorMiddleware: ErrorRequestHandler = (err, _, res, _next) => {
  const status = res.statusCode === 200 ? 500 : res.statusCode;
  const { message, stack } = err;

  const error: ErrorResponse = {
    message,
    stack: !isProduction() ? stack : null,
  };

  if (err instanceof AppError) {
    const { param, errorCode } = err;

    error.param = param;
    error.errorCode = errorCode;
  }

  if (err instanceof MFAError) {
    const { recommendedMFA } = err;
    error.recommendedMFA = recommendedMFA;
  }

  // Handle custom errors here.
  return res.status(status).json({
    error,
  });
};
