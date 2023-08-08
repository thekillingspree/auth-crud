import { Handler } from 'express';

export const alwaysOnMiddleware: Handler = (req, res, next) => {
  const userAgent = req.headers['user-agent'];
  console.log(userAgent);

  if (userAgent === 'AlwaysOn') {
    res.status(200).json({
      message: 'ping',
    });
    return;
  }

  next();
};
