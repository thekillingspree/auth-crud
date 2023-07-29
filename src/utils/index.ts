export * from './keyProvider';
export * from './cosmos';
export * from './communication';
export * from './mfa';

const keys = [
  'KEY_VAULT_URL',
  'PORT',
  'MONGO_URL',
  'COSMOS_ENDPOINT',
  'COSMOS_KEY',
  'COSMOS_DATABASE',
  'COSMOS_CONTAINER',
  'TWILIO_ACCOUNT_SID',
  'TWILIO_AUTH_TOKEN',
  'TWILIO_PHONE_NUMBER',
  'CLIENT_URL',
  'SMTP_USER',
  'SMTP_PASS',
  'SMTP_HOST',
  'SMTP_PORT',
];

export const checkEnvVariables = () => {
  for (const key of keys) {
    if (!process.env[key])
      throw new Error(`Missing ${key} in environment variables`);
  }

  return true;
};

export const isProduction = () =>
  !!process.env.NODE_ENV && process.env.NODE_ENV === 'production';
