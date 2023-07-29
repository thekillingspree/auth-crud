import { randomBytes, randomInt } from 'crypto';

export const genOtp = () => randomInt(999999).toString().padStart(6, '0');

export const generateNewCode = () => {
  const code = [];

  for (let j = 0; j < 5; j++) {
    code.push(randomBytes(1).toString('hex'));
  }
  code.push('-');
  for (let j = 0; j < 5; j++) {
    code.push(randomBytes(1).toString('hex'));
  }

  return code.join('').toUpperCase();
};

export const generateBackupCodes = () => {
  const backupCodes = [];
  for (let i = 0; i < 10; i++) {
    const code = generateNewCode();
    backupCodes.push(code);
  }

  return backupCodes;
};
