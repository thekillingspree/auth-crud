import { DefaultAzureCredential } from '@azure/identity';
import { SecretClient } from '@azure/keyvault-secrets';
import { PRIMARY_ENCRYPTION_KEY } from '../types';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
} from 'crypto';
import { AppError, ErrorCode } from './errors';

export class KeyProvider {
  private _keyVaultSecretClient: SecretClient;
  private static _instance: KeyProvider | null = null;
  private static primaryEncryptionKey: Buffer;

  private constructor() {
    const keyVaultURL = process.env.KEY_VAULT_URL || '';
    const credential = new DefaultAzureCredential();
    this._keyVaultSecretClient = new SecretClient(keyVaultURL, credential);

    this._keyVaultSecretClient
      .getSecret(PRIMARY_ENCRYPTION_KEY)
      .then(key => {
        if (!key.value) {
          throw new AppError(
            'KeyVault: Primary Encryption Key could not be loaded',
            ['key_vault'],
            ErrorCode.CONNECTION_ERROR
          );
        }
        KeyProvider.primaryEncryptionKey = Buffer.from(key.value, 'base64');
      })
      .catch(() => {
        throw new AppError(
          'KeyVault: Primary Encryption Key could not be loaded',
          ['key_vault'],
          ErrorCode.CONNECTION_ERROR
        );
      });
  }

  static getInstance(): KeyProvider {
    if (!this._instance) {
      this._instance = new KeyProvider();
    }

    return this._instance;
  }

  async getSecret(key: string) {
    const secret = await this._keyVaultSecretClient.getSecret(key);

    if (!secret.value) {
      throw new AppError(
        'KeyVault: Session Key could not be loaded',
        [key],
        ErrorCode.NOT_FOUND
      );
    }
    return secret.value;
  }

  private generateIV() {
    return randomBytes(12);
  }

  encrypt(data: string) {
    const buffer = Buffer.from(data, 'utf8');
    const iv = this.generateIV();
    const cipher = createCipheriv(
      'aes-256-gcm',
      KeyProvider.primaryEncryptionKey,
      iv
    );

    let encrypted = cipher.update(buffer);

    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const tag = cipher.getAuthTag();

    return Buffer.concat([iv, encrypted, tag]).toString('base64');
  }

  decrypt(data: string) {
    try {
      const buffer = Buffer.from(data, 'base64');
      const iv = buffer.subarray(0, 12);
      const tag = buffer.subarray(buffer.length - 16, buffer.length);
      const encrypted = buffer.subarray(12, buffer.length - 16);

      const decipher = createDecipheriv(
        'aes-256-gcm',
        KeyProvider.primaryEncryptionKey,
        iv
      );
      decipher.setAuthTag(tag);

      const decrypted = decipher.update(encrypted);

      return Buffer.concat([decrypted, decipher.final()]).toString('utf8');
    } catch (error) {
      console.error(error);
      throw new AppError(
        'Could not decrypt the data',
        ['data'],
        ErrorCode.INVALID_REQUEST
      );
    }
  }

  hash(data: string, algorithm = 'sha256') {
    return createHash(algorithm).update(data).digest('hex');
  }

  randomString(size: number, encoding: BufferEncoding = 'hex') {
    return randomBytes(size).toString(encoding);
  }

  generateHMAC(data: string): string {
    return createHmac('sha256', KeyProvider.primaryEncryptionKey)
      .update(data)
      .digest('hex');
  }

  validateHMAC(data: string, hash: string): boolean {
    return this.generateHMAC(data) === hash;
  }

  encodeString(
    data: string,
    fromEncoding: BufferEncoding = 'utf8',
    toEncoding: BufferEncoding = 'base64'
  ) {
    return Buffer.from(data, fromEncoding).toString(toEncoding);
  }

  decodeString(
    data: string,
    fromEncoding: BufferEncoding = 'base64',
    toEncoding: BufferEncoding = 'utf8'
  ) {
    return Buffer.from(data, fromEncoding).toString(toEncoding);
  }
}
