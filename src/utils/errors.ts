import { MFAType } from '../models/user';

export enum ErrorCode {
  SERVER_ERROR = 'server_error',
  INCOMPLETE = 'incomplete',
  INVALID_REQUEST = 'invalid_request',
  UNAUTHORIZED = 'unauthorized',
  NOT_FOUND = 'not_found',
  MFA_REQUIRED = 'mfa_required',
  CONNECTION_ERROR = 'connection_error',
  OUT_OF_ATTEMPTS = 'out_of_attempts',
  EXPIRED = 'expired',
}

export class AppError extends Error {
  public readonly errorCode: ErrorCode;
  public readonly param: string | string[];

  constructor(
    message: string,
    param: string | string[],
    errorCode = ErrorCode.SERVER_ERROR
  ) {
    super(message);
    this.errorCode = errorCode;
    this.param = param || [];
  }
}

export class MFAError extends AppError {
  public readonly recommendedMFA: MFAType;
  private static readonly MFA_MESSAGE = 'Please authenticate with MFA';
  constructor(recommendedMFA = MFAType.NONE) {
    super(MFAError.MFA_MESSAGE, ['mfaStatus'], ErrorCode.MFA_REQUIRED);
    this.recommendedMFA = recommendedMFA;
  }
}
