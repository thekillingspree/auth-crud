import mongoose, { Schema } from 'mongoose';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';

export enum TokenKind {
  EMAIL = 'email',
  PASSWORD_RESET = 'passwordReset',
  OTP = 'otp',
  TOTP = 'totp',
}

export enum Provider {
  Google = 'google',
  Entra = 'entra',
  Facebook = 'facebook',
}

export interface Token {
  token: string;
  kind: Provider | TokenKind;
  expiry: Date;
}

export enum MFAType {
  PHONE = 'phone',
  TOTP = 'totp',
  NONE = 'none',
}

export enum OtpReason {
  PHONE_VERIFY = 'phone_verify',
  TOTP_VERIFY = 'totp_verify',
  MFA = 'MFA',
}

export interface Otp extends Token {
  reason: OtpReason;
  tries: number;
}

export interface UserInterface {
  _id: string;
  email: string;
  password: string;
  profile: {
    name: string;
    picture: string;
    //...add other fields as required
  };
  googleId?: string;
  phone?: {
    number: string;
    verified: boolean;
  };
  facebookId?: string;
  entraId?: string;
  tokens: Token[];
  emailVerified: boolean;
  emailToken?: Token;
  passwordResetToken?: Token;
  totpSecret?: string;
  totpEnabled: MFAStatus;
  backupCodes: string[];
  comparePassword: (candidatePassword: string) => Promise<boolean>;
  getPreferredMFA: () => MFAType;
}

export enum MFAStatus {
  ENABLED = 'enabled', // Enabled but not verified
  DISABLED = 'disabled', // Disabled
  VERIFIED = 'verified', // Enabled and verified
}

// export interface MFAInfo {
//   mfaStatus: MFAStatus;
//   lastVerified?: Date;
// }

export interface UserSession {
  name: string;
  email: string;
  _id: string;
  otp?: Otp;
  recommendedMFA: MFAType;
  mfaStatus: MFAStatus;
  lastMFA?: Date;
}

const tokenDef = {
  token: String,
  kind: String,
  expiry: Date,
};

const userSchema = new Schema<UserInterface>(
  {
    email: {
      type: String,
      unique: true,
      required: [true, 'Email is required'],
    },
    password: {
      type: String,
      unique: true,
      required: true,
    },
    profile: {
      name: String,
      picture: String,
    },
    googleId: String,
    facebookId: String,
    entraId: String,
    tokens: [
      {
        ...tokenDef,
      },
    ],
    emailVerified: {
      type: Boolean,
      default: false,
    },
    emailToken: tokenDef,
    passwordResetToken: tokenDef,
    totpSecret: String,
    phone: {
      number: String,
      verified: {
        type: Boolean,
        default: false,
      },
    },
    totpEnabled: {
      type: String,
      default: MFAStatus.DISABLED,
    },
    backupCodes: [
      {
        type: String,
      },
    ],
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function (next) {
  if (this.isNew && !this.profile.picture) {
    const md5 = crypto.createHash('md5').update(this.email).digest('hex');
    this.profile.picture = `https://api.dicebear.com/6.x/shapes/svg?seed=${md5}`;
  }

  if (!this.isModified('password')) next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.comparePassword = async function (
  this: UserInterface,
  candidatePassword: string
) {
  const isCorrect = await bcrypt.compare(candidatePassword, this.password);

  return isCorrect;
};

userSchema.methods.getPreferredMFA = function (this: UserInterface) {
  if (this.totpEnabled === MFAStatus.VERIFIED) return MFAType.TOTP;

  if (this.phone && this.phone.verified) return MFAType.PHONE;

  return MFAType.NONE;
};

const User = mongoose.model<UserInterface>('User', userSchema);

export default User;
