import { authenticator } from 'otplib';
import client from 'twilio';
import nodemailer from 'nodemailer';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioClient = client(accountSid, authToken);

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: 587,
  //secure: true,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

authenticator.options = {
  digits: 6,
  step: 30,
  window: 5,
};

export const sendOtp = (phone: string, otp: string) => {
  return twilioClient.messages.create({
    body: `Your OTP to login to AuthCrud is ${otp}. Please note that 2FA with time based OTP is recommended over SMS based OTPs. `,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: phone,
  });
};

export const generateTotpSecret = (name: string): [string, string] => {
  const secret = authenticator.generateSecret();
  const keyUri = authenticator.keyuri(name, 'AuthCrud', secret);
  return [secret, keyUri];
};

export const verifyTotp = (token: string, secret: string) => {
  return authenticator.verify({ token, secret });
};

// Aesthic reset email template
// The below function returns plain-text and HTML templates for the reset email
export const resetEmailTemplate = (
  name: string,
  token: string
): [string, string] => {
  const plainText = `
  
  Hi ${name},

  You are receiving this email because you have requested the reset of the password for your account.
  
  Please click on the following link, or paste this into your browser to complete the process, and reset your password:
  ${process.env.CLIENT_URL}/reset/${token}
  
  If you did not request this, please ignore this email and your password will remain unchanged. 

  For enhanced security always enable MFA.
  
  Regards,
  Team AuthCrud
  `;

  const htmlTemplate = `

  <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 16px; color: #333;">
  <p>Hi ${name},</p>
  <p>You are receiving this email because you have requested the reset of the password for your account.</p>
  <p>Please click on the following link, or paste this into your browser to complete the process, and reset your password:</p>
  <p><a href="${process.env.CLIENT_URL}/reset/${token}">Reset Email</a></p>
  <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
  <p>For enhanced security always enable MFA, if not done already.</p>
  <p>Regards,</p>
  <p>Team AuthCrud</p>

  `;

  return [plainText, htmlTemplate];
};

export const verifyEmailTemplate = (
  name: string,
  token: string
): [string, string] => {
  const plainText = `

  Hi ${name},

  Please click on the following link, or paste this into your browser to verify your email:
  ${process.env.CLIENT_URL}/verify/${token}

  For enhanced security always enable MFA, if not done already.

  Regards,
  Team AuthCrud
  
  `;

  const htmlTemplate = `
  
  <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 16px; color: #333;">
  <p>Hi ${name},</p>
  <p>Please click on the following link, or paste this into your browser to verify your email:</p>
  <p><a href="${process.env.CLIENT_URL}/verify/${token}">Verify Email</a></p>
  <p>For enhanced security always enable MFA, if not done already.</p>
  <p>Regards,</p>
  <p>Team AuthCrud</p>
  </div>

  `;

  return [plainText, htmlTemplate];
};

export const sendEmail = async (
  email: string,
  subject: string,
  body: [string, string]
) => {
  const emailContent = {
    to: email,
    from: process.env.SMTP_USER!,
    subject,
    text: body[0],
    html: body[1],
  };

  await transporter.sendMail(emailContent);
};
