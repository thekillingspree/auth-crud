# Auth Crud

This project was created as an learning experiment by implementing Authentication, Authorization from the ground up. Includes Phone and TOTP based MFA, Email verification, Password reset, etc. in an API only environment. Curiosity on how authentication in modern applications work led me to build this.

Since this is purely for learning purposes, it is not recommended to use this in production. In production, a battle-tested library like Passport is recommended to be used.

## Implementations

- [x] Login, Register, Logout
- [x] Mongo DB based database
- [x] Globally distributed session store using Cosmos DB and [connect-cosmosdb](https://www.npmjs.com/package/connect-cosmosdb) store for express-session.
- [x] Email Verification
- [x] Reset Passwords
- [x] Phone based MFA
- [x] TOTP based MFA to be used with apps like Microsoft Authenticator, Google Authenticator, Authy etc.
- [x] Encryption of sensitive data using AES-256-GCM. Secrets are securely stored in Azure Key Vault.
- [x] CSRF protection, using HMAC generated tokens and double submit cookie pattern.

**Todo**

- [ ] Session and device management
- [ ] Email alerts for suspicious login activity
- [ ] OAuth and OpenID for Self, Google, Entra ID.

## Running Locally

1. Install dependencies

```bash
npm install
```

2. Duplicate the `.env.sample` file and change it to _`.env`_, and fill in all the values like the connection strings and secrets. For better management, will be moving all the values to Key Vault.
3. Create the necessary resources as below
   - Mongo DB database - For storing the data
   - Cosmos DB database - For storing the session data. You can disable the Cosmos db based session store, by removing the `store` option in the express-session middleware configuration.
   ```typescript
    app.use(
      session({
        ...
        //store, - commented out.
        ...
      })
    );
   ```
   - Azure KeyVault to store the secrets. Currently you would need two secrets `sessionKey` for session key and `primaryKey` which is used in encryption.
   - Twilio account to send SMS OTP
   - SendGrid/Email SMTP account to send emails via nodemailer.
4. Add the relevant values to the `.env` file.
5. Build the app:

```bash
npm run build
```

6. Start the app:

```bash
npm start
```
