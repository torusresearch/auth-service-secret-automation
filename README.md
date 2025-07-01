# Apple Client Secret Generator & AWS Encryptor

This Node.js application generates Apple Sign-in client secrets (JWT tokens), encrypts them using AWS KMS, and stores them in AWS Secrets Manager for both MAIN and FLASK applications.

## What it does

1. **Interactive CLI** - Prompts you for all required configuration through an easy-to-use interface
2. **Generates Apple JWT tokens** for MAIN and/or FLASK applications using their respective Apple credentials
3. **Encrypts tokens** using AWS KMS with your specified alias
4. **Stores encrypted tokens** in AWS Secrets Manager as key-value pairs
5. **Preserves existing secrets** - only updates the Apple client secret keys without affecting other values

## Prerequisites

### Node.js Dependencies
- Open Terminal inside the Linux workspace and run this command
```bash
bash install-package.sh
```

### Apple Developer Account Setup
- Apple Developer Team ID
- App Bundle IDs for both MAIN and FLASK applications  
- Key IDs for both applications
- ES256 Private Keys (ECDSA format from Apple Developer portal)

### AWS Setup
- AWS CLI installed and configured with appropriate permissions
- KMS key with alias: `alias/mmcx/{ENV}/auth-service-api`
- Secrets Manager secret: `{ENV}/web3-auth/auth-service-api`

## Usage

Run the interactive tool:

```bash
node initiateAppleSecretRotation.js
```

The tool will guide you through:

1. **AWS Configuration Check** - Confirms AWS CLI is installed and configured
2. **Environment Selection** - Choose Development, Staging, or Production
3. **App Selection** - Choose MAIN, FLASK, or both applications
4. **Apple Credentials** - Enter the required Apple Developer credentials:
   - Client ID (Bundle ID)
   - Team ID
   - Private Key Path
   - Key ID
5. **Confirmation** - Review your configuration before proceeding

## Interactive Prompts

The tool will ask you for:

```
🍎 Apple Client Secret Rotation Tool

? Is the AWS CLI installed and configured? (yes/no)
? Select the environment: (Development/Staging/Production)
? Select the app: (Main/Flask/Both)
? Enter [APP] Apple Client ID: 
? Enter [APP] Apple Team ID: 
? Enter [APP] Apple Key Path: 
? Enter [APP] Apple Key ID: 
```

## What happens when you run it

1. **Validates** AWS CLI configuration and credentials
2. **Collects** all required Apple Developer information interactively
3. **Generates JWT tokens**:
   - Creates JWT with 180-day expiry
   - Signs with ES256 algorithm using your private key
4. **Encrypts tokens** using AWS KMS
5. **Updates AWS Secrets Manager**:
   - Retrieves current secret values
   - Updates `MAIN_APPLE_CLIENT_SECRET` or `FLASK_APPLE_CLIENT_SECRET` keys
   - Preserves all other existing key-value pairs

## Finding Your Apple Credentials

1. **Team ID**: Found in Apple Developer Account > Membership
2. **Client ID**: Your app's Bundle ID from App Store Connect
3. **Key ID**: From the private key you created in Apple Developer > Certificates, Identifiers & Profiles > Keys
4. **Private Key**: Download the .p8 file from Apple Developer portal

## Output

The application will store encrypted keys in your AWS Secrets Manager:

- `MAIN_APPLE_CLIENT_SECRET`: Encrypted JWT for your main application
- `FLASK_APPLE_CLIENT_SECRET`: Encrypted JWT for your Flask application

Example successful run:
```
✅ Generated FLASK token successfully
🔒 Encrypting token with KMS alias: alias/mmcx/dev/auth-service-api
✅ Token encrypted successfully
📝 Updating FLASK_APPLE_CLIENT_SECRET in Secrets Manager: dev/web3-auth/auth-service-api
✅ Secret updated successfully
```

## Troubleshooting

### "secretOrPrivateKey must be an asymmetric key when using ES256"
- Ensure you're using the correct .p8 file downloaded from Apple Developer portal
- Verify the private key file path is correct and accessible

### AWS Permission Errors
- Run `aws configure list` to verify AWS CLI setup
- Ensure your AWS credentials have KMS and Secrets Manager permissions
- Verify the KMS key alias and Secrets Manager secret exist in your account

### Apple Key Issues
- Double-check Key ID matches the key in your Apple Developer account
- Ensure Team ID and Client ID are correct (no extra spaces)
- Verify the private key file exists at the specified path

## Security Notes

- **Private Keys**: Keep your Apple .p8 files secure and never commit them to version control
- **AWS Credentials**: Use IAM roles in production environments
- **Token Expiry**: Tokens are set to expire in 180 days - plan for regular rotation
- **Interactive Mode**: The tool doesn't store credentials - you enter them each time for security
