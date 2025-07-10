const fs = require('fs');
const jwt = require('jsonwebtoken');
const { input, select, confirm } = require('@inquirer/prompts');
const { updateSecretValue, encryptWithKMS, listSecretVersions } = require('./secretManager');


async function promptForInputs() {
  console.log('🍎 Apple Client Secret Rotation Tool\n');
  
  // confirm with user if aws cli is installed and configured
  const awsCliInstalled = await confirm({
    message: 'Is the AWS CLI installed and configured?',
    default: true
  });
  
  if (!awsCliInstalled) { 
    console.log('Please install and configure the AWS CLI to proceed.');
    return;
  }

  const environment = await select({
    message: 'Select the environment:',
    choices: [
      { name: 'Development', value: 'dev' },
      { name: 'UAT', value: 'uat' },
      { name: 'Production', value: 'prd' },
    ]
  });
  
  const app = await select({
    message: 'Select the app:',
    choices: [
      { name: 'Main', value: 'main' },
      { name: 'Flask', value: 'flask' }
    ]
  });
  
  // Now ask for app-specific values
  const clientId = await input({
    message: `Enter ${app.toUpperCase()} Apple Client ID:`,
    validate: (input) => input.trim() !== '' || 'Client ID cannot be empty'
  });
  
  const teamId = await input({
    message: `Enter ${app.toUpperCase()} Apple Team ID:`,
    validate: (input) => input.trim() !== '' || 'Team ID cannot be empty'
  });
  
  const keyPath = await input({
    message: `Enter ${app.toUpperCase()} Apple Key Path:`,
    validate: (input) => {
      if (input.trim() === '') return 'Key path cannot be empty';
      if (!fs.existsSync(input.trim())) return 'Key file does not exist';
      return true;
    }
  });
  
  const keyId = await input({
    message: `Enter ${app.toUpperCase()} Apple Key ID:`,
    validate: (input) => input.trim() !== '' || 'Key ID cannot be empty'
  });
  
  return {
    environment,
    app,
    config: {
      clientId,
      teamId,
      keyPath,
      keyId
    }
  };
}

async function generateAppleClientSecret(environment, app, config) {  
  console.log(`\n📋 Configuration Summary:`);
  console.log(`Environment: ${environment}`);
  console.log(`App: ${app}`);
  console.log(`Client ID: ${config.clientId}`);
  console.log(`Team ID: ${config.teamId}`);
  console.log(`Key Path: ${config.keyPath}`);
  console.log(`Key ID: ${config.keyId}\n`);
  
  // Confirm before proceeding
  const confirmProceed = await confirm({
    message: 'Do you want to proceed with generating the Apple client secret?',
    default: true
  });
  
  if (!confirmProceed) {
    console.log('Operation cancelled.');
    return;
  }

  // Generate Apple client secret
  console.log(`🔐 Generating ${app.toUpperCase()} Apple client secret...`);
  const signingKey = fs.readFileSync(config.keyPath, 'utf8');
  const appleSecretClaims = {
    iss: config.teamId,
    aud: 'https://appleid.apple.com',
    sub: config.clientId,
    exp: Math.floor(Date.now() / 1000) + 3600 * 24 * 180, // 180 days
    iat: Math.floor(Date.now() / 1000),
  };
  
  const token = jwt.sign(appleSecretClaims, signingKey, {
    algorithm: 'ES256',
    header: {
      kid: config.keyId,
      alg: 'ES256',
    },
  });
  console.log(`✅ Generated ${app.toUpperCase()} token successfully`);

  // Encrypt token with KMS
  const kmsAlias = `alias/mmcx/${environment}/auth-service-api`;
  console.log(`🔒 Encrypting token with KMS alias: ${kmsAlias}`);
  const encryptedToken = await encryptWithKMS(token, kmsAlias);
  console.log('✅ Token encrypted successfully');

  // Update secret in Secrets Manager
  const secretName = `${environment}/web3-auth/auth-service-api`;
  const secretKey = `${app.toUpperCase()}_APPLE_CLIENT_SECRET`;
    
  return {
    environment,
    app,
    encryptedToken,
    secretName: secretName,
    secretKey: secretKey,
    kmsAlias: kmsAlias
  };
}

async function main() {
  const { environment, app, config } = await promptForInputs();
  const { encryptedToken, secretName, secretKey } = await generateAppleClientSecret(environment, app, config);
  await updateSecretValue(secretName, secretKey, encryptedToken);
  await listSecretVersions(secretName);
}

// Run the function
main()
  .then(result => {
    if (result) {
      console.log('\n🎉 Process completed successfully!');
      console.log('📋 Summary:', {
        environment: result.environment,
        app: result.app,
        secretName: result.secretName,
        secretKey: result.secretKey,
        kmsAlias: result.kmsAlias
      });
    }
  })
  .catch(error => {
    console.error('❌ Error:', error.message);
    process.exit(1);
  });
