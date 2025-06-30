const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const { KMSClient, EncryptCommand } = require('@aws-sdk/client-kms');
const { SecretsManagerClient, PutSecretValueCommand, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
require('dotenv').config({ debug: false });

// Initialize AWS clients
const kmsClient = new KMSClient({ region: 'us-east-2' });
const secretsManagerClient = new SecretsManagerClient({ region: 'us-east-2' });

async function encryptWithKMS(plaintext, keyAlias) {
  try {
    const command = new EncryptCommand({
      KeyId: keyAlias,
      Plaintext: Buffer.from(plaintext, 'utf8')
    });
    
    const response = await kmsClient.send(command);
    return Buffer.from(response.CiphertextBlob).toString('base64');
  } catch (error) {
    throw new Error(`KMS encryption failed: ${error.message}`);
  }
}

async function getCurrentSecretValues(secretName) {
  try {
    const command = new GetSecretValueCommand({
      SecretId: secretName
    });
    
    const response = await secretsManagerClient.send(command);
    
    if (response.SecretString) {
      return JSON.parse(response.SecretString);
    } else {
      // If secret doesn't exist or is empty, return empty object
      return {};
    }
  } catch (error) {
    if (error.name === 'ResourceNotFoundException') {
      console.log(`Secret ${secretName} not found, will create new one`);
      return {};
    }
    throw new Error(`Failed to retrieve current secret values: ${error.message}`);
  }
}

async function updateSecretValue(secretName, key, value) {
  try {
    // Get current secret values
    console.log(`Retrieving current values from ${secretName}...`);
    const currentValues = await getCurrentSecretValues(secretName);
    console.log('Current secret keys:', Object.keys(currentValues));
    
    // Update the specific key
    currentValues[key] = value;
    console.log(`Updated key '${key}' in secret`);
    
    // Save updated values back to secret
    const command = new PutSecretValueCommand({
      SecretId: secretName,
      SecretString: JSON.stringify(currentValues, null, 2)
    });
    
    const response = await secretsManagerClient.send(command);
    console.log(`Secret updated successfully in ${secretName}:`, response.VersionId);
    return response;
  } catch (error) {
    throw new Error(`Failed to update secret: ${error.message}`);
  }
}

async function generateAppleClientSecret() {
  // Read environment variables for MAIN
  const mainClientId = process.env.MAIN_APPLE_CLIENT_ID;
  const mainTeamId = process.env.MAIN_APPLE_TEAM_ID;
  const mainKeyPath = process.env.MAIN_APPLE_KEY_PATH;
  const mainKeyId = process.env.MAIN_APPLE_KEY_ID;
  
  // Read environment variables for FLASK
  const flaskClientId = process.env.FLASK_APPLE_CLIENT_ID;
  const flaskTeamId = process.env.FLASK_APPLE_TEAM_ID;
  const flaskKeyPath = process.env.FLASK_APPLE_KEY_PATH;
  const flaskKeyId = process.env.FLASK_APPLE_KEY_ID;
  
  const env = process.env.ENV;

  // Validate required environment variables
  if (!mainClientId || !mainTeamId || !mainKeyPath || !mainKeyId || !env) {
    throw new Error('Missing required MAIN environment variables: MAIN_APPLE_CLIENT_ID, MAIN_APPLE_TEAM_ID, MAIN_APPLE_KEY_PATH, MAIN_APPLE_KEY_ID, ENV');
  }
  
  if (!flaskClientId || !flaskTeamId || !flaskKeyPath || !flaskKeyId) {
    throw new Error('Missing required FLASK environment variables: FLASK_APPLE_CLIENT_ID, FLASK_APPLE_TEAM_ID, FLASK_APPLE_KEY_PATH, FLASK_APPLE_KEY_ID');
  }

  // Generate MAIN Apple client secret
  console.log('Generating MAIN Apple client secret...');
  const mainSigningKey = fs.readFileSync(mainKeyPath, 'utf8');
  const mainAppleSecretClaims = {
    iss: mainTeamId,
    aud: 'https://appleid.apple.com',
    sub: mainClientId,
    exp: Math.floor(Date.now() / 1000) + 3600 * 24 * 180, // 180 days
    iat: Math.floor(Date.now() / 1000),
  };
  const mainToken = jwt.sign(mainAppleSecretClaims, mainSigningKey, {
    algorithm: 'ES256',
    header: {
      kid: mainKeyId,
      alg: 'ES256',
    },
  });
  console.log('Generated MAIN token:', mainToken);

  // Generate FLASK Apple client secret
  console.log('Generating FLASK Apple client secret...');
  const flaskSigningKey = fs.readFileSync(flaskKeyPath, 'utf8');
  const flaskAppleSecretClaims = {
    iss: flaskTeamId,
    aud: 'https://appleid.apple.com',
    sub: flaskClientId,
    exp: Math.floor(Date.now() / 1000) + 3600 * 24 * 180, // 180 days
    iat: Math.floor(Date.now() / 1000),
  };
  const flaskToken = jwt.sign(flaskAppleSecretClaims, flaskSigningKey, {
    algorithm: 'ES256',
    header: {
      kid: flaskKeyId,
      alg: 'ES256',
    },
  });
  console.log('Generated FLASK token:', flaskToken);

  // Encrypt both tokens with KMS
  const kmsAlias = `alias/mmcx/${env}/auth-service`;
  console.log('Encrypting tokens with KMS alias:', kmsAlias);
  const encryptedMainToken = await encryptWithKMS(mainToken, kmsAlias);
  const encryptedFlaskToken = await encryptWithKMS(flaskToken, kmsAlias);
  console.log('Both tokens encrypted successfully');

  // Update both keys in Secrets Manager
  const secretName = `${env}/web3-auth/auth-service-api`;
  console.log('Updating both MAIN_APPLE_CLIENT_SECRET and FLASK_APPLE_CLIENT_SECRET in Secrets Manager:', secretName);
  
  // Get current secret values
  const currentValues = await getCurrentSecretValues(secretName);
  console.log('Current secret keys:', Object.keys(currentValues));
  
  // Update both keys
  currentValues['MAIN_APPLE_CLIENT_SECRET'] = encryptedMainToken;
  currentValues['FLASK_APPLE_CLIENT_SECRET'] = encryptedFlaskToken;
  console.log('Updated keys: MAIN_APPLE_CLIENT_SECRET, FLASK_APPLE_CLIENT_SECRET');
  
  // Save updated values back to secret
  const command = new PutSecretValueCommand({
    SecretId: secretName,
    SecretString: JSON.stringify(currentValues, null, 2)
  });
  
  const response = await secretsManagerClient.send(command);
  console.log(`Both secrets updated successfully in ${secretName}:`, response.VersionId);

  return {
    mainToken: mainToken,
    flaskToken: flaskToken,
    encryptedMainToken: encryptedMainToken,
    encryptedFlaskToken: encryptedFlaskToken,
    secretName: secretName,
    secretKeys: ['MAIN_APPLE_CLIENT_SECRET', 'FLASK_APPLE_CLIENT_SECRET'],
    kmsAlias: kmsAlias
  };
}

// Run the function
generateAppleClientSecret()
  .then(result => {
    console.log('Process completed successfully:', {
      secretName: result.secretName,
      secretKeys: result.secretKeys,
      kmsAlias: result.kmsAlias
    });
  })
  .catch(error => {
    console.error('Error:', error.message);
    process.exit(1);
  });
