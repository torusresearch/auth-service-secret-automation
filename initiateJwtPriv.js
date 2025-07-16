const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { input, select, confirm } = require('@inquirer/prompts');
const { encryptWithKMS, updateSecretValue, listSecretVersions } = require('./secretManager');

async function generateJWTKeys() {
  console.log('🔐 JWT Key Generation & KMS Encryption Tool\n');

  try {
    // Check AWS CLI configuration
    const awsConfigured = await confirm({
      message: 'Is the AWS CLI installed and configured?',
      default: true
    });

    if (!awsConfigured) {
      console.log('❌ Please install and configure AWS CLI first');
      console.log('Run: aws configure');
      return;
    }

    // Get environment selection
    const environment = await select({
      message: 'Select the environment:',
      choices: [
        { name: 'Development', value: 'dev' },
        { name: 'Staging', value: 'uat' },
        { name: 'Production', value: 'prd' }
      ]
    });

    // Construct KMS alias using the same format as Apple rotation
    const kmsAlias = `alias/mmcx/${environment}/auth-service-api`;
    const secretName = `${environment}/web3-auth/auth-service-api`;

    console.log('\n📋 Configuration Summary:');
    console.log(`Environment: ${environment}`);
    console.log(`KMS Alias: ${kmsAlias}`);
    console.log(`Secret Name: ${secretName}`);

    const proceed = await confirm({
      message: 'Do you want to proceed with JWT key generation?',
      default: true
    });

    if (!proceed) {
      console.log('❌ Operation cancelled');
      return;
    }

    console.log('\n🔑 Generating ECDSA key pair (P-256)...');
    
    // Generate ECDSA key pair using Node.js crypto module
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1', // P-256 curve
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      },
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      }
    });

    console.log('✅ ECDSA key pair generated successfully');

    // Extract base64 content from private key (remove PEM headers/footers)
    console.log('📝 Extracting private key base64 content...');
    const privateKeyBase64 = privateKey
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\r?\n/g, '')
      .trim();

    // Extract base64 content from public key (remove PEM headers/footers)
    console.log('📝 Extracting public key base64 content...');
    const publicKeyBase64 = publicKey
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\r?\n/g, '')
      .trim();

    console.log('📏 Key lengths:');
    console.log(`Private key base64: ${privateKeyBase64.length} characters`);
    console.log(`Public key base64: ${publicKeyBase64.length} characters`);

    // Step 4: Encrypt private key with KMS (public key stays unencrypted)
    console.log(`\n🔒 Encrypting private key with KMS alias: ${kmsAlias}`);
    
    const encryptedPrivateKey = await encryptWithKMS(privateKeyBase64, kmsAlias);
    
    console.log('✅ Private key encrypted successfully with KMS');
    console.log('📝 Public key will be stored unencrypted');

    // Step 5: Update AWS Secrets Manager
    console.log(`\n📝 Updating JWT keys in Secrets Manager: ${secretName}`);
    
    // Update JWT_PRIV with encrypted private key
    await updateSecretValue(secretName, 'JWT_PRIV', encryptedPrivateKey);
    console.log('✅ JWT_PRIV updated successfully');
    
    // Update JWT_PUB with unencrypted public key
    await updateSecretValue(secretName, 'JWT_PUB', publicKeyBase64);
    console.log('✅ JWT_PUB updated successfully');

    // Step 6: Create result object with consistent structure
    const result = {
      metadata: {
        environment,
        kmsAlias,
        secretName,
        generatedAt: new Date().toISOString(),
        keyType: 'ECDSA P-256 (prime256v1)',
        algorithm: 'ES256'
      },
    };

    // Step 7: No cleanup needed - using in-memory key generation
    console.log('\n✅ No temporary files to clean up (used in-memory key generation)');

    // Step 8: Output results
    console.log('\n=== JWT KEYS (JSON FORMAT) ===');
    console.log(JSON.stringify(result, null, 2));

    console.log('\n✅ JWT key generation completed successfully!');
    console.log(`\n🔐 Keys encrypted with: ${kmsAlias}`);
    console.log(`📝 Keys stored in Secrets Manager: ${secretName}`);
    console.log('\n📊 Secrets Manager Keys:');
    console.log(`- JWT_PRIV: Encrypted with KMS`);
    console.log(`- JWT_PUB: Unencrypted base64`);
    console.log('\n📝 Security Notes:');
    console.log('- Keys generated using Node.js crypto module (no OpenSSL required)');
    console.log('- JWT_PRIV is encrypted with KMS and stored safely');
    console.log('- JWT_PUB is stored unencrypted for easy access');
    console.log('- Both keys are now available in your AWS Secrets Manager');
    console.log('- Use the encrypted versions for production applications');

    return result;

  } catch (error) {
    console.error('❌ Error during key generation:', error.message);
    console.error('Stack trace:', error.stack);
    process.exit(1);
  }
}

// Run the script
generateJWTKeys()
  .then(async () => {
    console.log('\n🎉 Process completed successfully!');
    await listSecretVersions('dev/web3-auth/auth-service-api');
  })
  .catch(error => {
    console.error('❌ Script failed:', error.message);
    process.exit(1);
  }); 