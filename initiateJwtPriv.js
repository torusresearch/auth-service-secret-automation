const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { input, select, confirm } = require('@inquirer/prompts');
const { encryptWithKMS, updateSecretValue, listSecretVersions } = require('./secretManager');
const rs = require('jsrsasign');

function validatePrivateKeyFormat(privateKey) {
  // Test the key with jsrsasign to see if it's valid
  try {
    console.log('🔍 Validating private key format with jsrsasign...');
    const key = rs.KEYUTIL.getKey(privateKey);
    console.log('✅ Private key validation successful');
    return key;
  } catch (error) {
    console.error('❌ Private key validation failed:', error.message);
    throw new Error(
      `Private key is not valid for ES256: ${
        error instanceof Error ? error.message : error
      }`
    );
  }
}

function reconstructPEMPrivateKey(base64Key) {
  // Use EC PRIVATE KEY format instead of PKCS#8 format
  const header = '-----BEGIN EC PRIVATE KEY-----';
  const footer = '-----END EC PRIVATE KEY-----';

  // Split the base64 key into 64-character lines for proper PEM formatting
  const formattedKey = base64Key.match(/.{1,64}/g)?.join('\n') || base64Key;

  return `${header}\n${formattedKey}\n${footer}`;
}

function testKeyPairMatch(privateKeyPEM, publicKeyPEM) {
  try {
    console.log('🧪 Testing if private key matches public key...');
    
    // Create a test payload
    const testPayload = {
      sub: 'test-user',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      test: 'key-pair-validation'
    };
    
    console.log('📝 Test payload created:', JSON.stringify(testPayload));
    
    // Method 1: Use jsrsasign for JWT signing and verification
    try {
      // Create JWT header
      const header = {
        alg: 'ES256',
        typ: 'JWT'
      };
      
      // Sign the JWT with private key
      console.log('🔏 Signing test JWT with private key...');
      const jwt = rs.KJUR.jws.JWS.sign('ES256', JSON.stringify(header), JSON.stringify(testPayload), privateKeyPEM);
      console.log('✅ JWT signed successfully');
      console.log('JWT (first 50 chars):', jwt.substring(0, 50) + '...');
      
      // Verify the JWT with public key
      console.log('🔍 Verifying JWT signature with public key...');
      const isValid = rs.KJUR.jws.JWS.verify(jwt, publicKeyPEM, ['ES256']);
      
      if (isValid) {
        console.log('✅ JWT verification successful - Private and public keys MATCH!');
        
        // Decode and display the payload to confirm
        const decoded = rs.KJUR.jws.JWS.parse(jwt);
        console.log('📋 Decoded payload:', JSON.stringify(decoded.payloadObj, null, 2));
        
        return {
          match: true,
          method: 'jsrsasign-jwt',
          jwt: jwt,
          decodedPayload: decoded.payloadObj
        };
      } else {
        console.log('❌ JWT verification failed - Keys do NOT match!');
        return { match: false, method: 'jsrsasign-jwt', error: 'JWT verification failed' };
      }
      
    } catch (jwtError) {
      console.log('❌ JWT method failed:', jwtError.message);
      
      // Method 2: Use Node.js crypto for direct signing/verification
      try {
        console.log('🔄 Trying Node.js crypto method...');
        
        const testMessage = JSON.stringify(testPayload);
        
        // Sign with private key
        const sign = crypto.createSign('SHA256');
        sign.update(testMessage);
        sign.end();
        const signature = sign.sign(privateKeyPEM);
        console.log('✅ Message signed with private key');
        
        // Verify with public key
        const verify = crypto.createVerify('SHA256');
        verify.update(testMessage);
        verify.end();
        const isValid = verify.verify(publicKeyPEM, signature);
        
        if (isValid) {
          console.log('✅ Signature verification successful - Private and public keys MATCH!');
          return {
            match: true,
            method: 'nodejs-crypto',
            signature: signature.toString('base64')
          };
        } else {
          console.log('❌ Signature verification failed - Keys do NOT match!');
          return { match: false, method: 'nodejs-crypto', error: 'Signature verification failed' };
        }
        
      } catch (cryptoError) {
        console.log('❌ Node.js crypto method also failed:', cryptoError.message);
        return { match: false, method: 'both-failed', error: `JWT: ${jwtError.message}, Crypto: ${cryptoError.message}` };
      }
    }
    
  } catch (error) {
    console.error('❌ Key pair test failed:', error.message);
    return { match: false, method: 'error', error: error.message };
  }
}

function convertPKCS8ToECPrivateKey(pkcs8PEM) {
  try {
    console.log('🔄 Converting PKCS#8 to EC PRIVATE KEY format using Node.js crypto...');
    
    // Create a KeyObject from the PKCS#8 PEM
    const keyObject = crypto.createPrivateKey({
      key: pkcs8PEM,
      format: 'pem',
      type: 'pkcs8'
    });
    
    // Export as EC PRIVATE KEY format
    const ecPrivateKeyPEM = keyObject.export({
      format: 'pem',
      type: 'sec1' // SEC1 is the EC PRIVATE KEY format
    });
    
    console.log('✅ Successfully converted to EC PRIVATE KEY format using Node.js crypto');
    return ecPrivateKeyPEM;
  } catch (error) {
    console.error('❌ Node.js crypto conversion failed:', error.message);
    
    // Fallback: try jsrsasign method but clean it up
    try {
      console.log('🔄 Trying jsrsasign fallback conversion method...');
      const key = rs.KEYUTIL.getKey(pkcs8PEM);
      let ecPrivateKeyPEM = rs.KEYUTIL.getPEM(key, 'PKCS1PRV');
      
      // Clean up the output - remove EC PARAMETERS if present
      if (ecPrivateKeyPEM.includes('-----BEGIN EC PARAMETERS-----')) {
        console.log('🧹 Cleaning up EC PARAMETERS from output...');
        
        // Split by EC PARAMETERS and find the EC PRIVATE KEY part
        const parts = ecPrivateKeyPEM.split('-----END EC PARAMETERS-----');
        if (parts.length > 1) {
          // The EC PRIVATE KEY should be in the second part
          const ecPrivKeyPart = parts[1].trim();
          
          // Check if it already has proper headers
          if (!ecPrivKeyPart.startsWith('-----BEGIN EC PRIVATE KEY-----')) {
            // Need to reconstruct the EC PRIVATE KEY
            // The remaining content should be the base64 data
            const base64Data = ecPrivKeyPart.replace(/\s/g, '');
            const formattedKey = base64Data.match(/.{1,64}/g)?.join('\n') || base64Data;
            ecPrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----\n${formattedKey}\n-----END EC PRIVATE KEY-----`;
          } else {
            ecPrivateKeyPEM = ecPrivKeyPart;
          }
        }
      }
      
      console.log('✅ Fallback conversion successful');
      return ecPrivateKeyPEM;
    } catch (fallbackError) {
      throw new Error(`All key conversion methods failed: ${fallbackError.message}`);
    }
  }
}

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

    // Step 3: Validate the generated private key format (PKCS#8)
    console.log('\n🔍 Step 3: Validating generated private key (PKCS#8 format)...');
    validatePrivateKeyFormat(privateKey);

    // Step 4: Convert PKCS#8 to EC PRIVATE KEY format and validate
    console.log('\n🔍 Step 4: Converting PKCS#8 to EC PRIVATE KEY format...');
    const ecPrivateKey = convertPKCS8ToECPrivateKey(privateKey);
    validatePrivateKeyFormat(ecPrivateKey);
    console.log('✅ EC PRIVATE KEY format is valid');

    // Step 5: Store the complete EC private key PEM (we'll encrypt the whole PEM)
    console.log('\n📝 Step 5: Preparing EC private key for encryption...');
    console.log('EC Private Key PEM format ready for encryption');
    console.log('EC Private Key length:', ecPrivateKey.length, 'characters');

    // Step 6: Extract base64 content from public key (remove PEM headers/footers)
    console.log('📝 Step 6: Extracting public key base64 content...');
    const ecPrivateKeyBase64 = ecPrivateKey
      .replace('-----BEGIN EC PRIVATE KEY-----', '')
      .replace('-----END EC PRIVATE KEY-----', '')
      .replace(/\r?\n/g, '')
      .trim();

    const publicKeyBase64 = publicKey
      .replace('-----BEGIN PUBLIC KEY-----', '')
      .replace('-----END PUBLIC KEY-----', '')
      .replace(/\r?\n/g, '')
      .trim();

    console.log('\n📏 Key lengths:');
    console.log(`EC Private key PEM base64: ${ecPrivateKeyBase64.length} characters`);
    console.log(`Public key base64: ${publicKeyBase64.length} characters`);

    // Step 6.5: Test key pair match
    console.log('\n🧪 Step 6.5: Testing key pair compatibility...');
    const keyTestResult = testKeyPairMatch(ecPrivateKey, publicKey);
    
    if (!keyTestResult.match) {
      console.error('❌ CRITICAL ERROR: Private and public keys do NOT match!');
      console.error('Test result:', keyTestResult);
      throw new Error(`Key pair validation failed: ${keyTestResult.error}`);
    }
    
    console.log('✅ Key pair validation successful!');
    console.log('📋 Test method used:', keyTestResult.method);
    if (keyTestResult.jwt) {
      console.log('🎯 Test JWT created and verified successfully');
    }

    // return;

    // Step 7: Encrypt complete EC private key PEM with KMS (public key stays unencrypted)
    console.log(`\n🔒 Step 7: Encrypting complete EC private key PEM with KMS alias: ${kmsAlias}`);
    
    const encryptedPrivateKey = await encryptWithKMS(ecPrivateKeyBase64, kmsAlias);
    
    console.log('✅ Complete EC private key PEM encrypted successfully with KMS');
    console.log('📝 Public key will be stored unencrypted');

    // Step 8: Update AWS Secrets Manager
    console.log(`\n📝 Step 8: Updating JWT keys in Secrets Manager: ${secretName}`);
    
    // Update JWT_PRIV with encrypted private key
    await updateSecretValue(secretName, 'JWT_PRIV', encryptedPrivateKey);
    console.log('✅ JWT_PRIV updated successfully');
    
    // Update JWT_PUB with unencrypted public key
    await updateSecretValue(secretName, 'JWT_PUB', publicKeyBase64);
    console.log('✅ JWT_PUB updated successfully');

    // Step 9: Create result object with consistent structure
    const result = {
      metadata: {
        environment,
        kmsAlias,
        secretName,
        generatedAt: new Date().toISOString(),
        keyType: 'ECDSA P-256 (prime256v1) - Complete EC PRIVATE KEY PEM',
        algorithm: 'ES256'
      },
    };

    // Step 10: No cleanup needed - using in-memory key generation
    console.log('\n✅ Step 10: No temporary files to clean up (used in-memory key generation)');

    // Step 11: Output results
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
    console.log('- Private key converted from PKCS#8 to EC PRIVATE KEY format');
    console.log('- Complete EC PRIVATE KEY PEM is encrypted with KMS and stored safely');
    console.log('- JWT_PUB is stored unencrypted for easy access');
    console.log('- Both keys are now available in your AWS Secrets Manager');
    console.log('- Private key validated with jsrsasign for ES256 compatibility');
    console.log('- Decrypted private key can be used directly without reconstruction');

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