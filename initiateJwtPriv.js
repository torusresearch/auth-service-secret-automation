const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { input, select, confirm } = require('@inquirer/prompts');
const { encryptWithKMS, updateSecretValue } = require('./secretManager');

// Generate a unique filename suffix to avoid conflicts
const generateSuffix = () => Math.random().toString(36).substring(2, 8);

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
        { name: 'Staging', value: 'staging' },
        { name: 'Production', value: 'prod' }
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

    // Generate unique filenames
    const suffix = generateSuffix();
    const privateKeyFile = `jwt_priv_${suffix}.pem`;
    const publicKeyFile = `jwt_pub_${suffix}.pem`;
    const privateKeyBase64File = `jwt_priv_${suffix}_base64.txt`;
    const publicKeyBase64File = `jwt_pub_${suffix}_base64.txt`;

    console.log('\n🔑 Generating ECDSA private key...');
    
    // Step 1: Generate ECDSA private key
    execSync(`openssl ecparam -name prime256v1 -genkey -noout -out ${privateKeyFile}`, { 
      stdio: 'inherit' 
    });
    console.log('✅ Private key generated successfully');

    // Step 2: Extract base64 content from private key (remove headers/footers)
    console.log('📝 Extracting private key base64 content...');
    execSync(`grep -v "PRIVATE KEY" ${privateKeyFile} | tr -d "\\n" > ${privateKeyBase64File}`, { 
      stdio: 'inherit' 
    });

    // Step 3: Generate corresponding public key
    console.log('🔑 Generating public key...');
    execSync(`openssl ec -in ${privateKeyFile} -pubout -out ${publicKeyFile}`, { 
      stdio: 'inherit' 
    });
    console.log('✅ Public key generated successfully');

    // Step 4: Extract base64 content from public key
    console.log('📝 Extracting public key base64 content...');
    execSync(`grep -v "PUBLIC KEY" ${publicKeyFile} | tr -d "\\n" > ${publicKeyBase64File}`, { 
      stdio: 'inherit' 
    });

    // Step 5: Read the base64 content
    const privateKeyBase64 = fs.readFileSync(privateKeyBase64File, 'utf8').trim();
    const publicKeyBase64 = fs.readFileSync(publicKeyBase64File, 'utf8').trim();

    console.log('📏 Key lengths:');
    console.log(`Private key base64: ${privateKeyBase64.length} characters`);
    console.log(`Public key base64: ${publicKeyBase64.length} characters`);

    // Step 6: Encrypt private key with KMS (public key stays unencrypted)
    console.log(`\n🔒 Encrypting private key with KMS alias: ${kmsAlias}`);
    
    const encryptedPrivateKey = await encryptWithKMS(privateKeyBase64, kmsAlias);
    
    console.log('✅ Private key encrypted successfully with KMS');
    console.log('📝 Public key will be stored unencrypted');

    // Step 7: Update AWS Secrets Manager
    console.log(`\n📝 Updating JWT keys in Secrets Manager: ${secretName}`);
    
    // Update JWT_PRIV with encrypted private key
    await updateSecretValue(secretName, 'JWT_PRIV', encryptedPrivateKey);
    console.log('✅ JWT_PRIV updated successfully');
    
    // Update JWT_PUB with unencrypted public key
    await updateSecretValue(secretName, 'JWT_PUB', publicKeyBase64);
    console.log('✅ JWT_PUB updated successfully');

    // Step 8: Create result object with consistent structure
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

    // Step 9: Clean up intermediate files
    console.log('\n🧹 Cleaning up temporary files...');
    const filesToCleanup = [
      privateKeyFile,
      publicKeyFile,
      privateKeyBase64File,
      publicKeyBase64File
    ];

    filesToCleanup.forEach(file => {
      if (fs.existsSync(file)) {
        fs.unlinkSync(file);
        console.log(`  - Removed ${file}`);
      }
    });

    // Step 10: Output results
    console.log('\n=== JWT KEYS (JSON FORMAT) ===');
    console.log(JSON.stringify(result, null, 2));

    // Step 11: Save to file option
    const saveToFile = await confirm({
      message: 'Save keys to file?',
      default: true
    });

    if (saveToFile) {
      const filename = `jwt-keys-${environment}-${Date.now()}.json`;
      fs.writeFileSync(filename, JSON.stringify(result, null, 2));
      console.log(`\n💾 Keys saved to: ${filename}`);
    }

    console.log('\n✅ JWT key generation completed successfully!');
    console.log(`\n🔐 Keys encrypted with: ${kmsAlias}`);
    console.log(`📝 Keys stored in Secrets Manager: ${secretName}`);
    console.log('\n📊 Secrets Manager Keys:');
    console.log(`- JWT_PRIV: Encrypted with KMS`);
    console.log(`- JWT_PUB: Unencrypted base64`);
    console.log('\n📝 Security Notes:');
    console.log('- JWT_PRIV is encrypted and stored safely');
    console.log('- JWT_PUB is stored unencrypted for easy access');
    console.log('- Both keys are now available in your AWS Secrets Manager');
    console.log('- Use the encrypted versions for production applications');

    return result;

  } catch (error) {
    console.error('❌ Error during key generation:', error.message);
    
    // Clean up any temporary files if error occurs
    const suffix = generateSuffix();
    const tempFiles = [
      `jwt_priv_${suffix}.pem`,
      `jwt_pub_${suffix}.pem`,
      `jwt_priv_${suffix}_base64.txt`,
      `jwt_pub_${suffix}_base64.txt`
    ];
    
    tempFiles.forEach(file => {
      if (fs.existsSync(file)) {
        try {
          fs.unlinkSync(file);
        } catch (cleanupError) {
          console.warn(`Warning: Could not clean up ${file}`);
        }
      }
    });
    
    process.exit(1);
  }
}

// Run the script
generateJWTKeys()
  .then(() => {
    console.log('\n🎉 Process completed successfully!');
  })
  .catch(error => {
    console.error('❌ Script failed:', error.message);
    process.exit(1);
  }); 