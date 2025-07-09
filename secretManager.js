const { SecretsManagerClient, PutSecretValueCommand, GetSecretValueCommand, DescribeSecretCommand, UpdateSecretVersionStageCommand } = require('@aws-sdk/client-secrets-manager');
const secretsManagerClient = new SecretsManagerClient({ region: 'us-east-2' });
const { KMSClient, EncryptCommand } = require('@aws-sdk/client-kms');


const kmsClient = new KMSClient({ region: 'us-east-2' });

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

function generateTimestampLabel() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const seconds = String(now.getSeconds()).padStart(2, '0');
  
  return `${year}${month}${day}_${hours}${minutes}${seconds}`;
}

async function labelPreviousVersionWithTimestamp(secretName) {
  try {
    console.log(`🏷️  Labeling previous version of ${secretName} with timestamp...`);
    
    // Get current secret information
    const describeCommand = new DescribeSecretCommand({
      SecretId: secretName
    });
    
    const secretInfo = await secretsManagerClient.send(describeCommand);
    
    // Find the previous version (AWSPREVIOUS)
    const previousVersionId = Object.keys(secretInfo.VersionIdsToStages || {}).find(versionId => 
      secretInfo.VersionIdsToStages[versionId].includes('AWSPREVIOUS')
    );
    
    if (!previousVersionId) {
      console.log('No previous version found, skipping timestamp labeling');
      return;
    }
    
    // Generate timestamp label
    const timestampLabel = generateTimestampLabel();
    console.log(`📅 Generated timestamp label: ${timestampLabel}`);
    
    // Add timestamp label to previous version (keeping AWSPREVIOUS as well)
    const updateCommand = new UpdateSecretVersionStageCommand({
      SecretId: secretName,
      VersionStage: timestampLabel,
      MoveToVersionId: previousVersionId
    });
    
    await secretsManagerClient.send(updateCommand);
    console.log(`✅ Previous version ${previousVersionId} labeled with ${timestampLabel}`);
    
    return timestampLabel;
  } catch (error) {
    console.warn(`⚠️  Warning: Failed to label previous version with timestamp: ${error.message}`);
    // Don't throw error here, continue with update
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
      console.log(`\n🔄 Starting secret update process for ${secretName}...`);
      
      // Step 1: Get current secret values
      console.log(`\n📥 Retrieving current values from ${secretName}...`);
      const currentValues = await getCurrentSecretValues(secretName);
      console.log('Current secret keys:', Object.keys(currentValues));
      
      // Step 2: Update the specific key
      currentValues[key] = value;
      console.log(`✏️  Updated key '${key}' in secret`);
      
      // Step 3: Save updated values back to secret (this creates new AWSCURRENT and moves old to AWSPREVIOUS)
      console.log(`\n💾 Saving updated values to ${secretName}...`);
      const command = new PutSecretValueCommand({
        SecretId: secretName,
        SecretString: JSON.stringify(currentValues, null, 2)
      });
      
      const response = await secretsManagerClient.send(command);
      console.log(`✅ Secret updated successfully in ${secretName}:`);
      console.log(`   - New version ID: ${response.VersionId}`);
      console.log(`   - New version labeled as AWSCURRENT`);
      
      // Step 4: Label the previous version with timestamp (now that it's AWSPREVIOUS)
      console.log(`\n🏷️  Adding timestamp label to previous version...`);
      await labelPreviousVersionWithTimestamp(secretName);
      
      console.log(`✅ Update process completed successfully!`);
      
      return response;
    } catch (error) {
      throw new Error(`Failed to update secret: ${error.message}`);
    }
  }

  async function listSecretVersions(secretName) {
    try {
      const command = new DescribeSecretCommand({
        SecretId: secretName
      });
      
      const response = await secretsManagerClient.send(command);
      
      console.log(`\n📚 Secret versions for ${secretName}:`);
      console.log('Version ID'.padEnd(36) + ' | ' + 'Labels');
      console.log('-'.repeat(50));
      
      for (const [versionId, stages] of Object.entries(response.VersionIdsToStages || {})) {
        console.log(`${versionId.padEnd(36)} | ${stages.join(', ')}`);
      }
      
      return response.VersionIdsToStages;
    } catch (error) {
      throw new Error(`Failed to list secret versions: ${error.message}`);
    }
  }
  
  module.exports = {
    getCurrentSecretValues,
    updateSecretValue,
    encryptWithKMS,
    listSecretVersions
  }