const { SecretsManagerClient, PutSecretValueCommand, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
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
  
  module.exports = {
    getCurrentSecretValues,
    updateSecretValue,
    encryptWithKMS
  }