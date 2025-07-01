
const { input, select, confirm } = require('@inquirer/prompts');
const { updateSecretValue, encryptWithKMS } = require('./secretManager');


async function promptForInputs() {
    console.log('Google Client Secret Rotation Tool\n');
    
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
        { name: 'Production', value: 'prod' },
        { name: 'UAT', value: 'uat' }
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
    const webClientSecret = await input({
      message: `Enter ${app.toUpperCase()} Google Web Client Secret:`,
      validate: (input) => input.trim() !== '' || 'Client Secret cannot be empty'
    });
    
    return {
      environment,
      app,
      config: {
        webClientSecret,
      }
    };
}
  

async function main() {
    const { environment, app, config } = await promptForInputs();
    const secretName = `${environment}/web3-auth/auth-service-api`;
    const secretKey = `${app.toUpperCase()}_GOOGLE_WEB_CLIENT_SECRET`;
  // Encrypt secret with KMS
  const kmsAlias = `alias/mmcx/${environment}/auth-service`;
  console.log(`🔒 Encrypting token with KMS alias: ${kmsAlias}`);
  const encryptedClientSecret = await encryptWithKMS(config.webClientSecret, kmsAlias);
  console.log('✅ Token encrypted successfully');
  await updateSecretValue(secretName, secretKey, encryptedClientSecret);
}

main()
  .then(result => {
    console.log('Secret updated successfully');
  })
  .catch(error => {
    console.error('Error:', error);
  });   