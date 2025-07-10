const { SecretsManagerClient, DescribeSecretCommand, UpdateSecretVersionStageCommand } = require('@aws-sdk/client-secrets-manager');
const { confirm } = require('@inquirer/prompts');

const secretsManagerClient = new SecretsManagerClient({ region: 'us-east-2' });

// Configuration
const DEFAULT_KEEP_COUNT = 10;
const DEFAULT_KEEP_DAYS = 7;
const AWS_REQUIRED_LABELS = ['AWSCURRENT', 'AWSPREVIOUS'];

function parseTimestampLabel(label) {
  // Parse timestamp labels like "20250709_143530"
  const match = label.match(/^(\d{8})_(\d{6})$/);
  if (match) {
    const [, dateStr, timeStr] = match;
    const year = parseInt(dateStr.substring(0, 4));
    const month = parseInt(dateStr.substring(4, 6)) - 1; // JavaScript months are 0-indexed
    const day = parseInt(dateStr.substring(6, 8));
    const hour = parseInt(timeStr.substring(0, 2));
    const minute = parseInt(timeStr.substring(2, 4));
    const second = parseInt(timeStr.substring(4, 6));
    
    return new Date(year, month, day, hour, minute, second);
  }
  return null;
}

function isTimestampLabel(label) {
  return /^\d{8}_\d{6}$/.test(label);
}

async function getSecretVersions(secretName) {
  try {
    const command = new DescribeSecretCommand({
      SecretId: secretName
    });
    
    const response = await secretsManagerClient.send(command);
    return response.VersionIdsToStages || {};
  } catch (error) {
    throw new Error(`Failed to get secret versions: ${error.message}`);
  }
}

async function listVersions(secretName) {
  console.log(`\n📚 Listing versions for secret: ${secretName}`);
  
  const versions = await getSecretVersions(secretName);
  
  if (Object.keys(versions).length === 0) {
    console.log('No versions found for this secret.');
    return;
  }
  
  console.log('\n' + 'Version ID'.padEnd(36) + ' | ' + 'Labels'.padEnd(30) + ' | Status');
  console.log('-'.repeat(80));
  
  let totalLabels = 0;
  const timestampLabels = [];
  
  for (const [versionId, labels] of Object.entries(versions)) {
    const labelStr = labels.join(', ');
    let status = '';
    
    if (labels.includes('AWSCURRENT')) {
      status = '🟢 CURRENT';
    } else if (labels.includes('AWSPREVIOUS')) {
      status = '🟡 PREVIOUS';
    } else if (labels.some(isTimestampLabel)) {
      status = '🔵 TIMESTAMPED';
      timestampLabels.push(...labels.filter(isTimestampLabel));
    } else {
      status = '⚪ UNLABELED';
    }
    
    console.log(`${versionId.padEnd(36)} | ${labelStr.padEnd(30)} | ${status}`);
    totalLabels += labels.length;
  }
  
  console.log('-'.repeat(80));
  console.log(`📊 Summary:`);
  console.log(`   Total versions: ${Object.keys(versions).length}`);
  console.log(`   Total labels: ${totalLabels}`);
  console.log(`   Timestamp labels: ${timestampLabels.length}`);
  console.log(`   Available label slots: ${20 - totalLabels}`);
  
  if (totalLabels >= 18) {
    console.log(`\n⚠️  WARNING: You have ${totalLabels} labels (approaching limit of 20)`);
    console.log(`   Consider cleaning up old timestamp labels.`);
  }
  
  return versions;
}

async function countLabels(secretName) {
  const versions = await getSecretVersions(secretName);
  let totalLabels = 0;
  
  for (const labels of Object.values(versions)) {
    totalLabels += labels.length;
  }
  
  console.log(`\n📊 Label count for ${secretName}:`);
  console.log(`   Total labels: ${totalLabels}/20`);
  console.log(`   Available slots: ${20 - totalLabels}`);
  
  return totalLabels;
}

function identifyVersionsToCleanup(versions, keepCount = DEFAULT_KEEP_COUNT, keepDays = DEFAULT_KEEP_DAYS, strict = false) {
  const toRemoveLabels = [];
  const toDeleteVersions = [];
  const timestampVersions = [];
  
  // Find all versions with timestamp labels
  for (const [versionId, labels] of Object.entries(versions)) {
    // Skip required AWS labels
    if (labels.includes('AWSCURRENT') || labels.includes('AWSPREVIOUS')) {
      continue;
    }
    
    const timestampLabels = labels.filter(isTimestampLabel);
    
    if (timestampLabels.length > 0) {
      for (const label of timestampLabels) {
        const timestamp = parseTimestampLabel(label);
        if (timestamp) {
          timestampVersions.push({
            versionId,
            label,
            timestamp,
            allLabels: labels
          });
        }
      }
    } else if (labels.length === 0) {
      // Unlabeled version - safe to delete
      toDeleteVersions.push(versionId);
    }
  }
  
  // Sort by timestamp (newest first)
  timestampVersions.sort((a, b) => b.timestamp - a.timestamp);
  
  // Keep recent versions based on count
  const versionsToKeep = timestampVersions.slice(0, keepCount);
  const versionsToCleanup = timestampVersions.slice(keepCount);
  
  console.log(`   - Will keep ${versionsToKeep.length} most recent timestamp versions`);
  console.log(`   - Will cleanup ${versionsToCleanup.length} older timestamp versions`);
  
  // Apply days filter only if not in strict mode
  if (!strict && keepDays > 0) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - keepDays);
    
    // Filter out versions that are too recent to delete
    const finalVersionsToCleanup = versionsToCleanup.filter(version => {
      const shouldKeepByDays = version.timestamp > cutoffDate;
      if (shouldKeepByDays) {
        console.log(`   - Keeping ${version.label} (within ${keepDays} days, not in strict mode)`);
        return false; // Don't cleanup this version
      }
      return true; // Cleanup this version
    });
    
    console.log(`   - After days filter: ${finalVersionsToCleanup.length} versions to cleanup`);
    
    // Mark versions for cleanup
    for (const version of finalVersionsToCleanup) {
      toRemoveLabels.push({
        versionId: version.versionId,
        label: version.label
      });
      
      // If removing this label leaves the version unlabeled, mark for deletion
      const remainingLabels = version.allLabels.filter(l => 
        l !== version.label && !AWS_REQUIRED_LABELS.includes(l)
      );
      
      if (remainingLabels.length === 0) {
        toDeleteVersions.push(version.versionId);
      }
    }
  } else {
    // Strict mode or no days filter - cleanup all versions beyond keepCount
    for (const version of versionsToCleanup) {
      // Remove timestamp label from this version
      toRemoveLabels.push({
        versionId: version.versionId,
        label: version.label
      });
      
      // If removing this label leaves the version unlabeled, mark for deletion
      const remainingLabels = version.allLabels.filter(l => 
        l !== version.label && !AWS_REQUIRED_LABELS.includes(l)
      );
      
      if (remainingLabels.length === 0) {
        toDeleteVersions.push(version.versionId);
      }
    }
  }
  
  return {
    toRemoveLabels,
    toDeleteVersions,
    versionsToKeep: versionsToKeep.length,
    versionsToCleanup: versionsToCleanup.length
  };
}

async function removeLabelFromVersion(secretName, versionId, label) {
  try {
    const command = new UpdateSecretVersionStageCommand({
      SecretId: secretName,
      VersionStage: label,
      RemoveFromVersionId: versionId
    });
    
    await secretsManagerClient.send(command);
    console.log(`✅ Removed label "${label}" from version ${versionId.substring(0, 8)}...`);
  } catch (error) {
    console.error(`❌ Failed to remove label "${label}" from version ${versionId.substring(0, 8)}...: ${error.message}`);
  }
}

async function cleanupVersions(secretName, options = {}) {
  const {
    keepCount = DEFAULT_KEEP_COUNT,
    keepDays = DEFAULT_KEEP_DAYS,
    dryRun = false,
    force = false,
    strict = false
  } = options;
  
  console.log(`\n🧹 Starting cleanup for secret: ${secretName}`);
  console.log(`   Keep count: ${keepCount}`);
  console.log(`   Keep days: ${keepDays}`);
  console.log(`   Strict mode: ${strict ? 'Yes (ignore days filter)' : 'No'}`);
  console.log(`   Dry run: ${dryRun ? 'Yes' : 'No'}`);
  
  const versions = await getSecretVersions(secretName);
  const cleanup = identifyVersionsToCleanup(versions, keepCount, keepDays, strict);
  
  console.log(`\n📋 Cleanup Plan:`);
  console.log(`   Labels to remove: ${cleanup.toRemoveLabels.length}`);
  console.log(`   Versions to delete: ${cleanup.toDeleteVersions.length}`);
  console.log(`   Versions to keep: ${cleanup.versionsToKeep}`);
  
  if (cleanup.toRemoveLabels.length === 0 && cleanup.toDeleteVersions.length === 0) {
    console.log('\n✅ No cleanup needed - all versions are within retention policy.');
    return;
  }
  
  // Show what will be cleaned up
  if (cleanup.toRemoveLabels.length > 0) {
    console.log(`\n🏷️  Labels to remove:`);
    for (const item of cleanup.toRemoveLabels) {
      console.log(`   - ${item.label} from ${item.versionId.substring(0, 8)}...`);
    }
  }
  
  if (cleanup.toDeleteVersions.length > 0) {
    console.log(`\n🗑️  Versions to delete:`);
    for (const versionId of cleanup.toDeleteVersions) {
      console.log(`   - ${versionId.substring(0, 8)}... (unlabeled)`);
    }
  }
  
  // Confirm if not in force mode
  if (!dryRun && !force) {
    const confirmed = await confirm({
      message: 'Do you want to proceed with the cleanup?',
      default: false
    });
    
    if (!confirmed) {
      console.log('❌ Cleanup cancelled by user.');
      return;
    }
  }
  
  if (dryRun) {
    console.log('\n🔍 DRY RUN - No actual changes made.');
    return;
  }
  
  // Execute cleanup
  console.log('\n🔄 Executing cleanup...');
  
  // Remove labels
  for (const item of cleanup.toRemoveLabels) {
    await removeLabelFromVersion(secretName, item.versionId, item.label);
  }
  
  // Note: AWS Secrets Manager doesn't support direct version deletion
  // Versions without labels become inaccessible and are cleaned up automatically
  if (cleanup.toDeleteVersions.length > 0) {
    console.log(`\n📝 Note: ${cleanup.toDeleteVersions.length} unlabeled versions will be automatically cleaned up by AWS.`);
  }
  
  console.log('\n✅ Cleanup completed successfully!');
  
  // Show final state
  await listVersions(secretName);
}

function showUsage() {
  console.log(`
🛠️  AWS Secrets Manager Version Cleanup Tool

Usage:
  node cleanupSecretVersions.js <command> <secret-name> [options]

Commands:
  list      List all versions and their labels
  count     Show label count and available slots
  cleanup   Clean up old versions and labels

Options:
  --keep N      Keep N most recent timestamp labels (default: ${DEFAULT_KEEP_COUNT})
  --days N      Keep labels newer than N days (default: ${DEFAULT_KEEP_DAYS})
  --strict      Ignore days filter, strictly keep only N versions
  --dry-run     Show what would be deleted without making changes
  --force       Skip confirmation prompts

Examples:
  node cleanupSecretVersions.js list dev/web3-auth/auth-service-api
  node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5
  node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5 --strict
  node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --dry-run
  node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --force
`);
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    showUsage();
    return;
  }
  
  const command = args[0];
  const secretName = args[1];
  
  if (!secretName) {
    console.error('❌ Error: Secret name is required');
    showUsage();
    return;
  }
  
  // Parse options
  const options = {};
  for (let i = 2; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--dry-run') {
      options.dryRun = true;
    } else if (arg === '--force') {
      options.force = true;
    } else if (arg === '--strict') {
      options.strict = true;
    } else if (arg === '--keep' && i + 1 < args.length) {
      options.keepCount = parseInt(args[++i]);
    } else if (arg === '--days' && i + 1 < args.length) {
      options.keepDays = parseInt(args[++i]);
    }
  }
  
  try {
    switch (command) {
      case 'list':
        await listVersions(secretName);
        break;
      case 'count':
        await countLabels(secretName);
        break;
      case 'cleanup':
        await cleanupVersions(secretName, options);
        break;
      default:
        console.error(`❌ Unknown command: ${command}`);
        showUsage();
    }
  } catch (error) {
    console.error(`❌ Error: ${error.message}`);
    process.exit(1);
  }
}

// Run the script
main(); 