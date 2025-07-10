# AWS Secrets Manager Version Management Guide

## 🚨 QUICK FIX - Maximum Staging Labels Exceeded

**IMMEDIATE ACTION REQUIRED** when you see this error:
```
⚠️  Warning: Failed to label previous version with timestamp: You exceeded the maximum number of staging labels allowed on a secret.
```

### Emergency Cleanup (30 seconds)

1. **Check Current State**
   ```bash
   node cleanupSecretVersions.js list dev/web3-auth/auth-service-api
   ```

2. **Emergency Cleanup (Keep Only 5 Recent)**
   ```bash
   node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5 --strict --force
   ```

3. **Verify Cleanup**
   ```bash
   node cleanupSecretVersions.js count dev/web3-auth/auth-service-api
   ```

### What This Emergency Fix Does

- ✅ **Keeps AWSCURRENT & AWSPREVIOUS** (required by AWS)
- ✅ **Keeps 5 most recent timestamp labels** (for rollback)
- ✅ **Removes older timestamp labels** (frees up space)
- ✅ **Ignores recency filter** (--strict flag forces count limit)
- ✅ **Automatically confirms** (--force flag)

### Expected Result

**Before:**
```
Total labels: 20+/20 (OVER LIMIT)
Available slots: negative
```

**After:**
```
Total labels: 7/20
Available slots: 13
```

### Resume Your Work

After cleanup, run your JWT generation again:
```bash
node initiateJwtPriv.js
```

**It should now work without the "maximum staging labels" error!**

### Safe Alternative (If You Want to See Changes First)

If you want to preview what will be deleted before making changes:

```bash
# 1. See what would be deleted
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5 --strict --dry-run

# 2. If looks good, run for real
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5 --strict
```

---

## 📋 Complete Version Management Guide

### Problem: Maximum Staging Labels Exceeded

AWS Secrets Manager has a **maximum of 20 staging labels** per secret. When you see this error, it means you've hit the limit and need to clean up old versions.

## 📋 AWS Limits

- **Maximum staging labels per secret**: 20
- **Maximum versions per secret**: 100
- **Required labels**: `AWSCURRENT`, `AWSPREVIOUS` (cannot be deleted)
- **Available for custom labels**: 18 timestamp labels

## 🔍 Understanding Version Management

### Version States:
- **AWSCURRENT**: Latest active version (required)
- **AWSPREVIOUS**: Second-to-latest version (required)
- **Timestamp labels**: Custom labels like `20250709_143530`
- **Unlabeled**: Versions without any staging labels

### Cleanup Strategy:
1. **Keep AWSCURRENT and AWSPREVIOUS** (required by AWS)
2. **Keep recent timestamp labels** (for rollback capability)
3. **Remove oldest timestamp labels** (free up space)
4. **Delete unlabeled versions** (no longer accessible)

## 🧹 Cleanup Methods

### Method 1: Manual Cleanup (AWS Console)
1. Go to AWS Secrets Manager console
2. Select your secret
3. Click "Retrieve secret value"
4. Go to "Versions" tab
5. Select versions with old timestamp labels
6. Click "Delete version"

### Method 2: AWS CLI
```bash
# List all versions
aws secretsmanager describe-secret --secret-id "your-secret-name"

# Delete a specific version
aws secretsmanager delete-secret --secret-id "your-secret-name" --version-id "VERSION_ID"

# Remove staging label from version
aws secretsmanager update-secret-version-stage \
  --secret-id "your-secret-name" \
  --version-stage "20250709_143530" \
  --remove-from-version-id "VERSION_ID"
```

### Method 3: Node.js Script (Recommended)
Use the provided cleanup script: `cleanupSecretVersions.js`

## 🛠️ Automated Cleanup Script

The cleanup script will:
- ✅ List all versions and their labels
- ✅ Identify versions safe to delete
- ✅ Remove old timestamp labels
- ✅ Delete unlabeled versions
- ✅ Preserve AWSCURRENT and AWSPREVIOUS
- ✅ Keep recent timestamp labels (configurable)

## 🚀 Usage Instructions

### 1. List Current Versions
```bash
node cleanupSecretVersions.js list dev/web3-auth/auth-service-api
```

### 2. Clean Up Automatically
```bash
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api
```

### 3. Custom Cleanup (keep last 5 timestamp labels)
```bash
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5
```

### 4. Strict Mode Cleanup (when hitting 20-label limit)
```bash
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 5 --strict
```

> **💡 When to use `--strict`:** Use when you're hitting the 20-label limit and all your timestamps are recent (same day). The `--strict` flag forces the count limit regardless of how recent the versions are.

## ⚠️ Important Safety Notes

### DO NOT Delete:
- ❌ Versions with `AWSCURRENT` label
- ❌ Versions with `AWSPREVIOUS` label
- ❌ Recently created versions (within last 24 hours)

### Safe to Delete:
- ✅ Versions with old timestamp labels (older than X days)
- ✅ Versions with no staging labels
- ✅ Duplicate versions (same content)

## 📊 Best Practices

### 1. Regular Cleanup Schedule
- **Weekly**: Review and clean up old versions
- **Monthly**: Deep cleanup of timestamp labels
- **Before major updates**: Clean up to make room

### 2. Retention Policy
- **Keep AWSCURRENT + AWSPREVIOUS**: Always (required)
- **Keep recent 7 days**: For quick rollback
- **Keep weekly snapshots**: For long-term recovery
- **Delete everything else**: To free up space

### 3. Monitoring
- Monitor the number of staging labels
- Set up alerts when approaching 20 labels
- Track version creation frequency

## 🔧 Configuration Options

### Environment Variables
```bash
export AWS_REGION=us-east-2
export SECRET_CLEANUP_KEEP_DAYS=7
export SECRET_CLEANUP_KEEP_COUNT=10
```

### Script Parameters
- `--keep N`: Keep N most recent timestamp labels
- `--days N`: Keep labels newer than N days
- `--strict`: Ignore days filter, strictly keep only N versions (use when hitting limits)
- `--dry-run`: Show what would be deleted (don't actually delete)
- `--force`: Skip confirmation prompts

## 🎯 Quick Reference

### Check Current Count
```bash
node cleanupSecretVersions.js count dev/web3-auth/auth-service-api
```

### Emergency Cleanup (keep only 3 recent, strict mode)
```bash
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --keep 3 --strict --force
```

### Safe Dry Run
```bash
node cleanupSecretVersions.js cleanup dev/web3-auth/auth-service-api --strict --dry-run
```

## 🆘 Troubleshooting

### Error: "Cannot delete version with AWSCURRENT"
- You're trying to delete the current version
- Solution: Never delete AWSCURRENT or AWSPREVIOUS

### Error: "Version not found"
- Version ID doesn't exist
- Solution: Use `list` command to get correct version IDs

### Error: "Access denied"
- Missing IAM permissions
- Solution: Ensure you have `secretsmanager:DeleteSecret` permission

## 📞 Support

If you encounter issues:
1. Run with `--dry-run` flag first
2. Check AWS IAM permissions
3. Verify secret name is correct
4. Review the cleanup logs

---

**⚠️ Always backup important secrets before cleanup!** 