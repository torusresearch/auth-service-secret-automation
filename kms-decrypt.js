/* eslint-disable @typescript-eslint/no-var-requires */
const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms')
const jwt = require('jsonwebtoken')

// Configuration
const AWS_REGION = process.env.AWS_REGION || 'us-east-2'
const TIME_REMAINING_THRESHOLD = {
  P1: parseInt(process.env.TIME_REMAINING_THRESHOLD_DAYS_P1, 10) || 7,
  P2: parseInt(process.env.TIME_REMAINING_THRESHOLD_DAYS_P2, 10) || 15,
  P3: parseInt(process.env.TIME_REMAINING_THRESHOLD_DAYS_P3, 10) || 30,
}

// Initialize AWS KMS client
const kmsClient = new KMSClient({
  region: AWS_REGION,
})

/**
 * Decrypts an encrypted value using AWS KMS
 * @param {string} encryptedValue - Base64 encoded encrypted value
 * @returns {Promise<string>} - Decrypted plaintext value
 */
async function decryptWithKMS(encryptedValue) {
  try {
    console.log('Starting KMS decryption...')

    // Convert base64 string to buffer for KMS
    const encryptedBuffer = Buffer.from(encryptedValue, 'base64')

    const command = new DecryptCommand({
      CiphertextBlob: encryptedBuffer,
      // KeyId is not needed - KMS can determine the key from the encrypted data
    })

    const response = await kmsClient.send(command)

    if (!response.Plaintext) {
      throw new Error('Decryption returned empty result')
    }

    const decryptedValue = Buffer.from(response.Plaintext).toString('utf-8')
    console.log('KMS decryption completed successfully')
    return decryptedValue
  } catch (error) {
    console.error('Error decrypting with KMS:', error.message)
    throw error
  }
}

/**
 * Decodes a JWT token without verification (for inspection purposes)
 * @param {string} token - JWT token string to decode
 * @returns {object} - Object containing header, payload, and signature information
 */
function decodeJWT(token) {
  try {
    // Decode without verification (for inspection only)
    const decoded = jwt.decode(token, { complete: true })

    if (!decoded) {
      throw new Error('Invalid JWT token format')
    }

    // Parse timestamps if they exist
    if (decoded.payload.exp) {
      decoded.payload.expFormatted = new Date(
        decoded.payload.exp * 1000,
      ).toISOString()
    }

    if (decoded.payload.iat) {
      decoded.payload.iatFormatted = new Date(
        decoded.payload.iat * 1000,
      ).toISOString()
    }

    return {
      header: decoded.header,
      payload: decoded.payload,
      signature: decoded.signature,
      raw: token,
    }
  } catch (error) {
    console.error('Error decoding JWT:', error.message)
    throw error
  }
}

/**
 * Analyzes JWT expiration and provides priority alerts
 * @param {object} jwtData - Decoded JWT data containing payload with exp timestamp
 * @returns {object} - Object containing time analysis and alert information
 */
function analyzeJWTExpiration(jwtData) {
  try {
    if (!jwtData.payload.exp) {
      return {
        hasExpiration: false,
        message: 'No expiration timestamp found in JWT',
      }
    }

    const now = new Date()
    const expiresAt = new Date(jwtData.payload.exp * 1000)
    const isExpired = now > expiresAt

    if (isExpired) {
      const daysExpired = Math.floor((now - expiresAt) / (1000 * 60 * 60 * 24))
      return {
        hasExpiration: true,
        isExpired: true,
        daysExpired,
        alertLevel: 'CRITICAL',
        status: 'EXPIRED',
        message: `Token expired ${daysExpired} days ago`,
        expiresAt: expiresAt.toISOString(),
      }
    }

    // Calculate time remaining
    const timeRemainingMs = expiresAt - now
    const daysRemaining = Math.floor(timeRemainingMs / (1000 * 60 * 60 * 24))

    // Determine alert level based on days remaining
    let alertLevel = 'NONE'
    let status = 'VALID'
    let alertMessage = ''

    if (daysRemaining < TIME_REMAINING_THRESHOLD.P1) {
      alertLevel = 'P1'
      status = 'P1 ALERT'
      alertMessage = `P1: Token expires in less than ${TIME_REMAINING_THRESHOLD.P1} days!`
    } else if (daysRemaining < TIME_REMAINING_THRESHOLD.P2) {
      alertLevel = 'P2'
      status = 'P2 ALERT'
      alertMessage = `P2: Token expires in less than ${TIME_REMAINING_THRESHOLD.P2} days!`
    } else if (daysRemaining < TIME_REMAINING_THRESHOLD.P3) {
      alertLevel = 'P3'
      status = 'P3 ALERT'
      alertMessage = `P3: Token expires in less than ${TIME_REMAINING_THRESHOLD.P3} days!`
    }

    return {
      hasExpiration: true,
      isExpired: false,
      daysRemaining,
      alertLevel,
      status,
      alertMessage,
      expiresAt: expiresAt.toISOString(),
    }
  } catch (error) {
    console.error('Error analyzing JWT expiration:', error.message)
    throw error
  }
}

/**
 * Checks if a string appears to be a JWT token
 * @param {string} value - String to check
 * @returns {boolean} - True if the string looks like a JWT
 */
function isJWT(value) {
  // JWT tokens have 3 parts separated by dots
  const parts = value.split('.')
  return parts.length === 3 && parts.every((part) => part.length > 0)
}

/**
 * Displays usage information
 */
function showUsage() {
  console.log('Usage:')
  console.log(
    '  Environment Variable: Set ENCRYPTED_VALUE environment variable',
  )
  console.log(
    '  Command Line Argument: node kms-decrypt.js <base64-encrypted-value>',
  )
  console.log(
    '  Standard Input: echo "<base64-encrypted-value>" | node kms-decrypt.js',
  )
  console.log('')
  console.log('Environment Variables:')
  console.log(
    '  ENCRYPTED_VALUE                    - Base64 encoded encrypted value to decrypt',
  )
  console.log(
    '  AWS_REGION                         - AWS region (default: us-east-2)',
  )
  console.log(
    '  TIME_REMAINING_THRESHOLD_DAYS_P1   - P1 alert threshold days (default: 7)',
  )
  console.log(
    '  TIME_REMAINING_THRESHOLD_DAYS_P2   - P2 alert threshold days (default: 15)',
  )
  console.log(
    '  TIME_REMAINING_THRESHOLD_DAYS_P3   - P3 alert threshold days (default: 180)',
  )
  console.log('')
  console.log('Features:')
  console.log('  - Decrypts base64 encoded KMS encrypted values')
  console.log('  - Automatically detects and analyzes JWT tokens')
  console.log('  - Provides expiration alerts for JWT tokens')
  console.log('  - Outputs everything in clean JSON format')
  console.log('  - Comprehensive logging and error handling')
  console.log('')
  console.log('Examples:')
  console.log('  export ENCRYPTED_VALUE="AQICAHi..." && node kms-decrypt.js')
  console.log('  node kms-decrypt.js "AQICAHi..."')
  console.log('  echo "AQICAHi..." | node kms-decrypt.js')
}

/**
 * Gets encrypted value from various input sources
 */
function getEncryptedValue() {
  // Priority: Command line argument > Environment variable > stdin
  if (process.argv[2]) {
    console.log('Using encrypted value from command line argument')
    return process.argv[2].trim()
  }

  if (process.env.ENCRYPTED_VALUE) {
    console.log(
      'Using encrypted value from ENCRYPTED_VALUE environment variable',
    )
    return process.env.ENCRYPTED_VALUE.trim()
  }

  return null
}

/**
 * Reads from stdin if available
 */
function readFromStdin() {
  return new Promise((resolve, reject) => {
    let data = ''

    // Check if stdin has data
    if (process.stdin.isTTY) {
      resolve(null) // No stdin data available
      return
    }

    process.stdin.setEncoding('utf8')

    process.stdin.on('data', (chunk) => {
      data += chunk
    })

    process.stdin.on('end', () => {
      resolve(data.trim() || null)
    })

    process.stdin.on('error', (error) => {
      reject(error)
    })

    // Set a timeout to avoid hanging
    setTimeout(() => {
      resolve(null)
    }, 1000)
  })
}

/**
 * Validates the encrypted value format
 */
function validateEncryptedValue(value) {
  if (!value) {
    return false
  }

  // Check if it's a valid base64 string
  try {
    const buffer = Buffer.from(value, 'base64')
    return (
      buffer.length > 0 &&
      Buffer.from(buffer.toString('base64'), 'base64').equals(buffer)
    )
  } catch (error) {
    return false
  }
}

/**
 * Main function to decrypt encrypted values
 */
async function main() {
  try {
    console.log('=== KMS Decryption Tool ===')
    console.log(`AWS Region: ${AWS_REGION}`)
    console.log('')

    // Handle help request
    if (process.argv.includes('--help') || process.argv.includes('-h')) {
      showUsage()
      process.exit(0)
    }

    // Get encrypted value from various sources
    let encryptedValue = getEncryptedValue()

    // If no command line arg or env var, try stdin
    if (!encryptedValue) {
      console.log(
        'No command line argument or environment variable found, checking stdin...',
      )
      encryptedValue = await readFromStdin()
    }

    // Validate we have an encrypted value
    if (!encryptedValue) {
      console.error('No encrypted value provided')
      showUsage()
      process.exit(1)
    }

    console.log('Using encrypted value from stdin')

    // Validate the encrypted value format
    if (!validateEncryptedValue(encryptedValue)) {
      throw new Error(
        'Invalid encrypted value format. Expected base64 encoded string.',
      )
    }

    console.log('Encrypted value format validation passed')

    // Decrypt the value using KMS
    const decryptedValue = await decryptWithKMS(encryptedValue)

    // Prepare the base result
    const result = {
      success: true,
      decryptedValue: decryptedValue,
      timestamp: new Date().toISOString(),
      isJWT: false,
      jwtAnalysis: null,
    }

    // Check if the decrypted value is a JWT token and analyze it
    if (isJWT(decryptedValue)) {
      result.isJWT = true

      try {
        // Decode JWT token
        const jwtData = decodeJWT(decryptedValue)

        console.log('JWT data:', jwtData)

        // Analyze expiration
        const expirationAnalysis = analyzeJWTExpiration(jwtData)

        // Add JWT analysis to result
        result.jwtAnalysis = {
          tokenInfo: {
            algorithm: jwtData.header?.alg,
            type: jwtData.header?.typ,
            audience: jwtData.payload?.aud,
            subject: jwtData.payload?.sub,
            issuedAt: jwtData.payload?.iatFormatted || null,
          },
          expiration: {
            hasExpiration: expirationAnalysis.hasExpiration,
            expiresAt: expirationAnalysis.expiresAt || null,
            isExpired: expirationAnalysis.isExpired || false,
            daysRemaining: expirationAnalysis.daysRemaining || null,
            daysExpired: expirationAnalysis.daysExpired || null,
            status: expirationAnalysis.status,
            alertLevel: expirationAnalysis.alertLevel,
            alertMessage: expirationAnalysis.alertMessage || null,
          },
        }
      } catch (jwtError) {
        result.jwtAnalysis = {
          error: `Failed to analyze JWT: ${jwtError.message}`,
        }
      }
    }

    // Output the complete result as clean JSON
    console.log(JSON.stringify(result, null, 2))
  } catch (error) {
    console.error('Script failed:', error.message)
    process.exit(1)
  }
}

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error.message)
  process.exit(1)
})

process.on('unhandledRejection', (reason) => {
  console.error('Unhandled Rejection:', reason)
  process.exit(1)
})

// Run the script if called directly
if (require.main === module) {
  main().catch((error) => {
    console.error('Fatal error:', error.message)
    process.exit(1)
  })
}

module.exports = {
  decryptWithKMS,
  validateEncryptedValue,
  decodeJWT,
  analyzeJWTExpiration,
  isJWT,
}
