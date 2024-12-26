const crypto = require('crypto');

/**
 * Generate a token with a specified TTL (in seconds).
 * The token contains a payload with expiration time and is signed using HMAC.
 * @param {number} ttlInSeconds - Time-to-live for the token in seconds.
 * @param {string} secretKey - Secret key used to sign the token.
 * @returns {string} Generated token.
 */
function generateToken(ttlInSeconds, secretKey) {
    const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
    const expirationTime = currentTime + ttlInSeconds;

    // Payload containing the expiration time
    const payload = JSON.stringify({ exp: expirationTime });
    const signature = crypto.createHmac('sha256', secretKey).update(payload).digest('hex');

    // Combine payload and signature
    const token = Buffer.from(payload).toString('base64') + '.' + signature;

    return token;
}

/**
 * Validate a token by verifying its signature and checking its expiration.
 * @param {string} token - Token to validate.
 * @param {string} secretKey - Secret key used to verify the token.
 * @returns {boolean} True if the token is valid.
 * @throws {Error} If the token is invalid or expired.
 */
function validateToken(token, secretKey) {
    try {
        const [encodedPayload, signature] = token.split('.');

        if (!encodedPayload || !signature) {
            throw new Error('Invalid token format');
        }

        const decodedPayload = Buffer.from(encodedPayload, 'base64').toString('utf8');

        // Decode the payload
        const payload = JSON.parse(decodedPayload);

        // Recalculate the signature
        const expectedSignature = crypto.createHmac('sha256', secretKey).update(decodedPayload).digest('hex');

        if (signature !== expectedSignature) {
            throw new Error('Invalid token signature');
        }

        // Check token expiration
        const currentTimestamp = Math.floor(Date.now() / 1000);
        if (currentTimestamp > payload.exp) {
            throw new Error('Token has expired');
        }

        return true; // Token is valid
    } catch (error) {
        throw error;
    }
}

module.exports = { generateToken, validateToken };
