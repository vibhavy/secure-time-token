const crypto = require('crypto');

class ScureTimeToken {
    constructor() {
        if (ScureTimeToken.instance) {
            return ScureTimeToken.instance; // Ensure singleton behavior
        }
        this.decodedPayload = null;

        // Bind methods to ensure `this` remains the class instance
        this.generateToken = this.generateToken.bind(this);
        this.validateToken = this.validateToken.bind(this);
        this.getDecodedPayload = this.getDecodedPayload.bind(this);

        ScureTimeToken.instance = this;
    }

    /**
     * Generate a token with a specified TTL (in seconds).
     * The token contains a payload that includes an expiration time and optional additional data,
     * signed using HMAC for integrity and security.
     *
     * @param {number} ttlInSeconds - Time-to-live for the token in seconds.
     * @param {string} secretKey - Secret key used to sign the token.
     * @param {object} options - Additional optional payload data to include in the token.
     * @returns {string} A string representing the generated token.
     */
    generateToken(ttlInSeconds, secretKey, options = {}) {
        const currentTime = Math.floor(Date.now() / 1000); // Current time in seconds
        const expirationTime = currentTime + ttlInSeconds;

        let payload = { exp: expirationTime };
        if (Object.keys(options).length > 0) {
            payload = { ...payload, ...options };
        }

        const strPayload = JSON.stringify(payload);
        const signature = crypto.createHmac('sha256', secretKey).update(strPayload).digest('hex');
        const token = Buffer.from(strPayload).toString('base64') + '.' + signature;

        return token;
    }

    /**
     * Validate a token by verifying its HMAC signature and checking if it has expired.
     * If the token is valid, the payload is stored in the class instance for further use.
     *
     * @param {string} token - The token to validate, in the format "payload.signature".
     * @param {string} secretKey - Secret key used to verify the token's HMAC signature.
     * @returns {boolean} Returns true if the token is valid.
     * @throws {Error} Throws an error if the token format is invalid, the signature is incorrect, or the token has expired.
     */
    validateToken(token, secretKey) {
        try {
            const [encodedPayload, signature] = token.split('.');
            if (!encodedPayload || !signature) {
                throw new Error('Invalid token format');
            }

            const decodedPayload = Buffer.from(encodedPayload, 'base64').toString('utf8');
            const payload = JSON.parse(decodedPayload);
            const expectedSignature = crypto.createHmac('sha256', secretKey).update(decodedPayload).digest('hex');

            if (signature !== expectedSignature) {
                throw new Error('Invalid token signature');
            }

            const currentTimestamp = Math.floor(Date.now() / 1000);
            if (currentTimestamp > payload.exp) {
                throw new Error('Token has expired');
            }

            this.decodedPayload = payload;
            return true;
        } catch (error) {
            throw error;
        }
    }

    /**
     * Retrieve the most recently decoded payload from the last validated token.
     *
     * @returns {object|null} The payload object of the last validated token, or null if no token has been validated yet.
     */
    getDecodedPayload() {
        return this.decodedPayload;
    }
}

// Export a single instance of the ScureTimeToken class (singleton pattern)
module.exports = new ScureTimeToken();
