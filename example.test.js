const { generateToken, validateToken, getDecodedPayload } = require('./index.js');

// Step 1: Generate a token
const secretKey = 'your-secure-secret-key';
const ttl = 120; // Token valid for 120 seconds
const token = generateToken(ttl, secretKey);
console.log('Generated Token:', token);

// Step 2: Validate the token
setTimeout(() => {
    try {
        const isValid = validateToken(token, secretKey);
        console.log('Token is valid:', isValid);

        const decodedPayload = getDecodedPayload();
        console.log('decoded payload:', decodedPayload);

    } catch (error) {
        console.error('Token validation failed:', error.message);
    }
}, 100000); // Validate after 100 seconds

// Step 3: Attempt to validate after token expiration
setTimeout(() => {
    try {
        const isValid = validateToken(token, secretKey);
        console.log('Token is valid:', isValid);
    } catch (error) {
        console.error('Token validation failed:', error.message);
    }
}, 130000); // Validate after 130 seconds (token expired)