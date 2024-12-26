# Token Generator and Validator

This project provides a lightweight module to generate and validate time-based secure tokens. The tokens are signed using HMAC for integrity and support a configurable time-to-live (TTL) mechanism to ensure tokens expire after a defined duration.

## Features

- Generate secure, time-based tokens with customizable TTL.
- Validate tokens and verify their expiration.
- Simple and lightweight implementation using Node.js.

---

## Installation

To install this module, clone the repository or include it in your project directly:

```bash
npm install secure-time-token
```

---

## Usage

### Import the Module

```javascript
const { generateToken, validateToken } = require('secure-time-token');
```

### Generate a Token

Use the `generateToken` function to create a secure token with a specified TTL (in seconds).

```javascript
const secretKey = 'your-secure-secret-key'; // Replace with your secure secret key
const ttlInSeconds = 60; // Token will expire in 60 seconds

const token = generateToken(ttlInSeconds, secretKey);
console.log('Generated Token:', token);
```

### Validate a Token

Use the `validateToken` function to verify the token's signature and expiration.

```javascript
try {
    const isValid = validateToken(token, secretKey);
    console.log('Token is valid:', isValid);
} catch (error) {
    console.error('Token validation failed:', error.message);
}
```

---

## Example Workflow

```javascript
const { generateToken, validateToken } = require('secure-time-token');

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
```

---

## Notes

1. **Secret Key Security**:
   - Use a strong, unique secret key to ensure the integrity of the tokens.
   - Never expose the secret key in client-side code or public repositories.

2. **Time Synchronization**:
   - Ensure the server's clock is synchronized to avoid discrepancies in token validation.

3. **Performance**:
   - The module is lightweight and suitable for applications where token security and expiration are critical.

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.

