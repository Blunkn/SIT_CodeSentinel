// This file is intentionally vulnerable for testing purposes, to see if vulnerability scanner can flag these secrets out.

// API Keys
const GOOGLE_API_KEY = "AIzaSyD-EXAMPLEKEY1234567890";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const AZURE_CLIENT_SECRET = "example-azure-client-secret-123456";

// Passwords
const DB_PASSWORD = "supersecurepassword123";
const ADMIN_PASSWORD = "admin123";

// JWT Secrets
const JWT_SECRET = "myjwtsecretkeyshouldbekeptsecret";

// Hardcoded Credentials
const username = "admin";
const password = "P@ssw0rd";

// Private Keys
const PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA7v/NiEXAMPLEKEYBASE64ENCRYPTEDINFO
-----END RSA PRIVATE KEY-----`;

// Placeholder for actual application logic
function doSomething() {
    console.log("Running application logic...");
}

doSomething();