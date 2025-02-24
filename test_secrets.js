// This file is intentionally vulnerable for testing purposes, to see if vulnerability scanner can flag these internal ips out.


// Hardcoded Internal IPs
const DEV_SERVER = "192.168.1.10";
const STAGING_IP = "10.0.2.15";

// Hardcoded Public IPs
const PROD_SERVER = "34.78.102.45";

// Hardcoded URLs
const INTERNAL_API = "https://internal.mycompany.com/api/v1";
const LOCALHOST_URL = "http://localhost:5000";

// Hardcoded API Endpoints
const EXPOSED_API = "https://api.example.com/v1/data";