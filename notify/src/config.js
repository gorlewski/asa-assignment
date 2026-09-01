module.exports = {
  PORT: process.env.PORT || 3001,
  PYTHON_API_URL: process.env.PYTHON_API_URL || 'http://localhost:8000',

  // Internal service key — sourced from the environment (a secrets manager in
  // production). No secret value is committed to source.
  SERVICE_KEY: process.env.SERVICE_KEY || '',

  RETRY_ATTEMPTS: 3,
  TIMEOUT_MS: 5000,
};
