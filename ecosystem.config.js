'use strict';

/**
 * PM2 process file for PayGate.
 *
 *   pm2 start ecosystem.config.js --env production
 *   pm2 save
 *   pm2 logs paygate
 *
 * IMPORTANT: run exactly ONE instance. PayGate uses SQLite (WAL) and an
 * in-process webhook outbox worker; horizontal scaling requires migrating the
 * queue to a shared store first.
 */
module.exports = {
  apps: [
    {
      name: 'paygate',
      script: './paygate.js',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',

      // Zero-downtime-ish restarts: the app sends `process.send('ready')`
      // once the HTTP server is listening and the outbox worker is armed.
      wait_ready: true,
      listen_timeout: 15000,
      kill_timeout: 12000,

      autorestart: true,
      max_restarts: 10,
      restart_delay: 2000,
      max_memory_restart: '300M',

      watch: false,
      time: true,
      merge_logs: true,
      error_file: './logs/error.log',
      out_file: './logs/out.log',

      env: {
        NODE_ENV: 'development',
        PORT: 3000,
      },
      env_production: {
        NODE_ENV: 'production',
        PORT: 3000,
      },
    },
  ],
};
