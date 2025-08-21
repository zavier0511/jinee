<?php
/**
 * Deployment Script for SMTP Handler
 * For ethical penetration testing setup
 */

echo "🚀 SMTP Handler Deployment Script\n";
echo "==================================\n\n";

// Check PHP version
if (version_compare(PHP_VERSION, '7.0.0', '<')) {
    echo "❌ PHP 7.0 or higher is required. Current version: " . PHP_VERSION . "\n";
    exit(1);
}

echo "✅ PHP Version: " . PHP_VERSION . "\n";

// Check required functions
$required_functions = ['fsockopen', 'json_encode', 'json_decode', 'file_get_contents', 'file_put_contents'];
foreach ($required_functions as $func) {
    if (!function_exists($func)) {
        echo "❌ Required function '$func' is not available\n";
        exit(1);
    }
}

echo "✅ Required PHP functions are available\n";

// Check file permissions
$current_dir = __DIR__;
if (!is_writable($current_dir)) {
    echo "❌ Current directory is not writable: $current_dir\n";
    echo "   Please run: chmod 755 $current_dir\n";
    exit(1);
}

echo "✅ Directory is writable\n";

// Create necessary files if they don't exist
$files_to_check = [
    'smtp_handler.php',
    'advanced_smtp_handler.php',
    'config.php',
    'test_smtp.php',
    'index.html'
];

foreach ($files_to_check as $file) {
    if (!file_exists($file)) {
        echo "❌ Missing file: $file\n";
    } else {
        echo "✅ Found: $file\n";
    }
}

// Create .htaccess for security (if Apache)
$htaccess_content = <<<'EOT'
# Security headers
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
</IfModule>

# Protect log files
<FilesMatch "\.(log|txt)$">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Protect configuration files
<FilesMatch "config\.php$">
    Order Allow,Deny
    Deny from all
</FilesMatch>

# Enable compression
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>
EOT;

if (!file_exists('.htaccess')) {
    file_put_contents('.htaccess', $htaccess_content);
    echo "✅ Created .htaccess file for security\n";
} else {
    echo "ℹ️  .htaccess file already exists\n";
}

// Test SMTP connectivity
echo "\n🔍 Testing SMTP connectivity...\n";

$smtp_servers = [
    ['host' => 'localhost', 'port' => 25],
    ['host' => '127.0.0.1', 'port' => 25],
];

$working_servers = 0;
foreach ($smtp_servers as $server) {
    echo "Testing {$server['host']}:{$server['port']}... ";
    
    $socket = @fsockopen($server['host'], $server['port'], $errno, $errstr, 5);
    if ($socket) {
        fclose($socket);
        echo "✅ OK\n";
        $working_servers++;
    } else {
        echo "❌ Failed ($errstr)\n";
    }
}

if ($working_servers === 0) {
    echo "⚠️  No SMTP servers are accessible. You may need to:\n";
    echo "   - Install a local mail server (postfix, sendmail, etc.)\n";
    echo "   - Configure external SMTP server details\n";
    echo "   - Check firewall settings\n";
}

// Configuration validation
echo "\n⚙️  Configuration validation...\n";

if (file_exists('config.php')) {
    $config = include 'config.php';
    
    // Check email configuration
    if (empty($config['email']['to'])) {
        echo "⚠️  No recipient email addresses configured\n";
    } else {
        echo "✅ Recipient emails configured: " . implode(', ', $config['email']['to']) . "\n";
    }
    
    // Check logging configuration
    if ($config['logging']['enabled']) {
        echo "✅ Logging is enabled\n";
    } else {
        echo "⚠️  Logging is disabled\n";
    }
    
    // Check security settings
    if ($config['security']['rate_limit']['enabled']) {
        echo "✅ Rate limiting is enabled\n";
    } else {
        echo "⚠️  Rate limiting is disabled\n";
    }
} else {
    echo "❌ Configuration file not found\n";
}

// Final instructions
echo "\n📋 Deployment Summary\n";
echo "====================\n";
echo "✅ PHP environment check passed\n";
echo "✅ File permissions are correct\n";
echo "✅ Security files created\n";

if ($working_servers > 0) {
    echo "✅ SMTP connectivity verified\n";
} else {
    echo "⚠️  SMTP connectivity needs attention\n";
}

echo "\n🎯 Next Steps:\n";
echo "1. Update config.php with your SMTP server details\n";
echo "2. Configure recipient email addresses\n";
echo "3. Test the setup using test_smtp.php\n";
echo "4. Update your form's action URL to point to smtp_handler.php\n";
echo "5. Ensure you have proper authorization for testing\n";

echo "\n🧪 Testing Commands:\n";
echo "- php test_smtp.php test     # Test SMTP connections\n";
echo "- php test_smtp.php send     # Send test email\n";
echo "- php test_smtp.php diag     # Run diagnostics\n";

echo "\n⚠️  SECURITY REMINDER:\n";
echo "This tool is for authorized penetration testing only.\n";
echo "Ensure you have proper written authorization before use.\n";
echo "Protect all captured data and follow responsible disclosure.\n";

echo "\n✅ Deployment complete!\n";
?>