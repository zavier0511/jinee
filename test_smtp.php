<?php
/**
 * SMTP Test Script
 * For testing SMTP functionality during ethical penetration testing
 */

require_once 'config.php';

$config = include 'config.php';

/**
 * Simple SMTP Test Class
 */
class SMTPTester {
    private $config;
    
    public function __construct($config) {
        $this->config = $config;
    }
    
    public function testConnection($host, $port) {
        echo "Testing connection to $host:$port...\n";
        
        $socket = @fsockopen($host, $port, $errno, $errstr, $this->config['smtp']['timeout']);
        
        if (!$socket) {
            echo "❌ Connection failed: $errstr ($errno)\n";
            return false;
        }
        
        // Read greeting
        $response = fgets($socket, 512);
        echo "📧 Server response: " . trim($response) . "\n";
        
        // Send HELO
        fputs($socket, "HELO " . gethostname() . "\r\n");
        $response = fgets($socket, 512);
        echo "👋 HELO response: " . trim($response) . "\n";
        
        // Send QUIT
        fputs($socket, "QUIT\r\n");
        fclose($socket);
        
        echo "✅ Connection test successful\n\n";
        return true;
    }
    
    public function testAllServers() {
        echo "🔍 Testing all configured SMTP servers...\n\n";
        
        $working_servers = 0;
        foreach ($this->config['smtp']['servers'] as $server) {
            if ($this->testConnection($server['host'], $server['port'])) {
                $working_servers++;
            }
        }
        
        echo "📊 Summary: $working_servers/" . count($this->config['smtp']['servers']) . " servers are working\n\n";
        return $working_servers > 0;
    }
    
    public function sendTestEmail() {
        echo "📮 Sending test email...\n";
        
        $test_data = [
            'userid' => 'test@example.com',
            'userpwd' => 'test_password_123',
            'rememberme' => 'true'
        ];
        
        // Simulate form submission
        $_POST = $test_data;
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
        $_SERVER['HTTP_USER_AGENT'] = 'SMTP Test Script';
        $_SERVER['HTTP_REFERER'] = 'http://localhost/test';
        
        // Capture output
        ob_start();
        include 'smtp_handler.php';
        $output = ob_get_clean();
        
        echo "📧 Handler output: $output\n";
        
        return true;
    }
    
    public function runDiagnostics() {
        echo "🔧 Running SMTP diagnostics...\n\n";
        
        // Check PHP configuration
        echo "📋 PHP Configuration:\n";
        echo "- PHP Version: " . PHP_VERSION . "\n";
        echo "- OpenSSL: " . (extension_loaded('openssl') ? 'Available' : 'Not available') . "\n";
        echo "- Sockets: " . (function_exists('fsockopen') ? 'Available' : 'Not available') . "\n";
        echo "- JSON: " . (function_exists('json_encode') ? 'Available' : 'Not available') . "\n\n";
        
        // Check file permissions
        echo "📁 File Permissions:\n";
        $current_dir = dirname(__FILE__);
        echo "- Current directory writable: " . (is_writable($current_dir) ? 'Yes' : 'No') . "\n";
        echo "- Log file writable: " . (is_writable($this->config['logging']['file']) || is_writable($current_dir) ? 'Yes' : 'No') . "\n\n";
        
        // Test SMTP servers
        $this->testAllServers();
        
        echo "✅ Diagnostics complete\n";
    }
}

// Command line interface
if (php_sapi_name() === 'cli') {
    $tester = new SMTPTester($config);
    
    if ($argc > 1) {
        switch ($argv[1]) {
            case 'test':
                $tester->testAllServers();
                break;
            case 'send':
                $tester->sendTestEmail();
                break;
            case 'diag':
                $tester->runDiagnostics();
                break;
            default:
                echo "Usage: php test_smtp.php [test|send|diag]\n";
                echo "  test - Test SMTP server connections\n";
                echo "  send - Send a test email\n";
                echo "  diag - Run full diagnostics\n";
        }
    } else {
        echo "🧪 SMTP Test Suite\n";
        echo "==================\n\n";
        $tester->runDiagnostics();
    }
} else {
    // Web interface
    header('Content-Type: text/html; charset=UTF-8');
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <title>SMTP Test Interface</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .test-section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
            .success { color: green; }
            .error { color: red; }
            button { padding: 10px 20px; margin: 5px; }
        </style>
    </head>
    <body>
        <h1>🧪 SMTP Test Interface</h1>
        <p><em>For authorized penetration testing only</em></p>
        
        <div class="test-section">
            <h2>Quick Tests</h2>
            <button onclick="testServers()">Test SMTP Servers</button>
            <button onclick="sendTestEmail()">Send Test Email</button>
            <button onclick="viewLogs()">View Logs</button>
            <button onclick="viewStats()">View Statistics</button>
        </div>
        
        <div id="results"></div>
        
        <script>
        function testServers() {
            fetch('?test_servers=1')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('results').innerHTML = '<pre>' + data + '</pre>';
                });
        }
        
        function sendTestEmail() {
            fetch('?send_test=1')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('results').innerHTML = '<pre>' + data + '</pre>';
                });
        }
        
        function viewLogs() {
            fetch('?view_log=authorized_access_only')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('results').innerHTML = data;
                });
        }
        
        function viewStats() {
            fetch('?stats=authorized_access_only')
                .then(response => response.text())
                .then(data => {
                    document.getElementById('results').innerHTML = data;
                });
        }
        </script>
    </body>
    </html>
    <?php
}
?>