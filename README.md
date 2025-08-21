# SMTP Email Handler for Ethical Penetration Testing

## ⚠️ IMPORTANT DISCLAIMER
This tool is designed for **authorized penetration testing only**. Ensure you have proper written authorization before using this tool. Unauthorized use may violate local, state, and federal laws.

## Overview
This PHP script provides SMTP functionality using port 25 for capturing and processing form submissions during authorized security assessments.

## Features
- ✅ SMTP email sending on port 25
- ✅ Multiple SMTP server support with failover
- ✅ Rate limiting and anti-bot protection
- ✅ Comprehensive logging and statistics
- ✅ Input validation and sanitization
- ✅ Honeypot field for bot detection
- ✅ Security headers and best practices

## Files Included
- `smtp_handler.php` - Basic SMTP handler
- `advanced_smtp_handler.php` - Enhanced version with more features
- `config.php` - Configuration file
- `test_smtp.php` - Testing utilities
- `index.html` - Sample form (update the action URL)

## Installation

1. **Upload files to your web server**
   ```bash
   # Make sure the directory is writable for logging
   chmod 755 /path/to/your/webroot
   chmod 666 /path/to/your/webroot/pentest_log.txt
   ```

2. **Configure SMTP settings**
   Edit `config.php` and update the SMTP server settings:
   ```php
   'smtp' => [
       'servers' => [
           ['host' => 'your-smtp-server.com', 'port' => 25],
       ],
   ],
   ```

3. **Update email settings**
   ```php
   'email' => [
       'from' => 'pentest@yourdomain.com',
       'to' => ['admin@yourdomain.com'],
   ],
   ```

## Usage

### Testing SMTP Connectivity
```bash
# Command line testing
php test_smtp.php test    # Test SMTP connections
php test_smtp.php send    # Send test email
php test_smtp.php diag    # Run full diagnostics
```

### Web Interface Testing
Navigate to `test_smtp.php` in your browser for a web-based testing interface.

### Form Integration
Update your HTML form's action attribute to point to the PHP handler:
```html
<form action="smtp_handler.php" method="post">
    <!-- Your form fields -->
</form>
```

## Configuration Options

### SMTP Settings
- **servers**: Array of SMTP servers with host and port
- **timeout**: Connection timeout in seconds
- **use_auth**: Enable SMTP authentication if required

### Security Features
- **Rate limiting**: Prevents abuse by limiting requests per IP
- **Honeypot field**: Detects automated bot submissions
- **Input sanitization**: Prevents XSS and injection attacks
- **IP filtering**: Whitelist/blacklist functionality

### Logging
- **Comprehensive logging**: All activities are logged
- **Log rotation**: Automatic log file rotation when size limit reached
- **Statistics**: Detailed analytics of captured data

## Monitoring and Analysis

### View Logs
```
GET /smtp_handler.php?view_log=authorized_access_only
```

### View Statistics
```
GET /smtp_handler.php?stats=authorized_access_only
```

### Clear Logs
```
GET /smtp_handler.php?clear_log=authorized_access_only
```

## Security Considerations

1. **Authorization**: Only use with proper written authorization
2. **Data Protection**: Secure the log files and captured data
3. **Access Control**: Implement proper access controls on the admin functions
4. **SSL/TLS**: Consider using encrypted connections when possible
5. **Regular Cleanup**: Regularly clean up logs and captured data

## Troubleshooting

### Common Issues

1. **SMTP Connection Failed**
   - Check if port 25 is open
   - Verify SMTP server address
   - Check firewall settings

2. **Permission Denied**
   - Ensure web server has write permissions
   - Check file ownership and permissions

3. **Rate Limiting**
   - Adjust rate limiting settings in config
   - Clear rate limit data if needed

### Debug Mode
Enable debug output in the configuration:
```php
'testing' => [
    'debug_output' => true,
],
```

## Legal and Ethical Guidelines

- ✅ Only use with explicit written authorization
- ✅ Document all testing activities
- ✅ Protect captured data appropriately
- ✅ Follow responsible disclosure practices
- ❌ Never use against unauthorized targets
- ❌ Never use for malicious purposes

## Support

For issues or questions related to authorized penetration testing:
1. Check the troubleshooting section
2. Review the configuration settings
3. Test SMTP connectivity separately
4. Ensure proper permissions and setup

---

**Remember**: This tool is for authorized security testing only. Always follow legal and ethical guidelines when conducting penetration tests.