<?php
/**
 * AutoSecureWP Login Security Class
 *
 * @package AutoSecureWP
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class AutoSecure_WP_Login_Security {
    
    /**
     * Plugin options
     */
    private $options;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->options = get_option('autosecure_wp_login_options', array());
        $this->init();
    }
    
    /**
     * Initialize login security
     */
    private function init() {
        if (!empty($this->options['enable_brute_force_protection'])) {
            // Hook into WordPress login process
            add_action('wp_login_failed', array($this, 'handle_failed_login'));
            add_filter('authenticate', array($this, 'check_login_attempts'), 30, 3);
            add_action('wp_login', array($this, 'handle_successful_login'), 10, 2);
            
            // Add login error handling
            add_filter('wp_login_errors', array($this, 'add_login_warnings'), 10, 2);
            add_action('login_head', array($this, 'add_login_styles'));
            
            // Initialize reset handling
            $this->init_reset_handling();
        }
    }
    
    /**
     * Handle failed login attempts
     */
    public function handle_failed_login($username) {
        $ip = $this->get_client_ip();
        
        // Record the failed attempt
        $this->record_login_attempt($ip, $username, false);
        
        // Check current failed attempts
        $failed_attempts = $this->get_failed_attempts_count($ip);
        $max_attempts = isset($this->options['max_login_attempts']) ? $this->options['max_login_attempts'] : 5;
        $remaining_attempts = $max_attempts - $failed_attempts;
        
        // Store current attempt info for display on next page load
        set_transient('autosecure_attempt_info_' . md5($ip), array(
            'failed_attempts' => $failed_attempts,
            'remaining_attempts' => $remaining_attempts,
            'max_attempts' => $max_attempts,
            'timestamp' => time()
        ), 300); // 5 minutes
        
        if ($failed_attempts >= $max_attempts) {
            // Lock out the IP
            $this->lockout_ip($ip);
            
            // Send email notification about lockout
            $this->send_lockout_notification($ip, $username, $failed_attempts);
        }
    }
    
    /**
     * Handle successful login
     */
    public function handle_successful_login($user_login, $user) {
        $ip = $this->get_client_ip();
        $this->record_login_attempt($ip, $user_login, true);
        
        // Clear failed attempts for this IP on successful login
        $this->clear_failed_attempts($ip);
    }
    
    /**
     * Check login attempts before authentication
     */
    public function check_login_attempts($user, $username, $password) {
        $ip = $this->get_client_ip();
        
        // Check if IP is currently locked out
        if ($this->is_ip_locked_out($ip)) {
            $remaining_time = $this->get_lockout_remaining_time($ip);
            return new WP_Error('login_lockout', 
                sprintf(
                    __('Too many failed login attempts. Please try again in %s minutes.', 'autosecure-wp'),
                    ceil($remaining_time / 60)
                )
            );
        }
        
        return $user;
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip_headers = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_headers as $header) {
            if (!empty($_SERVER[$header])) {
                $ip = $_SERVER[$header];
                
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    /**
     * Record login attempt in database
     */
    private function record_login_attempt($ip, $username, $success = false) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        // Check if table exists
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            return false;
        }
        
        // Get additional information
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referer = $_SERVER['HTTP_REFERER'] ?? '';
        
        // Determine attempt type
        $attempt_type = 'unknown';
        if ($success) {
            $attempt_type = 'successful';
        } else {
            if (username_exists($username)) {
                $attempt_type = 'failed_password';
            } else {
                $attempt_type = 'invalid_username';
            }
        }
        
        return $wpdb->insert(
            $table_name,
            array(
                'ip_address' => $ip,
                'username' => sanitize_user($username),
                'timestamp' => current_time('mysql'),
                'success' => $success ? 1 : 0,
                'user_agent' => $user_agent,
                'attempt_type' => $attempt_type,
                'referer' => $referer
            ),
            array('%s', '%s', '%s', '%d', '%s', '%s', '%s')
        );
    }
    
    /**
     * Get failed attempts count
     */
    private function get_failed_attempts_count($ip) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            return 0;
        }
        
        $lockout_duration = isset($this->options['lockout_duration']) ? $this->options['lockout_duration'] : 30;
        $lockout_duration_seconds = $lockout_duration * 60;
        
        $result = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} 
             WHERE ip_address = %s 
             AND success = 0 
             AND timestamp > DATE_SUB(NOW(), INTERVAL %d SECOND)",
            $ip,
            $lockout_duration_seconds
        ));
        
        return $result ? $result : 0;
    }
    
    /**
     * Lockout IP address
     */
    private function lockout_ip($ip) {
        $lockout_duration = isset($this->options['lockout_duration']) ? $this->options['lockout_duration'] : 30;
        $lockout_duration_seconds = $lockout_duration * 60;
        
        $lockout_key = 'autosecure_lockout_' . md5($ip);
        set_transient($lockout_key, array(
            'locked_at' => time(),
            'duration' => $lockout_duration_seconds
        ), $lockout_duration_seconds);
    }
    
    /**
     * Check if IP is locked out
     */
    private function is_ip_locked_out($ip) {
        $lockout_key = 'autosecure_lockout_' . md5($ip);
        return get_transient($lockout_key) !== false;
    }
    
    /**
     * Get remaining lockout time
     */
    private function get_lockout_remaining_time($ip) {
        $lockout_key = 'autosecure_lockout_' . md5($ip);
        $lockout_data = get_transient($lockout_key);
        
        if ($lockout_data && is_array($lockout_data)) {
            $elapsed = time() - $lockout_data['locked_at'];
            return max(0, $lockout_data['duration'] - $elapsed);
        }
        
        return 0;
    }
    
    /**
     * Clear failed attempts for IP
     */
    private function clear_failed_attempts($ip) {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            return false;
        }
        
        $wpdb->delete(
            $table_name,
            array(
                'ip_address' => $ip,
                'success' => 0
            ),
            array('%s', '%d')
        );
        
        // Also clear lockout
        $lockout_key = 'autosecure_lockout_' . md5($ip);
        delete_transient($lockout_key);
    }
    
    /**
     * Add login warnings to WordPress login errors
     */
    public function add_login_warnings($errors, $redirect_to) {
        $ip = $this->get_client_ip();
        
        // Check if IP is locked out
        if ($this->is_ip_locked_out($ip)) {
            $remaining_time = $this->get_lockout_remaining_time($ip);
            $minutes = ceil($remaining_time / 60);
            
            $lockout_msg = sprintf(
                __('<strong>Account Locked:</strong> Too many failed login attempts. Your IP address has been temporarily blocked for %d minutes.<br><br><a href="#" onclick="toggleResetForm(); return false;">Request immediate access via email</a>', 'autosecure-wp'),
                $minutes
            );
            
            $reset_form = $this->get_reset_form_html($ip);
            
            $errors->add('autosecure_locked', $lockout_msg . $reset_form);
        } else {
            // Check for attempt info (after failed login)
            $attempt_info = get_transient('autosecure_attempt_info_' . md5($ip));
            if ($attempt_info && is_array($attempt_info)) {
                $remaining = $attempt_info['remaining_attempts'];
                
                if ($remaining <= 2 && $remaining > 0) {
                    $warning_msg = sprintf(
                        __('<strong>Security Warning:</strong> You have <strong>%d</strong> login attempt%s remaining before your IP address will be temporarily blocked for security.', 'autosecure-wp'),
                        $remaining,
                        $remaining == 1 ? '' : 's'
                    );
                    
                    $errors->add('autosecure_warning', $warning_msg);
                }
                
                // Clear the transient after use
                delete_transient('autosecure_attempt_info_' . md5($ip));
            }
        }
        
        return $errors;
    }
    
    /**
     * Get reset form HTML
     */
    private function get_reset_form_html($ip) {
        return '
        <div id="autosecure-reset-form" style="display:none; margin-top: 15px; padding: 15px; background: #f0f8ff; border: 1px solid #0073aa; border-radius: 4px; clear: both;">
            <p style="margin: 0 0 10px 0; font-weight: bold; color: #333;">Request Unlock Link:</p>
            <p style="margin: 0 0 15px 0; color: #666; font-size: 14px;">Enter your email address to receive an unlock link. If your email is associated with a user account on this site, you will receive an unlock link.</p>
            <form method="post" action="" style="margin: 0;">
                <input type="hidden" name="autosecure_unlock_request" value="1">
                <input type="hidden" name="blocked_ip" value="' . esc_attr($ip) . '">
                <div style="margin-bottom: 15px;">
                    <label for="unlock_email" style="display: block; margin-bottom: 5px; font-weight: bold; color: #333;">Your Email Address:</label>
                    <input type="email" 
                           name="user_email" 
                           id="unlock_email" 
                           placeholder="Enter your email address" 
                           required 
                           style="width: 100%; 
                                  padding: 10px; 
                                  border: 2px solid #ddd; 
                                  border-radius: 4px; 
                                  font-size: 16px; 
                                  box-sizing: border-box;
                                  background: #fff;
                                  display: block !important;
                                  visibility: visible !important;">
                </div>
                <div style="margin-top: 15px; text-align: left;">
                    <input type="submit" 
                           value="Send Unlock Link" 
                           style="background: #0073aa; 
                                  border: 1px solid #0073aa; 
                                  color: white; 
                                  padding: 12px 20px; 
                                  border-radius: 4px; 
                                  cursor: pointer; 
                                  font-size: 16px; 
                                  font-weight: bold;
                                  margin-right: 10px;
                                  display: inline-block;">
                    <button type="button" 
                            onclick="document.getElementById(\'autosecure-reset-form\').style.display=\'none\'; return false;" 
                            style="background: #f1f1f1; 
                                   border: 1px solid #ccc; 
                                   color: #333; 
                                   padding: 12px 20px; 
                                   border-radius: 4px; 
                                   cursor: pointer; 
                                   font-size: 16px;
                                   display: inline-block;">Cancel</button>
                </div>
            </form>
        </div>';
    }
    
    /**
     * Add login page styles and scripts
     */
    public function add_login_styles() {
        ?>
        <style>
        .login #login_error {
            margin-bottom: 20px;
        }
        .login #login_error[data-error-code="autosecure_warning"] {
            border-left: 4px solid #ffba00 !important;
            background: #fff3cd !important;
            color: #856404 !important;
        }
        .login #login_error[data-error-code="autosecure_locked"] {
            border-left: 4px solid #dc3232 !important;
            background: #fbeaea !important;
            color: #721c24 !important;
        }
        
        /* Force visibility of unlock form elements */
        #autosecure-reset-form {
            display: none !important;
            margin-top: 15px !important;
            padding: 15px !important;
            background: #f0f8ff !important;
            border: 1px solid #0073aa !important;
            border-radius: 4px !important;
            clear: both !important;
            overflow: visible !important;
        }
        
        #autosecure-reset-form.show {
            display: block !important;
        }
        
        #autosecure-reset-form input[type="email"] {
            width: 100% !important;
            padding: 10px !important;
            border: 2px solid #ddd !important;
            border-radius: 4px !important;
            font-size: 16px !important;
            box-sizing: border-box !important;
            background: #fff !important;
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            position: static !important;
            height: auto !important;
            min-height: 40px !important;
        }
        
        #autosecure-reset-form input[type="submit"] {
            background: #0073aa !important;
            border: 1px solid #0073aa !important;
            color: white !important;
            padding: 12px 20px !important;
            border-radius: 4px !important;
            cursor: pointer !important;
            font-size: 16px !important;
            font-weight: bold !important;
            margin-right: 10px !important;
            display: inline-block !important;
            visibility: visible !important;
            opacity: 1 !important;
        }
        
        #autosecure-reset-form button {
            background: #f1f1f1 !important;
            border: 1px solid #ccc !important;
            color: #333 !important;
            padding: 12px 20px !important;
            border-radius: 4px !important;
            cursor: pointer !important;
            font-size: 16px !important;
            display: inline-block !important;
            visibility: visible !important;
            opacity: 1 !important;
        }
        
        #autosecure-reset-form label {
            display: block !important;
            margin-bottom: 5px !important;
            font-weight: bold !important;
            color: #333 !important;
            visibility: visible !important;
        }
        
        #autosecure-reset-form div {
            margin-bottom: 15px !important;
            display: block !important;
            visibility: visible !important;
        }
        </style>
        <script>
        function toggleResetForm() {
            var form = document.getElementById('autosecure-reset-form');
            if (form) {
                if (form.style.display === 'none' || !form.classList.contains('show')) {
                    form.style.display = 'block';
                    form.classList.add('show');
                } else {
                    form.style.display = 'none';
                    form.classList.remove('show');
                }
            }
        }
        
        // Add data attributes to error divs for styling
        document.addEventListener('DOMContentLoaded', function() {
            var errors = document.querySelectorAll('#login_error');
            errors.forEach(function(error) {
                if (error.innerHTML.indexOf('Security Warning:') !== -1) {
                    error.setAttribute('data-error-code', 'autosecure_warning');
                    error.style.borderLeft = '4px solid #ffba00';
                    error.style.background = '#fff3cd';
                    error.style.color = '#856404';
                } else if (error.innerHTML.indexOf('Account Locked:') !== -1) {
                    error.setAttribute('data-error-code', 'autosecure_locked');
                    error.style.borderLeft = '4px solid #dc3232';
                    error.style.background = '#fbeaea';
                    error.style.color = '#721c24';
                }
            });
        });
        </script>
        <?php
    }
    
    /**
     * Send lockout notification email
     */
    private function send_lockout_notification($ip, $username, $failed_attempts) {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        $subject = sprintf(__('[%s] Security Alert: Login Lockout Activated', 'autosecure-wp'), $site_name);
        
        $message = sprintf(
            __("Security Alert: Login Lockout Activated\n\n" .
               "A login lockout has been activated on your website due to multiple failed login attempts.\n\n" .
               "Details:\n" .
               "- IP Address: %s\n" .
               "- Username Attempted: %s\n" .
               "- Failed Attempts: %d\n" .
               "- Time: %s\n" .
               "- Website: %s\n\n" .
               "The IP address has been temporarily blocked. The user can request an unlock link via email if they are a legitimate user.\n\n" .
               "This email was sent by AutoSecureWP security plugin.", 'autosecure-wp'),
            $ip,
            $username,
            $failed_attempts,
            current_time('mysql'),
            $site_url
        );
        
        wp_mail($admin_email, $subject, $message);
    }
    
    /**
     * Handle unlock request from login page
     */
    public function handle_reset_request() {
        if (isset($_POST['autosecure_unlock_request']) && $_POST['autosecure_unlock_request'] == '1') {
            $blocked_ip = sanitize_text_field($_POST['blocked_ip']);
            $user_email = sanitize_email($_POST['user_email']);
            
            if (empty($user_email) || !is_email($user_email)) {
                $redirect_url = add_query_arg('autosecure_message', 'invalid_email_format', wp_login_url());
                wp_redirect($redirect_url);
                exit;
            }
            
            // Check if email exists in the system
            $user = get_user_by('email', $user_email);
            if (!$user) {
                // Don't reveal if email exists or not for security
                $redirect_url = add_query_arg('autosecure_message', 'unlock_sent', wp_login_url());
                wp_redirect($redirect_url);
                exit;
            }
            
            // Send unlock link to the user
            $this->send_unlock_link($blocked_ip, $user_email, $user);
            
            // Redirect with success message
            $redirect_url = add_query_arg('autosecure_message', 'unlock_sent', wp_login_url());
            wp_redirect($redirect_url);
            exit;
        }
        
        // Handle display of messages from redirects
        if (isset($_GET['autosecure_message'])) {
            add_filter('wp_login_errors', array($this, 'show_redirect_messages'), 10, 2);
        }
    }
    
    /**
     * Send unlock link email
     */
    private function send_unlock_link($blocked_ip, $user_email, $user) {
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        $unlock_token = wp_generate_password(32, false);
        
        // Store unlock token temporarily (2 hours)
        set_transient('autosecure_unlock_' . md5($blocked_ip . $user_email), array(
            'token' => $unlock_token,
            'ip' => $blocked_ip,
            'email' => $user_email,
            'user_id' => $user->ID,
            'created' => time()
        ), 2 * 3600);
        
        $subject = sprintf(__('[%s] Account Unlock Link', 'autosecure-wp'), $site_name);
        
        $unlock_url = add_query_arg(array(
            'autosecure_unlock' => $unlock_token,
            'ip' => base64_encode($blocked_ip),
            'email' => base64_encode($user_email)
        ), wp_login_url());
        
        $message = sprintf(
            __("Hello %s,\n\n" .
               "You requested an unlock link for your account that has been temporarily blocked due to failed login attempts.\n\n" .
               "IP Address: %s\n" .
               "Website: %s\n\n" .
               "Click the link below to unlock your account and restore access:\n" .
               "%s\n\n" .
               "This link will expire in 2 hours for security reasons.\n\n" .
               "If you did not request this unlock, please ignore this email. Your account will remain secure.\n\n" .
               "If you continue to have trouble logging in, please contact the site administrator.\n\n" .
               "Best regards,\n" .
               "%s Security Team", 'autosecure-wp'),
            $user->display_name,
            $blocked_ip,
            $site_url,
            $unlock_url,
            $site_name
        );
        
        // Log the unlock request
        global $wpdb;
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
            $wpdb->insert(
                $table_name,
                array(
                    'ip_address' => $blocked_ip,
                    'username' => $user->user_login,
                    'timestamp' => current_time('mysql'),
                    'success' => 0,
                    'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                    'attempt_type' => 'unlock_request',
                    'referer' => 'email_unlock_system'
                ),
                array('%s', '%s', '%s', '%d', '%s', '%s', '%s')
            );
        }
        
        wp_mail($user_email, $subject, $message);
    }
    
    /**
     * Show messages from redirects
     */
    public function show_redirect_messages($errors, $redirect_to) {
        if (isset($_GET['autosecure_message'])) {
            $message_type = sanitize_title($_GET['autosecure_message']);
            
            switch ($message_type) {
                case 'unlock_sent':
                    $errors->add('autosecure_success', __('<strong>Unlock Link Sent!</strong> If your email address is associated with an account on this site, you will receive an unlock link shortly. Please check your email and click the link to restore access.'));
                    break;
                case 'invalid_email_format':
                    $errors->add('autosecure_error', __('<strong>Error:</strong> Please enter a valid email address.'));
                    break;
                case 'access_unlocked':
                    $errors->add('autosecure_success', __('<strong>Access Restored!</strong> Your account has been successfully unlocked. You can now log in normally.'));
                    break;
                case 'invalid_unlock_link':
                    $errors->add('autosecure_error', __('<strong>Invalid Unlock Link:</strong> This unlock link has expired or is invalid. Please request a new unlock link.'));
                    break;
                case 'unlock_used':
                    $errors->add('autosecure_error', __('<strong>Link Already Used:</strong> This unlock link has already been used. If you still cannot access your account, please request a new unlock link.'));
                    break;
            }
        }
        
        return $errors;
    }
    
    /**
     * Initialize reset handling
     */
    public function init_reset_handling() {
        // Handle unlock requests from login page
        add_action('login_init', array($this, 'handle_reset_request'));
        
        // Handle unlock link clicks
        add_action('login_init', array($this, 'handle_unlock_link'));
    }
    
    /**
     * Handle unlock link clicks
     */
    public function handle_unlock_link() {
        if (isset($_GET['autosecure_unlock']) && isset($_GET['ip']) && isset($_GET['email'])) {
            $unlock_token = sanitize_text_field($_GET['autosecure_unlock']);
            $encoded_ip = sanitize_text_field($_GET['ip']);
            $encoded_email = sanitize_text_field($_GET['email']);
            
            $blocked_ip = base64_decode($encoded_ip);
            $user_email = base64_decode($encoded_email);
            
            // Verify unlock token
            $stored_data = get_transient('autosecure_unlock_' . md5($blocked_ip . $user_email));
            
            if (!$stored_data || !is_array($stored_data)) {
                $redirect_url = add_query_arg('autosecure_message', 'invalid_unlock_link', wp_login_url());
                wp_redirect($redirect_url);
                exit;
            }
            
            if ($stored_data['token'] !== $unlock_token || $stored_data['ip'] !== $blocked_ip || $stored_data['email'] !== $user_email) {
                $redirect_url = add_query_arg('autosecure_message', 'invalid_unlock_link', wp_login_url());
                wp_redirect($redirect_url);
                exit;
            }
            
            // Check if link was already used
            if (isset($stored_data['used']) && $stored_data['used']) {
                $redirect_url = add_query_arg('autosecure_message', 'unlock_used', wp_login_url());
                wp_redirect($redirect_url);
                exit;
            }
            
            // Unlock is valid, clear the lockout
            $this->clear_failed_attempts($blocked_ip);
            
            // Mark the unlock token as used
            $stored_data['used'] = true;
            $stored_data['used_at'] = time();
            set_transient('autosecure_unlock_' . md5($blocked_ip . $user_email), $stored_data, 3600);
            
            // Log the successful unlock
            global $wpdb;
            $table_name = $wpdb->prefix . 'autosecure_login_attempts';
            if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
                $user = get_user_by('email', $user_email);
                $wpdb->insert(
                    $table_name,
                    array(
                        'ip_address' => $blocked_ip,
                        'username' => $user ? $user->user_login : 'unknown',
                        'timestamp' => current_time('mysql'),
                        'success' => 1,
                        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
                        'attempt_type' => 'unlock_successful',
                        'referer' => 'email_unlock_link'
                    ),
                    array('%s', '%s', '%s', '%d', '%s', '%s', '%s')
                );
            }
            
            // Send notification to admin about the unlock
            $this->send_unlock_notification($blocked_ip, $user_email);
            
            // Redirect with success message
            $redirect_url = add_query_arg('autosecure_message', 'access_unlocked', wp_login_url());
            wp_redirect($redirect_url);
            exit;
        }
    }
    
    /**
     * Send unlock notification to admin
     */
    private function send_unlock_notification($ip, $user_email) {
        $admin_email = get_option('admin_email');
        $site_name = get_bloginfo('name');
        $site_url = home_url();
        
        $subject = sprintf(__('[%s] Account Unlock Notification', 'autosecure-wp'), $site_name);
        
        $message = sprintf(
            __("Account Unlock Notification\n\n" .
               "An account has been successfully unlocked using the email unlock system.\n\n" .
               "Details:\n" .
               "- IP Address: %s\n" .
               "- User Email: %s\n" .
               "- Time: %s\n" .
               "- Website: %s\n\n" .
               "The user can now log in normally. This email is for your information and security records.\n\n" .
               "If this unlock was not authorized, please review your security settings.\n\n" .
               "AutoSecureWP Security System", 'autosecure-wp'),
            $ip,
            $user_email,
            current_time('mysql'),
            $site_url
        );
        
        wp_mail($admin_email, $subject, $message);
    }
}