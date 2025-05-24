<?php
/**
 * AutoSecureWP Admin Class
 *
 * @package AutoSecureWP
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class AutoSecure_WP_Admin {
    
    /**
     * Constructor
     */
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'admin_init'));
        add_action('wp_ajax_autosecure_reset_lockouts', array($this, 'handle_reset_lockouts'));
        add_action('wp_ajax_autosecure_clear_attempts', array($this, 'handle_clear_attempts'));
        add_action('wp_ajax_autosecure_block_ip', array($this, 'handle_block_ip'));
        add_action('wp_ajax_autosecure_get_log_details', array($this, 'handle_get_log_details'));
        add_action('wp_ajax_autosecure_clear_all_logs', array($this, 'handle_clear_all_logs'));
        
        // Schedule cleanup cron job
        add_action('autosecure_wp_cleanup_logs', array($this, 'cleanup_old_logs'));
        if (!wp_next_scheduled('autosecure_wp_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'autosecure_wp_cleanup_logs');
        }
    }
    
    /**
     * Initialize admin settings
     */
    public function admin_init() {
        register_setting('autosecure_wp_login_options', 'autosecure_wp_login_options', array($this, 'sanitize_login_options'));
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        // Main menu page
        add_menu_page(
            __('AutoSecure WP', 'autosecure-wp'),
            __('AutoSecure WP', 'autosecure-wp'),
            'manage_options',
            'autosecure-wp',
            array($this, 'display_dashboard_page'),
            'dashicons-shield-alt',
            30
        );
        
        // Login Security submenu
        add_submenu_page(
            'autosecure-wp',
            __('Login Security', 'autosecure-wp'),
            __('Login Security', 'autosecure-wp'),
            'manage_options',
            'autosecure-wp-login',
            array($this, 'display_login_security_page')
        );
        
        // Login Logs submenu
        add_submenu_page(
            'autosecure-wp',
            __('Login Logs', 'autosecure-wp'),
            __('Login Logs', 'autosecure-wp'),
            'manage_options',
            'autosecure-wp-logs',
            array($this, 'display_login_logs_page')
        );
    }
    
    /**
     * Display dashboard page
     */
    public function display_dashboard_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <div class="notice notice-success">
                <p><?php _e('AutoSecureWP is successfully installed and activated!', 'autosecure-wp'); ?></p>
            </div>
            
            <div class="card" style="background: #fff; border: 1px solid #c3c4c7; padding: 20px; margin: 20px 0;">
                <h2><?php _e('Welcome to AutoSecureWP', 'autosecure-wp'); ?></h2>
                <p><?php _e('Your WordPress security plugin is ready to be configured.', 'autosecure-wp'); ?></p>
                <p><?php _e('Security features are now active and protecting your site.', 'autosecure-wp'); ?></p>
            </div>
            
            <div class="card" style="background: #fff; border: 1px solid #c3c4c7; padding: 20px; margin: 20px 0;">
                <h3><?php _e('Plugin Information', 'autosecure-wp'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php _e('Version', 'autosecure-wp'); ?></th>
                        <td><?php echo esc_html(AUTOSECURE_WP_VERSION); ?></td>
                    </tr>
                    <tr>
                        <th scope="row"><?php _e('Status', 'autosecure-wp'); ?></th>
                        <td><span style="color: green;"><?php _e('Active', 'autosecure-wp'); ?></span></td>
                    </tr>
                </table>
            </div>
        </div>
        <?php
    }
    
    /**
     * Display login security page
     */
    public function display_login_security_page() {
        // Get current options
        $options = get_option('autosecure_wp_login_options', $this->get_default_login_options());
        
        // Handle form submission
        if (isset($_POST['submit']) && wp_verify_nonce($_POST['autosecure_nonce'], 'autosecure_login_settings')) {
            $options = $this->sanitize_login_options($_POST['autosecure_wp_login_options']);
            update_option('autosecure_wp_login_options', $options);
            echo '<div class="notice notice-success"><p>' . __('Settings saved successfully!', 'autosecure-wp') . '</p></div>';
        }
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <form method="post" action="">
                <?php wp_nonce_field('autosecure_login_settings', 'autosecure_nonce'); ?>
                
                <!-- Brute Force Protection Section -->
                <div class="card">
                    <h2><?php _e('Brute Force Protection', 'autosecure-wp'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php _e('Enable Brute Force Protection', 'autosecure-wp'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="autosecure_wp_login_options[enable_brute_force_protection]" value="1" <?php checked($options['enable_brute_force_protection'], 1); ?>>
                                    <?php _e('Enable login attempt limiting', 'autosecure-wp'); ?>
                                </label>
                                <p class="description"><?php _e('Limit the number of login attempts from each IP address.', 'autosecure-wp'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Max Login Attempts', 'autosecure-wp'); ?></th>
                            <td>
                                <input type="number" name="autosecure_wp_login_options[max_login_attempts]" value="<?php echo esc_attr($options['max_login_attempts']); ?>" min="1" max="20" class="small-text">
                                <p class="description"><?php _e('Number of failed login attempts before lockout (default: 5)', 'autosecure-wp'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Lockout Duration (minutes)', 'autosecure-wp'); ?></th>
                            <td>
                                <input type="number" name="autosecure_wp_login_options[lockout_duration]" value="<?php echo esc_attr($options['lockout_duration']); ?>" min="1" max="1440" class="small-text">
                                <p class="description"><?php _e('How long to lock out an IP after failed attempts (default: 30 minutes)', 'autosecure-wp'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <!-- Current Status & Reset -->
                <div class="card">
                    <h2><?php _e('Current Status & Management', 'autosecure-wp'); ?></h2>
                    <div id="login-security-stats">
                        <?php $this->display_current_lockouts(); ?>
                    </div>
                    <p>
                        <button type="button" class="button" id="reset-all-lockouts"><?php _e('Reset All Login Lockouts', 'autosecure-wp'); ?></button>
                        <button type="button" class="button" id="clear-failed-attempts"><?php _e('Clear All Failed Attempts', 'autosecure-wp'); ?></button>
                        <span class="spinner" style="float: none; margin: 0 5px;"></span>
                    </p>
                    <p class="description">
                        <?php _e('Use these buttons to reset lockouts and clear failed login attempt records. Users will be able to login immediately after reset.', 'autosecure-wp'); ?>
                    </p>
                </div>
                
                <!-- Auto-cleanup Settings -->
                <div class="card">
                    <h2><?php _e('Automatic Log Cleanup', 'autosecure-wp'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php _e('Auto-delete Old Logs', 'autosecure-wp'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="autosecure_wp_login_options[auto_cleanup_logs]" value="1" <?php checked(isset($options['auto_cleanup_logs']) ? $options['auto_cleanup_logs'] : 0, 1); ?>>
                                    <?php _e('Automatically delete old login logs', 'autosecure-wp'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php _e('Keep Logs For (days)', 'autosecure-wp'); ?></th>
                            <td>
                                <input type="number" name="autosecure_wp_login_options[log_retention_days]" value="<?php echo esc_attr(isset($options['log_retention_days']) ? $options['log_retention_days'] : 30); ?>" min="1" max="365" class="small-text">
                                <p class="description"><?php _e('Number of days to keep login logs (default: 30 days)', 'autosecure-wp'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <?php submit_button(); ?>
            </form>
        </div>
        
        <script>
        jQuery(document).ready(function($) {
            $('#reset-all-lockouts').click(function() {
                var button = $(this);
                var spinner = $('.spinner');
                
                if (!confirm('<?php _e('Are you sure you want to reset all current login lockouts?', 'autosecure-wp'); ?>')) {
                    return;
                }
                
                button.prop('disabled', true);
                spinner.addClass('is-active');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'autosecure_reset_lockouts',
                        nonce: '<?php echo wp_create_nonce('autosecure_reset_lockouts'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('<?php _e('All login lockouts have been reset successfully!', 'autosecure-wp'); ?>');
                            location.reload();
                        } else {
                            alert('<?php _e('Error resetting lockouts.', 'autosecure-wp'); ?>');
                        }
                    },
                    complete: function() {
                        button.prop('disabled', false);
                        spinner.removeClass('is-active');
                    }
                });
            });
            
            $('#clear-failed-attempts').click(function() {
                var button = $(this);
                var spinner = $('.spinner');
                
                if (!confirm('<?php _e('Are you sure you want to clear all failed login attempt records?', 'autosecure-wp'); ?>')) {
                    return;
                }
                
                button.prop('disabled', true);
                spinner.addClass('is-active');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'autosecure_clear_attempts',
                        nonce: '<?php echo wp_create_nonce('autosecure_clear_attempts'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('<?php _e('All failed login attempts have been cleared!', 'autosecure-wp'); ?>');
                            location.reload();
                        } else {
                            alert('<?php _e('Error clearing failed attempts.', 'autosecure-wp'); ?>');
                        }
                    },
                    complete: function() {
                        button.prop('disabled', false);
                        spinner.removeClass('is-active');
                    }
                });
            });
        });
        </script>
        
        <style>
            .card {
                background: #fff;
                border: 1px solid #c3c4c7;
                padding: 20px;
                margin: 20px 0;
                box-shadow: 0 1px 1px rgba(0,0,0,.04);
            }
            .card h2 {
                margin-top: 0;
                padding-bottom: 10px;
                border-bottom: 1px solid #e1e1e1;
            }
        </style>
        <?php
    }
    
    /**
     * Display login logs page
     */
    public function display_login_logs_page() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        // Simple pagination
        $per_page = 50;
        $current_page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
        $offset = ($current_page - 1) * $per_page;
        
        // Get total count
        $total_items = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}");
        
        // Get logs  
        $logs = $wpdb->get_results($wpdb->prepare(
            "SELECT * FROM {$table_name} ORDER BY timestamp DESC LIMIT %d OFFSET %d",
            $per_page,
            $offset
        ));
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <!-- Statistics Summary -->
            <div class="card">
                <h2><?php _e('Login Attempts Summary', 'autosecure-wp'); ?></h2>
                <?php $this->display_login_stats_summary(); ?>
            </div>
            
            <!-- Logs Table -->
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h3><?php printf(__('Login Attempts (%s total)', 'autosecure-wp'), number_format($total_items)); ?></h3>
                    <div>
                        <button type="button" class="button" id="clear-all-logs"><?php _e('Clear All Logs', 'autosecure-wp'); ?></button>
                        <span class="spinner" style="float: none; margin: 0 5px;"></span>
                    </div>
                </div>
                
                <?php if (empty($logs)): ?>
                    <p><?php _e('No login attempts found.', 'autosecure-wp'); ?></p>
                <?php else: ?>
                    <table class="wp-list-table widefat fixed striped">
                        <thead>
                            <tr>
                                <th><?php _e('Date & Time', 'autosecure-wp'); ?></th>
                                <th><?php _e('Status', 'autosecure-wp'); ?></th>
                                <th><?php _e('IP Address', 'autosecure-wp'); ?></th>
                                <th><?php _e('Username', 'autosecure-wp'); ?></th>
                                <th><?php _e('User Agent', 'autosecure-wp'); ?></th>
                                <th><?php _e('Actions', 'autosecure-wp'); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($logs as $log): ?>
                                <tr>
                                    <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($log->timestamp))); ?></td>
                                    <td>
                                        <?php if ($log->success): ?>
                                            <span style="color: #00a32a; font-weight: bold;">✓ <?php _e('Success', 'autosecure-wp'); ?></span>
                                        <?php else: ?>
                                            <span style="color: #d63638; font-weight: bold;">✗ <?php _e('Failed', 'autosecure-wp'); ?></span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <code><?php echo esc_html($log->ip_address); ?></code>
                                        <?php if ($this->is_ip_currently_locked($log->ip_address)): ?>
                                            <br><small style="color: #d63638;"><strong><?php _e('Currently Locked', 'autosecure-wp'); ?></strong></small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <strong><?php echo esc_html($log->username); ?></strong>
                                        <?php if (!$log->success && !username_exists($log->username)): ?>
                                            <br><small style="color: #d63638;"><?php _e('Invalid User', 'autosecure-wp'); ?></small>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <small title="<?php echo esc_attr($log->user_agent); ?>">
                                            <?php echo esc_html($this->parse_user_agent($log->user_agent)); ?>
                                        </small>
                                    </td>
                                    <td>
                                        <?php if (!$log->success): ?>
                                            <button type="button" class="button button-small block-ip" data-ip="<?php echo esc_attr($log->ip_address); ?>">
                                                <?php _e('Block IP', 'autosecure-wp'); ?>
                                            </button>
                                        <?php endif; ?>
                                        <button type="button" class="button button-small view-details" data-id="<?php echo $log->id; ?>">
                                            <?php _e('Details', 'autosecure-wp'); ?>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>
        
        <!-- Details Modal -->
        <div id="log-details-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 999999;">
            <div style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 30px; border-radius: 8px; max-width: 600px; width: 90%;">
                <h3><?php _e('Login Attempt Details', 'autosecure-wp'); ?></h3>
                <div id="log-details-content"></div>
                <p style="text-align: right; margin-top: 20px;">
                    <button type="button" class="button" onclick="document.getElementById('log-details-modal').style.display='none'"><?php _e('Close', 'autosecure-wp'); ?></button>
                </p>
            </div>
        </div>
        
        <script>
        jQuery(document).ready(function($) {
            // Block IP functionality
            $('.block-ip').click(function() {
                var ip = $(this).data('ip');
                if (confirm('<?php _e('Are you sure you want to permanently block this IP address?', 'autosecure-wp'); ?>')) {
                    $.ajax({
                        url: ajaxurl,
                        type: 'POST',
                        data: {
                            action: 'autosecure_block_ip',
                            ip: ip,
                            nonce: '<?php echo wp_create_nonce('autosecure_block_ip'); ?>'
                        },
                        success: function(response) {
                            if (response.success) {
                                alert('<?php _e('IP address has been blocked successfully.', 'autosecure-wp'); ?>');
                                location.reload();
                            } else {
                                alert('<?php _e('Error blocking IP address.', 'autosecure-wp'); ?>');
                            }
                        }
                    });
                }
            });
            
            // View details functionality
            $('.view-details').click(function() {
                var logId = $(this).data('id');
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'autosecure_get_log_details',
                        log_id: logId,
                        nonce: '<?php echo wp_create_nonce('autosecure_get_log_details'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            $('#log-details-content').html(response.data);
                            $('#log-details-modal').show();
                        }
                    }
                });
            });
            
            // Clear all logs functionality
            $('#clear-all-logs').click(function() {
                var button = $(this);
                var spinner = button.next('.spinner');
                
                if (!confirm('<?php _e('Are you sure you want to delete ALL login logs? This action cannot be undone.', 'autosecure-wp'); ?>')) {
                    return;
                }
                
                button.prop('disabled', true);
                spinner.addClass('is-active');
                
                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'autosecure_clear_all_logs',
                        nonce: '<?php echo wp_create_nonce('autosecure_clear_all_logs'); ?>'
                    },
                    success: function(response) {
                        if (response.success) {
                            alert('<?php _e('All login logs have been cleared successfully!', 'autosecure-wp'); ?>');
                            location.reload();
                        } else {
                            alert('<?php _e('Error clearing logs.', 'autosecure-wp'); ?>');
                        }
                    },
                    complete: function() {
                        button.prop('disabled', false);
                        spinner.removeClass('is-active');
                    }
                });
            });
        });
        </script>
        
        <style>
        .card {
            background: #fff;
            border: 1px solid #c3c4c7;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 1px 1px rgba(0,0,0,.04);
        }
        .card h2, .card h3 {
            margin-top: 0;
            padding-bottom: 10px;
            border-bottom: 1px solid #e1e1e1;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        .stat-item {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            text-align: center;
        }
        .stat-number {
            font-size: 24px;
            font-weight: bold;
            display: block;
        }
        .stat-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        .success { color: #00a32a; }
        .failed { color: #d63638; }
        .locked { color: #d63638; }
        </style>
        <?php
    }
    
    /**
     * Get default login options
     */
    private function get_default_login_options() {
        return array(
            'enable_brute_force_protection' => 1,
            'max_login_attempts' => 5,
            'lockout_duration' => 30,
            'enable_progressive_lockout' => 1,
            'permanent_blacklist_attempts' => 20,
            'ip_whitelist' => array(),
            'ip_blacklist' => array()
        );
    }
    
    /**
     * Sanitize login options
     */
    public function sanitize_login_options($input) {
        $sanitized = array();
        
        $sanitized['enable_brute_force_protection'] = isset($input['enable_brute_force_protection']) ? 1 : 0;
        $sanitized['max_login_attempts'] = absint($input['max_login_attempts']) ?: 5;
        $sanitized['lockout_duration'] = absint($input['lockout_duration']) ?: 30;
        $sanitized['enable_progressive_lockout'] = 1;
        $sanitized['permanent_blacklist_attempts'] = 20;
        $sanitized['ip_whitelist'] = array();
        $sanitized['ip_blacklist'] = array();
        $sanitized['auto_cleanup_logs'] = isset($input['auto_cleanup_logs']) ? 1 : 0;
        $sanitized['log_retention_days'] = absint($input['log_retention_days']) ?: 30;
        
        return $sanitized;
    }
    
    /**
     * Display current lockouts
     */
    private function display_current_lockouts() {
        global $wpdb;
        
        // Get current lockout count
        $lockout_count = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_autosecure_lockout_%'"
        );
        
        // Get failed attempts in last hour
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        $recent_attempts = 0;
        
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") == $table_name) {
            $recent_attempts = $wpdb->get_var(
                "SELECT COUNT(*) FROM {$table_name} 
                 WHERE success = 0 AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
            );
        }
        
        ?>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 15px 0;">
            <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; text-align: center;">
                <span style="font-size: 24px; font-weight: bold; color: #dc3232; display: block;"><?php echo $lockout_count ?: 0; ?></span>
                <span style="font-size: 12px; color: #666; text-transform: uppercase;"><?php _e('Currently Locked IPs', 'autosecure-wp'); ?></span>
            </div>
            <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; text-align: center;">
                <span style="font-size: 24px; font-weight: bold; color: #d63638; display: block;"><?php echo $recent_attempts ?: 0; ?></span>
                <span style="font-size: 12px; color: #666; text-transform: uppercase;"><?php _e('Failed Attempts (1 Hour)', 'autosecure-wp'); ?></span>
            </div>
        </div>
        <?php
    }
    
    /**
     * Display login statistics summary
     */
    private function display_login_stats_summary() {
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        if ($wpdb->get_var("SHOW TABLES LIKE '$table_name'") != $table_name) {
            echo '<p>' . __('No login data available yet.', 'autosecure-wp') . '</p>';
            return;
        }
        
        // Get statistics
        $total = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name}") ?: 0;
        $successful = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name} WHERE success = 1") ?: 0;
        $failed = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name} WHERE success = 0") ?: 0;
        $recent = $wpdb->get_var("SELECT COUNT(*) FROM {$table_name} WHERE timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)") ?: 0;
        $unique_ips = $wpdb->get_var("SELECT COUNT(DISTINCT ip_address) FROM {$table_name}") ?: 0;
        $locked = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE '_transient_autosecure_lockout_%'") ?: 0;
        
        ?>
        <div class="stats-grid">
            <div class="stat-item">
                <span class="stat-number" style="color: #0073aa;"><?php echo number_format($total); ?></span>
                <span class="stat-label"><?php _e('Total Attempts', 'autosecure-wp'); ?></span>
            </div>
            <div class="stat-item">
                <span class="stat-number success"><?php echo number_format($successful); ?></span>
                <span class="stat-label"><?php _e('Successful', 'autosecure-wp'); ?></span>
            </div>
            <div class="stat-item">
                <span class="stat-number failed"><?php echo number_format($failed); ?></span>
                <span class="stat-label"><?php _e('Failed', 'autosecure-wp'); ?></span>
            </div>
            <div class="stat-item">
                <span class="stat-number" style="color: #f56e28;"><?php echo number_format($recent); ?></span>
                <span class="stat-label"><?php _e('Last 24 Hours', 'autosecure-wp'); ?></span>
            </div>
            <div class="stat-item">
                <span class="stat-number" style="color: #7c3aed;"><?php echo number_format($unique_ips); ?></span>
                <span class="stat-label"><?php _e('Unique IPs', 'autosecure-wp'); ?></span>
            </div>
            <div class="stat-item">
                <span class="stat-number locked"><?php echo number_format($locked); ?></span>
                <span class="stat-label"><?php _e('Currently Locked', 'autosecure-wp'); ?></span>
            </div>
        </div>
        <?php
    }
    
    /**
     * Check if IP is currently locked
     */
    private function is_ip_currently_locked($ip) {
        $lockout_key = 'autosecure_lockout_' . md5($ip);
        return get_transient($lockout_key) !== false;
    }
    
    /**
     * Parse user agent string
     */
    private function parse_user_agent($user_agent) {
        if (empty($user_agent)) {
            return __('Unknown', 'autosecure-wp');
        }
        
        if (strpos($user_agent, 'Chrome') !== false) {
            return 'Chrome';
        } elseif (strpos($user_agent, 'Firefox') !== false) {
            return 'Firefox';
        } elseif (strpos($user_agent, 'Safari') !== false) {
            return 'Safari';
        } elseif (strpos($user_agent, 'Edge') !== false) {
            return 'Edge';
        } elseif (strpos($user_agent, 'curl') !== false) {
            return 'cURL';
        } else {
            return substr($user_agent, 0, 30) . '...';
        }
    }
    
    /**
     * Handle reset lockouts AJAX request
     */
    public function handle_reset_lockouts() {
        if (!wp_verify_nonce($_POST['nonce'], 'autosecure_reset_lockouts')) {
            wp_send_json_error('Invalid nonce');
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        global $wpdb;
        
        $wpdb->query(
            "DELETE FROM {$wpdb->options} 
             WHERE option_name LIKE '_transient_autosecure_lockout_%' 
             OR option_name LIKE '_transient_timeout_autosecure_lockout_%'"
        );
        
        wp_send_json_success('All lockouts reset successfully');
    }
    
    /**
     * Handle clear attempts AJAX request
     */
    public function handle_clear_attempts() {
        if (!wp_verify_nonce($_POST['nonce'], 'autosecure_clear_attempts')) {
            wp_send_json_error('Invalid nonce');
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        global $wpdb;
        
        wp_send_json_success('All failed attempts cleared successfully');
    }
    
    /**
     * Handle block IP AJAX request
     */
    public function handle_block_ip() {
        if (!wp_verify_nonce($_POST['nonce'], 'autosecure_block_ip')) {
            wp_send_json_error('Invalid nonce');
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        $ip = sanitize_text_field($_POST['ip']);
        
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('Invalid IP address');
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'autosecure_ip_blacklist';
        
        $result = $wpdb->replace(
            $table_name,
            array(
                'ip_address' => $ip,
                'reason' => 'Manually blocked from login logs',
                'created_at' => current_time('mysql'),
                'is_permanent' => 1
            ),
            array('%s', '%s', '%s', '%d')
        );
        
        if ($result !== false) {
            wp_send_json_success('IP blocked successfully');
        } else {
            wp_send_json_error('Error blocking IP');
        }
    }
    
    /**
     * Handle get log details AJAX request
     */
    public function handle_get_log_details() {
        if (!wp_verify_nonce($_POST['nonce'], 'autosecure_get_log_details')) {
            wp_send_json_error('Invalid nonce');
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        $log_id = intval($_POST['log_id']);
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        $log = $wpdb->get_row($wpdb->prepare(
            "SELECT * FROM {$table_name} WHERE id = %d",
            $log_id
        ));
        
        if (!$log) {
            wp_send_json_error('Log entry not found');
        }
        
        $ip_attempts = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} WHERE ip_address = %s",
            $log->ip_address
        ));
        
        $ip_failed_attempts = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$table_name} WHERE ip_address = %s AND success = 0",
            $log->ip_address
        ));
        
        ob_start();
        ?>
        <table class="form-table">
            <tr>
                <th><?php _e('Date & Time', 'autosecure-wp'); ?></th>
                <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($log->timestamp))); ?></td>
            </tr>
            <tr>
                <th><?php _e('Status', 'autosecure-wp'); ?></th>
                <td>
                    <?php if ($log->success): ?>
                        <span style="color: #00a32a; font-weight: bold;">✓ <?php _e('Successful Login', 'autosecure-wp'); ?></span>
                    <?php else: ?>
                        <span style="color: #d63638; font-weight: bold;">✗ <?php _e('Failed Login', 'autosecure-wp'); ?></span>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th><?php _e('IP Address', 'autosecure-wp'); ?></th>
                <td>
                    <code><?php echo esc_html($log->ip_address); ?></code>
                    <?php if ($this->is_ip_currently_locked($log->ip_address)): ?>
                        <br><small style="color: #d63638;"><strong><?php _e('Currently Locked Out', 'autosecure-wp'); ?></strong></small>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th><?php _e('Username Attempted', 'autosecure-wp'); ?></th>
                <td>
                    <strong><?php echo esc_html($log->username); ?></strong>
                    <?php if (username_exists($log->username)): ?>
                        <br><small style="color: #00a32a;"><?php _e('This is a valid WordPress username', 'autosecure-wp'); ?></small>
                    <?php else: ?>
                        <br><small style="color: #d63638;"><?php _e('This username does not exist', 'autosecure-wp'); ?></small>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th><?php _e('User Agent', 'autosecure-wp'); ?></th>
                <td>
                    <code style="font-size: 11px; word-break: break-all;">
                        <?php 
                        $user_agent = isset($log->user_agent) ? $log->user_agent : '';
                        echo esc_html($user_agent ? $user_agent : __('Not recorded', 'autosecure-wp')); 
                        ?>
                    </code>
                </td>
            </tr>
            <tr>
                <th><?php _e('Browser/Client', 'autosecure-wp'); ?></th>
                <td>
                    <?php 
                    $user_agent = isset($log->user_agent) ? $log->user_agent : '';
                    echo esc_html($this->parse_user_agent($user_agent)); 
                    ?>
                </td>
            </tr>
            <tr>
                <th><?php _e('IP Statistics', 'autosecure-wp'); ?></th>
                <td>
                    <strong><?php _e('Total attempts from this IP:', 'autosecure-wp'); ?></strong> <?php echo number_format($ip_attempts); ?><br>
                    <strong><?php _e('Failed attempts from this IP:', 'autosecure-wp'); ?></strong> <?php echo number_format($ip_failed_attempts); ?>
                </td>
            </tr>
        </table>
        <?php
        $content = ob_get_clean();
        
        wp_send_json_success($content);
    }
    
    /**
     * Handle clear all logs AJAX request
     */
    public function handle_clear_all_logs() {
        if (!wp_verify_nonce($_POST['nonce'], 'autosecure_clear_all_logs')) {
            wp_send_json_error('Invalid nonce');
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
        }
        
        global $wpdb;
        
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        $result = $wpdb->query("TRUNCATE TABLE {$table_name}");
        
        if ($result !== false) {
            wp_send_json_success('All logs cleared successfully');
        } else {
            wp_send_json_error('Error clearing logs');
        }
    }
    
    /**
     * Cleanup old logs based on retention settings
     */
    public function cleanup_old_logs() {
        $options = get_option('autosecure_wp_login_options', array());
        
        // Only cleanup if auto-cleanup is enabled
        if (empty($options['auto_cleanup_logs'])) {
            return;
        }
        
        $retention_days = isset($options['log_retention_days']) ? absint($options['log_retention_days']) : 30;
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'autosecure_login_attempts';
        
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$table_name} WHERE timestamp < DATE_SUB(NOW(), INTERVAL %d DAY)",
            $retention_days
        ));
    }
}