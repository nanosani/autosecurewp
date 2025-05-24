<?php
/**
 * Plugin Name: AutoSecureWP
 * Plugin URI: https://your-domain.com/autosecure-wp
 * Description: Complete WordPress security solution with advanced protection features.
 * Version: 1.0.0
 * Author: Your Name
 * Author URI: https://your-domain.com
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: autosecure-wp
 * Domain Path: /languages
 * Requires at least: 5.0
 * Tested up to: 6.6
 * Requires PHP: 7.4
 * Network: true
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Define plugin constants
define('AUTOSECURE_WP_VERSION', '1.0.0');
define('AUTOSECURE_WP_PLUGIN_FILE', __FILE__);
define('AUTOSECURE_WP_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('AUTOSECURE_WP_PLUGIN_URL', plugin_dir_url(__FILE__));
define('AUTOSECURE_WP_PLUGIN_BASENAME', plugin_basename(__FILE__));

/**
 * Simple activation function
 */
function autosecure_wp_activate() {
    // Set basic options
    add_option('autosecure_wp_activated', true);
    add_option('autosecure_wp_version', AUTOSECURE_WP_VERSION);
    
    // Create database tables
    autosecure_wp_create_tables();
    
    // Set default login options
    if (!get_option('autosecure_wp_login_options')) {
        add_option('autosecure_wp_login_options', array(
            'enable_brute_force_protection' => 1,
            'max_login_attempts' => 5,
            'lockout_duration' => 30,
            'enable_progressive_lockout' => 1,
            'permanent_blacklist_attempts' => 20,
            'ip_whitelist' => array(),
            'ip_blacklist' => array()
        ));
    }
}

/**
 * Create database tables
 */
function autosecure_wp_create_tables() {
    global $wpdb;
    
    $charset_collate = $wpdb->get_charset_collate();
    
    // Login attempts table
    $table1 = $wpdb->prefix . 'autosecure_login_attempts';
    $sql1 = "CREATE TABLE $table1 (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        username varchar(255),
        timestamp datetime DEFAULT CURRENT_TIMESTAMP,
        success tinyint(1) DEFAULT 0,
        user_agent text,
        attempt_type varchar(50) DEFAULT 'unknown',
        referer varchar(500),
        PRIMARY KEY (id),
        KEY ip_address (ip_address),
        KEY timestamp (timestamp),
        KEY success (success),
        KEY attempt_type (attempt_type)
    ) $charset_collate;";
    
    // IP blacklist table
    $table2 = $wpdb->prefix . 'autosecure_ip_blacklist';
    $sql2 = "CREATE TABLE $table2 (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        ip_address varchar(45) NOT NULL,
        reason varchar(255),
        created_at datetime DEFAULT CURRENT_TIMESTAMP,
        is_permanent tinyint(1) DEFAULT 0,
        PRIMARY KEY (id),
        UNIQUE KEY ip_address (ip_address)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql1);
    dbDelta($sql2);
    
    // Also add missing columns to existing table if they don't exist
    $table_name = $wpdb->prefix . 'autosecure_login_attempts';
    $columns = $wpdb->get_col("DESC {$table_name}", 0);
    
    if (!in_array('attempt_type', $columns)) {
        $wpdb->query("ALTER TABLE {$table_name} ADD COLUMN attempt_type varchar(50) DEFAULT 'unknown'");
    }
    
    if (!in_array('referer', $columns)) {
        $wpdb->query("ALTER TABLE {$table_name} ADD COLUMN referer varchar(500)");
    }
}

/**
 * Simple deactivation function  
 */
function autosecure_wp_deactivate() {
    delete_option('autosecure_wp_activated');
}

// Register hooks
register_activation_hook(__FILE__, 'autosecure_wp_activate');
register_deactivation_hook(__FILE__, 'autosecure_wp_deactivate');

// Only load other files if plugin is activated successfully
if (get_option('autosecure_wp_activated')) {
    // Load main class
    if (file_exists(AUTOSECURE_WP_PLUGIN_DIR . 'includes/class-autosecure-wp.php')) {
        require_once AUTOSECURE_WP_PLUGIN_DIR . 'includes/class-autosecure-wp.php';
        
        /**
         * Initialize the plugin
         */
        function autosecure_wp_init() {
            return AutoSecure_WP::get_instance();
        }
        
        // Initialize plugin
        add_action('plugins_loaded', 'autosecure_wp_init');
    }
}