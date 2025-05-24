<?php
/**
 * AutoSecureWP Activator Class
 *
 * @package AutoSecureWP
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class AutoSecure_WP_Activator {
    
    /**
     * Plugin activation
     */
    public static function activate() {
        // Suppress any output during activation
        ob_start();
        
        try {
            // Create database tables
            self::create_database_tables();
            
            // Set plugin options
            self::set_default_options();
            
            // Set activation flag
            add_option('autosecure_wp_activated', true);
            add_option('autosecure_wp_version', AUTOSECURE_WP_VERSION);
            
        } catch (Exception $e) {
            // Log error but don't output anything
            error_log('AutoSecureWP Activation Error: ' . $e->getMessage());
        }
        
        // Clean any output buffer
        ob_end_clean();
    }
    
    /**
     * Create database tables
     */
    private static function create_database_tables() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        // Login attempts table
        $login_table = $wpdb->prefix . 'autosecure_login_attempts';
        $sql1 = "CREATE TABLE $login_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            username varchar(255),
            timestamp datetime DEFAULT CURRENT_TIMESTAMP,
            success tinyint(1) DEFAULT 0,
            user_agent text,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY timestamp (timestamp),
            KEY success (success)
        ) $charset_collate;";
        
        // IP blacklist table
        $blacklist_table = $wpdb->prefix . 'autosecure_ip_blacklist';
        $sql2 = "CREATE TABLE $blacklist_table (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            reason varchar(255),
            created_at datetime DEFAULT CURRENT_TIMESTAMP,
            is_permanent tinyint(1) DEFAULT 0,
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        
        // Create tables individually to avoid concatenation issues
        dbDelta($sql1);
        dbDelta($sql2);
    }
    
    /**
     * Set default plugin options
     */
    private static function set_default_options() {
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
}