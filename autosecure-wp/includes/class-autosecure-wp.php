<?php
/**
 * Main AutoSecureWP Class
 *
 * @package AutoSecureWP
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class AutoSecure_WP {
    
    /**
     * Plugin instance
     */
    private static $instance = null;
    
    /**
     * Get plugin instance
     */
    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->init();
    }
    
    /**
     * Initialize plugin
     */
    private function init() {
        // Load admin interface if in admin
        if (is_admin()) {
            $this->load_admin();
        }
        
        // Load login security module
        $this->load_login_security();
    }
    
    /**
     * Load admin interface
     */
    private function load_admin() {
        if (file_exists(AUTOSECURE_WP_PLUGIN_DIR . 'includes/class-admin.php')) {
            require_once AUTOSECURE_WP_PLUGIN_DIR . 'includes/class-admin.php';
            new AutoSecure_WP_Admin();
        }
    }
    
    /**
     * Load login security module
     */
    private function load_login_security() {
        if (file_exists(AUTOSECURE_WP_PLUGIN_DIR . 'includes/class-login-security.php')) {
            require_once AUTOSECURE_WP_PLUGIN_DIR . 'includes/class-login-security.php';
            new AutoSecure_WP_Login_Security();
        }
    }
}