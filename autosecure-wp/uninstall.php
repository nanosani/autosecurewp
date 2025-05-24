<?php
/**
 * AutoSecureWP Uninstall
 *
 * @package AutoSecureWP
 */

// If uninstall not called from WordPress, then exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Clean up plugin options
delete_option('autosecure_wp_activated');
delete_option('autosecure_wp_version');
delete_option('autosecure_wp_login_options');

// Clean up transients
global $wpdb;
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_autosecure_%'");
$wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_autosecure_%'");

// Optionally drop database tables (uncomment if you want to remove all data)
// $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}autosecure_login_attempts");
// $wpdb->query("DROP TABLE IF EXISTS {$wpdb->prefix}autosecure_ip_blacklist");