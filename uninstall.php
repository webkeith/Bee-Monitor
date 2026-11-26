<?php
/**
 * Bee Monitor uninstall.
 *
 * Scheduled events are always removed. Findings, baseline, log, and settings
 * are removed only when "Delete all Bee Monitor data on uninstall" is enabled.
 *
 * @package BeeMonitor
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery -- removing Bee Monitor tables and options on uninstall.

foreach ( array( 'bee_monitor_scheduled_scan', 'bee_monitor_continue_scan', 'bee_monitor_digest' ) as $bee_monitor_hook ) {
	wp_clear_scheduled_hook( $bee_monitor_hook );
}

$bee_monitor_settings = is_multisite() ? get_site_option( 'bee_monitor_settings' ) : get_option( 'bee_monitor_settings' );
if ( ! is_array( $bee_monitor_settings ) || empty( $bee_monitor_settings['delete_data_on_uninstall'] ) ) {
	return;
}

global $wpdb;
foreach ( array( 'baseline', 'findings', 'log', 'deliveries', 'activity' ) as $bee_monitor_table ) {
	$wpdb->query( $wpdb->prepare( 'DROP TABLE IF EXISTS %i', $wpdb->base_prefix . 'bee_monitor_' . $bee_monitor_table ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange
}

if ( is_multisite() ) {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s", $wpdb->esc_like( 'bee_monitor_' ) . '%' ) );
}
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( 'bee_monitor_' ) . '%' ) );

delete_metadata( 'user', 0, 'bee_monitor_known_networks', '', true );

$bee_monitor_uploads = wp_upload_dir( null, false );
$bee_monitor_qdir    = trailingslashit( $bee_monitor_uploads['basedir'] ) . 'bee-monitor-quarantine';
require_once ABSPATH . 'wp-admin/includes/file.php';
if ( is_dir( $bee_monitor_qdir ) && 'direct' === get_filesystem_method() && WP_Filesystem() ) {
	global $wp_filesystem;
	$wp_filesystem->rmdir( $bee_monitor_qdir, true );
}

$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_transient_bee_monitor_' ) . '%', $wpdb->esc_like( '_transient_timeout_bee_monitor_' ) . '%' ) );
if ( is_multisite() ) {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s OR meta_key LIKE %s", $wpdb->esc_like( '_site_transient_bee_monitor_' ) . '%', $wpdb->esc_like( '_site_transient_timeout_bee_monitor_' ) . '%' ) );
} else {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( '_site_transient_bee_monitor_' ) . '%', $wpdb->esc_like( '_site_transient_timeout_bee_monitor_' ) . '%' ) );
}
