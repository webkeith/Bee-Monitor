<?php
/**
 * Security activity log: who changed what, when, and how.
 *
 * Stores the acting user ID (never names or emails), the channel, and short details.
 * Rows older than the retention period are deleted automatically.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bee Monitor custom table; the log must reflect the database, not a cache.

/**
 * Activity log.
 */
final class Activity {

	const PER_PAGE = 50;

	/**
	 * Record an event.
	 *
	 * @param string   $type   Event type.
	 * @param string   $subject Object (plugin slug, option name, user ID, path, ...).
	 * @param string   $detail Short detail.
	 * @param int|null $actor  Acting user ID (defaults to the current user).
	 */
	public static function log( $type, $subject, $detail = '', $actor = null ) {
		global $wpdb;
		if ( BEE_MONITOR_DB_VERSION !== (string) Storage::get( 'db_version', '' ) ) {
			return;
		}
		$wpdb->insert(
			Storage::table( 'activity' ),
			array(
				'created_at' => current_time( 'mysql', true ),
				'type'       => substr( sanitize_key( $type ), 0, 32 ),
				'object'     => substr( sanitize_text_field( (string) $subject ), 0, 191 ),
				'actor'      => null === $actor ? get_current_user_id() : (int) $actor,
				'via'        => Context::via(),
				'detail'     => substr( sanitize_text_field( (string) $detail ), 0, 255 ),
			),
			array( '%s', '%s', '%s', '%d', '%s', '%s' )
		);
	}

	/**
	 * Page of events, newest first.
	 *
	 * @param string $type Type filter or ''.
	 * @param int    $page Page.
	 * @return array items, total.
	 */
	public static function query( $type, $page ) {
		global $wpdb;
		$table  = Storage::table( 'activity' );
		$offset = max( 0, ( (int) $page - 1 ) * self::PER_PAGE );
		if ( '' === $type ) {
			$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i ORDER BY id DESC LIMIT %d OFFSET %d', $table, self::PER_PAGE, $offset ), ARRAY_A );
		} else {
			$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE type = %s', $table, $type ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE type = %s ORDER BY id DESC LIMIT %d OFFSET %d', $table, $type, self::PER_PAGE, $offset ), ARRAY_A );
		}
		return array(
			'items' => (array) $rows,
			'total' => $total,
		);
	}

	/**
	 * Number of events since a time.
	 *
	 * @param int $since Unix time.
	 * @return int
	 */
	public static function count_since( $since ) {
		global $wpdb;
		if ( BEE_MONITOR_DB_VERSION !== (string) Storage::get( 'db_version', '' ) ) {
			return 0;
		}
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE created_at >= %s', Storage::table( 'activity' ), gmdate( 'Y-m-d H:i:s', (int) $since ) ) );
	}

	/**
	 * Delete events older than the retention period.
	 *
	 * @param int $days Days to keep.
	 * @return int Rows deleted.
	 */
	public static function purge( $days ) {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 1, (int) $days ) * DAY_IN_SECONDS );
		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE created_at < %s', Storage::table( 'activity' ), $cutoff ) );
	}

	/**
	 * Delete every event.
	 *
	 * @return int Rows deleted.
	 */
	public static function delete_all() {
		global $wpdb;
		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i', Storage::table( 'activity' ) ) );
	}

	/**
	 * Events performed by a user (privacy export).
	 *
	 * @param int $user_id User ID.
	 * @return array
	 */
	public static function for_actor( $user_id ) {
		global $wpdb;
		return (array) $wpdb->get_results( $wpdb->prepare( 'SELECT created_at, type, object, via, detail FROM %i WHERE actor = %d ORDER BY id DESC LIMIT 500', Storage::table( 'activity' ), $user_id ), ARRAY_A );
	}

	/**
	 * Remove a user from the log (privacy erase): events are kept, the actor is cleared.
	 *
	 * @param int $user_id User ID.
	 * @return int Rows changed.
	 */
	public static function anonymize_actor( $user_id ) {
		global $wpdb;
		return (int) $wpdb->query( $wpdb->prepare( 'UPDATE %i SET actor = 0 WHERE actor = %d', Storage::table( 'activity' ), $user_id ) );
	}

	/**
	 * Event types and labels.
	 *
	 * @return array
	 */
	public static function types() {
		return array(
			'update_core'        => __( 'WordPress core updated', 'bee-monitor' ),
			'update_plugin'      => __( 'Plugin installed, updated, or deleted', 'bee-monitor' ),
			'update_theme'       => __( 'Theme installed, updated, or deleted', 'bee-monitor' ),
			'update_translation' => __( 'Translations updated', 'bee-monitor' ),
			'activated_plugin'   => __( 'Plugin activated', 'bee-monitor' ),
			'deactivated_plugin' => __( 'Plugin deactivated', 'bee-monitor' ),
			'switch_theme'       => __( 'Theme switched', 'bee-monitor' ),
			'user_change'        => __( 'User created or role changed', 'bee-monitor' ),
			'user_deleted'       => __( 'User deleted', 'bee-monitor' ),
			'profile_update'     => __( 'User profile updated', 'bee-monitor' ),
			'app_password'       => __( 'Application password created', 'bee-monitor' ),
			'option_update'      => __( 'Key setting changed', 'bee-monitor' ),
			'scan_completed'     => __( 'Scan completed', 'bee-monitor' ),
			'scan_cancelled'     => __( 'Scan cancelled', 'bee-monitor' ),
			'finding_status'     => __( 'Finding status changed', 'bee-monitor' ),
			'bm_settings'        => __( 'Bee Monitor settings saved', 'bee-monitor' ),
			'baseline'           => __( 'Baseline rebuilt or changes accepted', 'bee-monitor' ),
			'report_exported'    => __( 'Report exported', 'bee-monitor' ),
			'file_repaired'      => __( 'File repaired from official source', 'bee-monitor' ),
			'file_quarantined'   => __( 'File quarantined', 'bee-monitor' ),
			'file_restored'      => __( 'Quarantined file restored', 'bee-monitor' ),
			'quarantine_deleted' => __( 'Quarantined copy deleted', 'bee-monitor' ),
			'activity_cleared'   => __( 'Activity log cleared', 'bee-monitor' ),
		);
	}

	/**
	 * Label for a type.
	 *
	 * @param string $type Type.
	 * @return string
	 */
	public static function label( $type ) {
		$types = self::types();
		return isset( $types[ $type ] ) ? $types[ $type ] : $type;
	}
}
