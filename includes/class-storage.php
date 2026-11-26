<?php
/**
 * Database tables, network-wide options, scan lock, and the Bee Monitor log.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bee Monitor custom tables have no WordPress API; results must not be served from a cache an attacker could poison.

/**
 * Persistence layer for Bee Monitor.
 */
final class Storage {

	const OPTION_PREFIX = 'bee_monitor_';

	/**
	 * Option keys created by Bee Monitor, used by uninstall.
	 *
	 * @var string[]
	 */
	const OPTION_KEYS = array(
		'settings',
		'settings_hash',
		'db_version',
		'baseline_meta',
		'scan_state',
		'scan_counter',
		'last_scan',
		'lock',
		'context',
		'snapshot_users',
		'snapshot_roles',
		'snapshot_options',
		'snapshot_cron',
		'last_content_sweep',
		'mail_window',
		'mail_status',
		'heartbeat_status',
		'login_bucket',
		'trusted_urls',
		'deploy_until',
		'digest_sig',
		'cancel_scan',
		'snapshot_app_passwords',
		'quarantine',
		'last_remote_check',
	);

	/**
	 * Full table name.
	 *
	 * @param string $name Short name: baseline, findings, log.
	 * @return string
	 */
	public static function table( $name ) {
		global $wpdb;
		return $wpdb->base_prefix . 'bee_monitor_' . $name;
	}

	/**
	 * Read a Bee Monitor option (network-wide on multisite).
	 *
	 * @param string $key     Key without prefix.
	 * @param mixed  $fallback Default value.
	 * @return mixed
	 */
	public static function get( $key, $fallback = false ) {
		if ( is_multisite() ) {
			return get_site_option( self::OPTION_PREFIX . $key, $fallback );
		}
		return get_option( self::OPTION_PREFIX . $key, $fallback );
	}

	/**
	 * Read an option directly from the database, bypassing the per-request cache
	 * (used for flags set by another request, such as scan cancellation).
	 *
	 * @param string $key      Key without prefix.
	 * @param mixed  $fallback Default.
	 * @return mixed
	 */
	public static function get_fresh( $key, $fallback = false ) {
		$name = self::OPTION_PREFIX . $key;
		if ( is_multisite() ) {
			wp_cache_delete( get_current_network_id() . ':' . $name, 'site-options' );
		} else {
			wp_cache_delete( $name, 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
		return self::get( $key, $fallback );
	}

	/**
	 * Write a Bee Monitor option without autoloading it on single sites.
	 *
	 * @param string $key   Key without prefix.
	 * @param mixed  $value Value.
	 * @return bool
	 */
	public static function set( $key, $value ) {
		if ( is_multisite() ) {
			return update_site_option( self::OPTION_PREFIX . $key, $value );
		}
		return update_option( self::OPTION_PREFIX . $key, $value, false );
	}

	/**
	 * Delete a Bee Monitor option.
	 *
	 * @param string $key Key without prefix.
	 * @return bool
	 */
	public static function delete( $key ) {
		if ( is_multisite() ) {
			return delete_site_option( self::OPTION_PREFIX . $key );
		}
		return delete_option( self::OPTION_PREFIX . $key );
	}

	/**
	 * Create or upgrade tables.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$charset  = $wpdb->get_charset_collate();
		$baseline = self::table( 'baseline' );
		$findings = self::table( 'findings' );
		$log      = self::table( 'log' );
		$delivery = self::table( 'deliveries' );
		$activity = self::table( 'activity' );

		dbDelta(
			"CREATE TABLE {$baseline} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				path_key char(32) NOT NULL,
				path text NOT NULL,
				area varchar(20) NOT NULL DEFAULT '',
				sha256 char(64) NOT NULL DEFAULT '',
				size bigint(20) unsigned NOT NULL DEFAULT 0,
				mtime bigint(20) unsigned NOT NULL DEFAULT 0,
				mac char(64) NOT NULL DEFAULT '',
				last_seen_scan bigint(20) unsigned NOT NULL DEFAULT 0,
				updated_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				UNIQUE KEY path_key (path_key),
				KEY last_seen_scan (last_seen_scan)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$findings} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				fingerprint char(32) NOT NULL,
				rule varchar(64) NOT NULL,
				severity tinyint(3) unsigned NOT NULL DEFAULT 0,
				confidence varchar(16) NOT NULL DEFAULT '',
				basis varchar(16) NOT NULL DEFAULT '',
				change_type varchar(32) NOT NULL DEFAULT '',
				subject text NOT NULL,
				reason text NOT NULL,
				evidence longtext NULL,
				status varchar(16) NOT NULL DEFAULT 'open',
				first_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				last_seen datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				occurrences int(10) unsigned NOT NULL DEFAULT 1,
				notified_at datetime NULL DEFAULT NULL,
				reminded_at datetime NULL DEFAULT NULL,
				resolved_by bigint(20) unsigned NOT NULL DEFAULT 0,
				resolved_at datetime NULL DEFAULT NULL,
				resolution_note text NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY fingerprint (fingerprint),
				KEY status_severity (status,severity),
				KEY last_seen (last_seen)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$log} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				level varchar(10) NOT NULL DEFAULT 'info',
				message varchar(255) NOT NULL DEFAULT '',
				context text NULL,
				PRIMARY KEY  (id),
				KEY created_at (created_at)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$delivery} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				finding_id bigint(20) unsigned NOT NULL,
				recipient char(32) NOT NULL,
				kind varchar(16) NOT NULL DEFAULT 'immediate',
				sent_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				PRIMARY KEY  (id),
				KEY finding_recipient (finding_id,recipient)
			) {$charset};"
		);

		dbDelta(
			"CREATE TABLE {$activity} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				created_at datetime NOT NULL DEFAULT '1970-01-01 00:00:00',
				type varchar(32) NOT NULL DEFAULT '',
				object varchar(191) NOT NULL DEFAULT '',
				actor bigint(20) unsigned NOT NULL DEFAULT 0,
				via varchar(16) NOT NULL DEFAULT '',
				detail varchar(255) NOT NULL DEFAULT '',
				PRIMARY KEY  (id),
				KEY created_at (created_at),
				KEY type (type),
				KEY actor (actor)
			) {$charset};"
		);

		self::set( 'db_version', BEE_MONITOR_DB_VERSION );
	}

	/**
	 * Run install when the schema version changes.
	 */
	public static function maybe_upgrade() {
		if ( BEE_MONITOR_DB_VERSION !== (string) self::get( 'db_version', '' ) ) {
			self::install();
		}
	}

	/**
	 * Whether all Bee Monitor tables exist.
	 *
	 * @return bool
	 */
	public static function tables_exist() {
		global $wpdb;
		static $exists = null;
		if ( true === $exists ) {
			return true;
		}
		foreach ( array( 'baseline', 'findings', 'log', 'deliveries', 'activity' ) as $name ) {
			$table = self::table( $name );
			$found = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $table ) ) );
			if ( $found !== $table ) {
				return false;
			}
		}
		$exists = true;
		return true;
	}

	/**
	 * Write a log entry. Context must already be free of secrets.
	 *
	 * @param string $level   info|warning|error.
	 * @param string $message Message.
	 * @param array  $context Extra data.
	 */
	public static function log( $level, $message, $context = array() ) {
		global $wpdb;
		$wpdb->insert(
			self::table( 'log' ),
			array(
				'created_at' => current_time( 'mysql', true ),
				'level'      => substr( sanitize_key( $level ), 0, 10 ),
				'message'    => substr( wp_strip_all_tags( $message ), 0, 255 ),
				'context'    => $context ? wp_json_encode( $context ) : null,
			),
			array( '%s', '%s', '%s', '%s' )
		);
	}

	/**
	 * Recent log entries.
	 *
	 * @param int $limit Max rows.
	 * @return array
	 */
	public static function recent_log( $limit = 50 ) {
		global $wpdb;
		$table = self::table( 'log' );
		return (array) $wpdb->get_results(
			$wpdb->prepare( 'SELECT created_at, level, message, context FROM %i ORDER BY id DESC LIMIT %d', $table, $limit ),
			ARRAY_A
		);
	}

	/**
	 * Keep the log bounded.
	 *
	 * @param int $keep Rows to keep.
	 */
	public static function prune_log( $keep = 2000 ) {
		global $wpdb;
		$table = self::table( 'log' );
		$max   = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT MAX(id) FROM %i', $table ) );
		if ( $max > $keep ) {
			$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE id <= %d', $table, $max - $keep ) );
		}
	}

	/**
	 * Acquire the scan lock.
	 *
	 * @param int $ttl Seconds after which a lock is considered stale.
	 * @return string|false Token or false when locked.
	 */
	public static function acquire_lock( $ttl = 600 ) {
		$lock = self::get( 'lock', array() );
		if ( is_array( $lock ) && ! empty( $lock['time'] ) && (int) $lock['time'] > time() - $ttl ) {
			return false;
		}
		$token = wp_generate_password( 20, false );
		self::set(
			'lock',
			array(
				'token' => $token,
				'time'  => time(),
			)
		);
		$check = self::get( 'lock', array() );
		return ( is_array( $check ) && isset( $check['token'] ) && $check['token'] === $token ) ? $token : false;
	}

	/**
	 * Release the scan lock if we own it.
	 *
	 * @param string $token Token from acquire_lock().
	 */
	public static function release_lock( $token ) {
		$lock = self::get( 'lock', array() );
		if ( is_array( $lock ) && isset( $lock['token'] ) && $lock['token'] === $token ) {
			self::delete( 'lock' );
		}
	}

	/**
	 * Record the current site and admin URLs as trusted for use in email links.
	 */
	public static function remember_urls() {
		self::set(
			'trusted_urls',
			array(
				'home'  => network_home_url( '/' ),
				'admin' => is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' ),
			)
		);
	}

	/**
	 * Trusted URLs, recording them on first use.
	 *
	 * @return array home, admin.
	 */
	public static function trusted_urls() {
		$urls = self::get( 'trusted_urls', array() );
		if ( ! is_array( $urls ) || empty( $urls['home'] ) || empty( $urls['admin'] ) ) {
			self::remember_urls();
			$urls = self::get( 'trusted_urls', array() );
		}
		return $urls;
	}

	/**
	 * Secret used to sign baseline rows.
	 *
	 * @return string
	 */
	public static function mac_key() {
		if ( defined( 'BEE_MONITOR_HMAC_KEY' ) && is_string( BEE_MONITOR_HMAC_KEY ) && strlen( BEE_MONITOR_HMAC_KEY ) >= 32 ) {
			return BEE_MONITOR_HMAC_KEY;
		}
		return wp_salt( 'secure_auth' ) . '|bee-monitor-baseline';
	}

	/**
	 * Short fingerprint of the signing key, safe to store.
	 *
	 * @return string
	 */
	public static function mac_key_fingerprint() {
		return substr( hash( 'sha256', 'fp|' . self::mac_key() ), 0, 16 );
	}

	/**
	 * Signature for a baseline row.
	 *
	 * @param string $path_key Path key.
	 * @param string $sha256   File hash.
	 * @param int    $size     File size.
	 * @return string
	 */
	public static function row_mac( $path_key, $sha256, $size ) {
		return hash_hmac( 'sha256', $path_key . '|' . $sha256 . '|' . (int) $size, self::mac_key() );
	}

	/**
	 * Baseline rows for a set of path keys.
	 *
	 * @param string[] $keys Path keys.
	 * @return array Rows keyed by path_key.
	 */
	public static function baseline_rows( array $keys ) {
		global $wpdb;
		if ( empty( $keys ) ) {
			return array();
		}
		$table        = self::table( 'baseline' );
		$placeholders = implode( ',', array_fill( 0, count( $keys ), '%s' ) );
		$rows         = $wpdb->get_results(
			$wpdb->prepare( "SELECT id, path_key, path, area, sha256, size, mtime, mac FROM %i WHERE path_key IN ({$placeholders})", array_merge( array( $table ), $keys ) ), // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
			ARRAY_A
		);
		$out          = array();
		foreach ( (array) $rows as $row ) {
			$out[ $row['path_key'] ] = $row;
		}
		return $out;
	}

	/**
	 * Insert or replace a baseline row.
	 *
	 * @param string $rel     Relative path.
	 * @param string $area    Area.
	 * @param string $sha256  Hash.
	 * @param int    $size    Size.
	 * @param int    $mtime   Modified time.
	 * @param int    $scan_id Scan ID.
	 */
	public static function upsert_baseline( $rel, $area, $sha256, $size, $mtime, $scan_id ) {
		global $wpdb;
		$key = md5( $rel );
		$wpdb->replace(
			self::table( 'baseline' ),
			array(
				'path_key'       => $key,
				'path'           => $rel,
				'area'           => $area,
				'sha256'         => $sha256,
				'size'           => (int) $size,
				'mtime'          => (int) $mtime,
				'mac'            => self::row_mac( $key, $sha256, $size ),
				'last_seen_scan' => (int) $scan_id,
				'updated_at'     => current_time( 'mysql', true ),
			),
			array( '%s', '%s', '%s', '%s', '%d', '%d', '%s', '%d', '%s' )
		);
	}

	/**
	 * Update only the stored mtime (not part of the signature).
	 *
	 * @param string $key   Path key.
	 * @param int    $mtime Modified time.
	 */
	public static function touch_baseline( $key, $mtime ) {
		global $wpdb;
		$wpdb->update( self::table( 'baseline' ), array( 'mtime' => (int) $mtime ), array( 'path_key' => $key ), array( '%d' ), array( '%s' ) );
	}

	/**
	 * Remove a baseline row.
	 *
	 * @param string $rel Relative path.
	 */
	public static function delete_baseline( $rel ) {
		global $wpdb;
		$wpdb->delete( self::table( 'baseline' ), array( 'path_key' => md5( $rel ) ), array( '%s' ) );
	}

	/**
	 * Mark baseline rows as seen by a scan.
	 *
	 * @param string[] $keys    Path keys.
	 * @param int      $scan_id Scan ID.
	 */
	public static function mark_seen( array $keys, $scan_id ) {
		global $wpdb;
		if ( empty( $keys ) ) {
			return;
		}
		$table        = self::table( 'baseline' );
		$placeholders = implode( ',', array_fill( 0, count( $keys ), '%s' ) );
		$args         = array_merge( array( (int) $scan_id ), array_values( $keys ) );
		$wpdb->query( $wpdb->prepare( "UPDATE %i SET last_seen_scan = %d WHERE path_key IN ({$placeholders})", array_merge( array( $table ), $args ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- one placeholder per key.
	}

	/**
	 * Baseline rows not seen by a scan, paged by ID.
	 *
	 * @param int $scan_id Scan ID.
	 * @param int $after   Cursor.
	 * @param int $limit   Page size.
	 * @return array
	 */
	public static function unseen_rows( $scan_id, $after, $limit ) {
		global $wpdb;
		$table = self::table( 'baseline' );
		return (array) $wpdb->get_results(
			$wpdb->prepare( 'SELECT id, path_key, path, area, sha256, size, mac FROM %i WHERE last_seen_scan < %d AND id > %d ORDER BY id ASC LIMIT %d', $table, $scan_id, $after, $limit ),
			ARRAY_A
		);
	}

	/**
	 * Number of baseline rows.
	 *
	 * @return int
	 */
	public static function baseline_count() {
		global $wpdb;
		$table = self::table( 'baseline' );
		return (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i', $table ) );
	}

	/**
	 * Baseline row counts per area.
	 *
	 * @return array
	 */
	public static function baseline_area_counts() {
		global $wpdb;
		$table = self::table( 'baseline' );
		$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT area, COUNT(*) AS total FROM %i GROUP BY area ORDER BY area', $table ), ARRAY_A );
		$out   = array();
		foreach ( (array) $rows as $row ) {
			$out[ $row['area'] ] = (int) $row['total'];
		}
		return $out;
	}

	/**
	 * Hash identifying a recipient without storing the address.
	 *
	 * @param string $email Email.
	 * @return string
	 */
	public static function recipient_key( $email ) {
		return md5( strtolower( trim( (string) $email ) ) );
	}

	/**
	 * Record deliveries of findings to a recipient.
	 *
	 * @param int[]  $ids   Finding IDs.
	 * @param string $email Recipient.
	 * @param string $kind  immediate|digest.
	 */
	public static function record_deliveries( array $ids, $email, $kind ) {
		global $wpdb;
		$key = self::recipient_key( $email );
		$now = current_time( 'mysql', true );
		foreach ( array_unique( array_map( 'absint', $ids ) ) as $id ) {
			if ( $id ) {
				$wpdb->insert(
					self::table( 'deliveries' ),
					array(
						'finding_id' => $id,
						'recipient'  => $key,
						'kind'       => substr( sanitize_key( $kind ), 0, 16 ),
						'sent_at'    => $now,
					),
					array( '%d', '%s', '%s', '%s' )
				);
			}
		}
	}

	/**
	 * Which recipients each finding has been delivered to.
	 *
	 * @param int[] $ids Finding IDs.
	 * @return array finding_id => [ recipient_key => true ].
	 */
	public static function delivered_map( array $ids ) {
		global $wpdb;
		$ids = array_values( array_filter( array_map( 'absint', $ids ) ) );
		$map = array();
		if ( empty( $ids ) ) {
			return $map;
		}
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$rows         = $wpdb->get_results( $wpdb->prepare( "SELECT finding_id, recipient FROM %i WHERE finding_id IN ({$placeholders})", array_merge( array( self::table( 'deliveries' ) ), $ids ) ), ARRAY_A ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- one placeholder per ID.
		foreach ( (array) $rows as $row ) {
			$map[ (int) $row['finding_id'] ][ $row['recipient'] ] = true;
		}
		return $map;
	}

	/**
	 * Remove delivery records of findings that no longer exist.
	 */
	public static function prune_deliveries() {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE finding_id NOT IN ( SELECT id FROM %i )', self::table( 'deliveries' ), self::table( 'findings' ) ) );
	}

	/**
	 * Delete closed findings not seen within the retention period.
	 *
	 * @param int $days Retention in days; 0 keeps everything.
	 * @return int Rows deleted.
	 */
	public static function purge_findings( $days ) {
		global $wpdb;
		$days = (int) $days;
		if ( $days <= 0 ) {
			return 0;
		}
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		return (int) $wpdb->query( $wpdb->prepare( 'DELETE FROM %i WHERE status IN (%s, %s, %s) AND last_seen < %s', self::table( 'findings' ), 'resolved', 'expected', 'auto', $cutoff ) );
	}

	/**
	 * Empty the baseline table.
	 */
	public static function clear_baseline() {
		global $wpdb;
		$table = self::table( 'baseline' );
		$wpdb->query( $wpdb->prepare( 'DELETE FROM %i', $table ) );
	}
}
