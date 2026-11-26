<?php
/**
 * Findings: recording, deduplication, status, and descriptions.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Bee Monitor custom tables have no WordPress API; findings must reflect the database, not a cache.

/**
 * Findings repository.
 */
final class Findings {

	const INFO     = 0;
	const LOW      = 1;
	const MEDIUM   = 2;
	const HIGH     = 3;
	const CRITICAL = 4;

	const STATUS_OPEN     = 'open';
	const STATUS_EXPECTED = 'expected';
	const STATUS_RESOLVED = 'resolved';
	const STATUS_AUTO     = 'auto';

	/**
	 * Record a finding, deduplicating by fingerprint.
	 *
	 * Expected: same fingerprint stays silent forever.
	 * Resolved: reappearance reopens and alerts once.
	 *
	 * @param array $f rule, severity, confidence, basis, change_type, subject, reason, evidence, key, status.
	 * @return int Finding ID.
	 */
	public static function record( array $f ) {
		global $wpdb;
		$table = Storage::table( 'findings' );
		$now   = current_time( 'mysql', true );

		$f = wp_parse_args(
			$f,
			array(
				'rule'        => 'unknown',
				'severity'    => self::LOW,
				'confidence'  => 'low',
				'basis'       => 'heuristic',
				'change_type' => '',
				'subject'     => '',
				'reason'      => '',
				'evidence'    => array(),
				'key'         => '',
				'status'      => self::STATUS_OPEN,
			)
		);

		$fingerprint = md5( $f['rule'] . '|' . $f['subject'] . '|' . $f['key'] );
		$existing    = $wpdb->get_row( $wpdb->prepare( 'SELECT id, status FROM %i WHERE fingerprint = %s', $table, $fingerprint ), ARRAY_A );

		if ( $existing ) {
			$data    = array( 'last_seen' => $now );
			$formats = array( '%s' );
			if ( self::STATUS_RESOLVED === $existing['status'] && self::STATUS_OPEN === $f['status'] ) {
				$data['status']      = self::STATUS_OPEN;
				$data['notified_at'] = null;
				$data['reminded_at'] = null;
				$formats[]           = '%s';
				$formats[]           = '%s';
				$formats[]           = '%s';
				Storage::log( 'warning', 'Bee Monitor: resolved finding reappeared', array( 'id' => (int) $existing['id'] ) );
			}
			$wpdb->update( $table, $data, array( 'id' => (int) $existing['id'] ), $formats, array( '%d' ) );
			$wpdb->query( $wpdb->prepare( 'UPDATE %i SET occurrences = occurrences + 1 WHERE id = %d', $table, (int) $existing['id'] ) );
			return (int) $existing['id'];
		}

		$wpdb->insert(
			$table,
			array(
				'fingerprint' => $fingerprint,
				'rule'        => substr( sanitize_key( $f['rule'] ), 0, 64 ),
				'severity'    => max( self::INFO, min( self::CRITICAL, (int) $f['severity'] ) ),
				'confidence'  => substr( sanitize_key( $f['confidence'] ), 0, 16 ),
				'basis'       => substr( sanitize_key( $f['basis'] ), 0, 16 ),
				'change_type' => substr( sanitize_key( $f['change_type'] ), 0, 32 ),
				'subject'     => substr( (string) $f['subject'], 0, 1000 ),
				'reason'      => substr( (string) $f['reason'], 0, 2000 ),
				'evidence'    => wp_json_encode( $f['evidence'] ),
				'status'      => $f['status'],
				'first_seen'  => $now,
				'last_seen'   => $now,
				'occurrences' => 1,
				'notified_at' => ( self::STATUS_OPEN === $f['status'] ) ? null : $now,
			),
			array( '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);
		$id = (int) $wpdb->insert_id;
		if ( self::STATUS_OPEN === $f['status'] && $f['severity'] >= self::MEDIUM ) {
			Storage::log(
				'warning',
				sprintf( 'Bee Monitor finding #%d: %s', $id, $f['rule'] ),
				array(
					'severity' => self::severity_key( (int) $f['severity'] ),
					'subject'  => substr( (string) $f['subject'], 0, 200 ),
				)
			);
		}
		return $id;
	}

	/**
	 * One finding.
	 *
	 * @param int $id ID.
	 * @return array|null
	 */
	public static function get( $id ) {
		global $wpdb;
		$table = Storage::table( 'findings' );
		$row   = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM %i WHERE id = %d', $table, $id ), ARRAY_A );
		return $row ? self::hydrate( $row ) : null;
	}

	/**
	 * Query findings.
	 *
	 * @param array $args status, min_severity, per_page, page.
	 * @return array items, total.
	 */
	public static function query( array $args ) {
		global $wpdb;
		$table = Storage::table( 'findings' );
		$args  = wp_parse_args(
			$args,
			array(
				'status'       => self::STATUS_OPEN,
				'min_severity' => 0,
				'per_page'     => 50,
				'page'         => 1,
			)
		);

		$min    = (int) $args['min_severity'];
		$limit  = (int) $args['per_page'];
		$offset = max( 0, ( (int) $args['page'] - 1 ) * $limit );
		if ( 'all' === $args['status'] ) {
			$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE severity >= %d', $table, $min ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE severity >= %d ORDER BY severity DESC, last_seen DESC, id DESC LIMIT %d OFFSET %d', $table, $min, $limit, $offset ), ARRAY_A );
		} else {
			$total = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM %i WHERE severity >= %d AND status = %s', $table, $min, $args['status'] ) );
			$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE severity >= %d AND status = %s ORDER BY severity DESC, last_seen DESC, id DESC LIMIT %d OFFSET %d', $table, $min, $args['status'], $limit, $offset ), ARRAY_A );
		}

		return array(
			'items' => array_map( array( __CLASS__, 'hydrate' ), (array) $rows ),
			'total' => $total,
		);
	}

	/**
	 * Open findings not yet emailed.
	 *
	 * @param int $min_severity Minimum severity.
	 * @param int $max_severity Maximum severity.
	 * @return array
	 */
	public static function pending( $min_severity, $max_severity = self::CRITICAL ) {
		global $wpdb;
		$table = Storage::table( 'findings' );
		$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE status = %s AND notified_at IS NULL AND severity BETWEEN %d AND %d ORDER BY severity DESC, id ASC LIMIT 500', $table, self::STATUS_OPEN, $min_severity, $max_severity ), ARRAY_A );
		return array_map( array( __CLASS__, 'hydrate' ), (array) $rows );
	}

	/**
	 * Open high-severity findings due for a reminder.
	 *
	 * @param int $days Reminder interval in days.
	 * @return array
	 */
	public static function due_reminders( $days ) {
		global $wpdb;
		if ( $days <= 0 ) {
			return array();
		}
		$table  = Storage::table( 'findings' );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - $days * DAY_IN_SECONDS );
		$rows   = $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM %i WHERE status = %s AND severity >= %d AND notified_at IS NOT NULL AND notified_at < %s AND ( reminded_at IS NULL OR reminded_at < %s ) ORDER BY severity DESC LIMIT 100', $table, self::STATUS_OPEN, self::HIGH, $cutoff, $cutoff ), ARRAY_A );
		return array_map( array( __CLASS__, 'hydrate' ), (array) $rows );
	}

	/**
	 * Mark findings as emailed.
	 *
	 * @param int[]  $ids    IDs.
	 * @param string $column notified_at or reminded_at.
	 */
	public static function mark_sent( array $ids, $column = 'notified_at' ) {
		global $wpdb;
		$ids = array_filter( array_map( 'absint', $ids ) );
		if ( empty( $ids ) ) {
			return;
		}
		$column       = 'reminded_at' === $column ? 'reminded_at' : 'notified_at';
		$table        = Storage::table( 'findings' );
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$params       = array_merge( array( current_time( 'mysql', true ) ), $ids );
		$wpdb->query( $wpdb->prepare( "UPDATE %i SET %i = %s WHERE id IN ({$placeholders})", array_merge( array( $table, $column ), $params ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- one placeholder per ID.
	}

	/**
	 * Change the status of findings.
	 *
	 * @param int[]  $ids     IDs.
	 * @param string $status  New status.
	 * @param string $note    Note.
	 * @param int    $user_id Acting user.
	 * @return int Rows changed.
	 */
	public static function set_status( array $ids, $status, $note, $user_id ) {
		global $wpdb;
		$ids = array_filter( array_map( 'absint', $ids ) );
		if ( empty( $ids ) || ! in_array( $status, array( self::STATUS_OPEN, self::STATUS_EXPECTED, self::STATUS_RESOLVED ), true ) ) {
			return 0;
		}
		$table        = Storage::table( 'findings' );
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$now          = current_time( 'mysql', true );
		$params       = array_merge( array( $status, (int) $user_id, $now, substr( (string) $note, 0, 1000 ) ), $ids );
		return (int) $wpdb->query( $wpdb->prepare( "UPDATE %i SET status = %s, resolved_by = %d, resolved_at = %s, resolution_note = %s WHERE id IN ({$placeholders})", array_merge( array( $table ), $params ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- $params is a merged array matching every placeholder.
	}

	/**
	 * Counts of open findings per severity.
	 *
	 * @return array
	 */
	public static function open_counts() {
		global $wpdb;
		$table = Storage::table( 'findings' );
		$rows  = $wpdb->get_results( $wpdb->prepare( 'SELECT severity, COUNT(*) AS total FROM %i WHERE status = %s GROUP BY severity', $table, self::STATUS_OPEN ), ARRAY_A );
		$out   = array_fill( 0, 5, 0 );
		foreach ( (array) $rows as $row ) {
			$out[ (int) $row['severity'] ] = (int) $row['total'];
		}
		return $out;
	}

	/**
	 * Decode stored JSON.
	 *
	 * @param array $row Row.
	 * @return array
	 */
	public static function hydrate( $row ) {
		$row['evidence'] = json_decode( (string) $row['evidence'], true );
		if ( ! is_array( $row['evidence'] ) ) {
			$row['evidence'] = array();
		}
		$row['severity'] = (int) $row['severity'];
		$row['id']       = (int) $row['id'];
		return $row;
	}

	/**
	 * Severity key.
	 *
	 * @param int $severity Severity.
	 * @return string
	 */
	public static function severity_key( $severity ) {
		$keys = array( 'info', 'low', 'medium', 'high', 'critical' );
		return isset( $keys[ $severity ] ) ? $keys[ $severity ] : 'info';
	}

	/**
	 * Translated severity label.
	 *
	 * @param int $severity Severity.
	 * @return string
	 */
	public static function severity_label( $severity ) {
		$labels = array(
			__( 'Info', 'bee-monitor' ),
			__( 'Low', 'bee-monitor' ),
			__( 'Medium', 'bee-monitor' ),
			__( 'High', 'bee-monitor' ),
			__( 'Critical', 'bee-monitor' ),
		);
		return isset( $labels[ $severity ] ) ? $labels[ $severity ] : $labels[0];
	}

	/**
	 * Severity number from key.
	 *
	 * @param string $key Key.
	 * @return int
	 */
	public static function severity_from_key( $key ) {
		$map = array_flip( array( 'info', 'low', 'medium', 'high', 'critical' ) );
		return isset( $map[ $key ] ) ? $map[ $key ] : self::HIGH;
	}

	/**
	 * Translated labels for confidence, basis, and change type.
	 *
	 * @param string $group confidence|basis|change|status.
	 * @param string $key   Key.
	 * @return string
	 */
	public static function term( $group, $key ) {
		$terms = array(
			'confidence' => array(
				'confirmed' => __( 'confirmed', 'bee-monitor' ),
				'high'      => __( 'high confidence', 'bee-monitor' ),
				'medium'    => __( 'medium confidence', 'bee-monitor' ),
				'low'       => __( 'low confidence', 'bee-monitor' ),
			),
			'basis'      => array(
				'integrity' => __( 'integrity check', 'bee-monitor' ),
				'heuristic' => __( 'heuristic indicator', 'bee-monitor' ),
				'location'  => __( 'location rule', 'bee-monitor' ),
				'event'     => __( 'site event', 'bee-monitor' ),
				'monitor'   => __( 'monitor health', 'bee-monitor' ),
			),
			'change'     => array(
				'added'               => __( 'added', 'bee-monitor' ),
				'modified'            => __( 'modified', 'bee-monitor' ),
				'deleted'             => __( 'deleted', 'bee-monitor' ),
				'present_at_baseline' => __( 'present when baseline was created', 'bee-monitor' ),
				'present'             => __( 'present', 'bee-monitor' ),
				'changed'             => __( 'changed', 'bee-monitor' ),
				'created'             => __( 'created', 'bee-monitor' ),
				'removed'             => __( 'removed', 'bee-monitor' ),
				'detected'            => __( 'detected', 'bee-monitor' ),
				'updated'             => __( 'updated', 'bee-monitor' ),
			),
			'status'     => array(
				'open'     => __( 'Open', 'bee-monitor' ),
				'expected' => __( 'Expected', 'bee-monitor' ),
				'resolved' => __( 'Resolved', 'bee-monitor' ),
				'auto'     => __( 'Auto-verified', 'bee-monitor' ),
			),
		);
		return isset( $terms[ $group ][ $key ] ) ? $terms[ $group ][ $key ] : $key;
	}

	/**
	 * Translated title for a rule.
	 *
	 * @param string $rule Rule ID.
	 * @return string
	 */
	public static function title( $rule ) {
		$titles = self::titles();
		return isset( $titles[ $rule ] ) ? $titles[ $rule ] : $rule;
	}

	/**
	 * Rule titles.
	 *
	 * @return array
	 */
	private static function titles() {
		return array(
			'core_checksum_mismatch'      => __( 'WordPress core file does not match official checksum', 'bee-monitor' ),
			'core_unknown_file'           => __( 'Unknown file in WordPress core directory', 'bee-monitor' ),
			'core_file_missing'           => __( 'WordPress core file is missing', 'bee-monitor' ),
			'core_file_updated'           => __( 'WordPress core file updated (matches official checksum)', 'bee-monitor' ),
			'executable_in_uploads'       => __( 'Executable PHP file in uploads', 'bee-monitor' ),
			'executable_in_cache'         => __( 'Executable PHP file in a cache or temporary directory', 'bee-monitor' ),
			'inert_php_stub'              => __( 'Inert PHP placeholder file', 'bee-monitor' ),
			'php_in_media_file'           => __( 'PHP code inside a media or text file', 'bee-monitor' ),
			'suspicious_code'             => __( 'Suspicious code indicators', 'bee-monitor' ),
			'config_modified'             => __( 'wp-config.php changed', 'bee-monitor' ),
			'config_injection'            => __( 'Possible injection in wp-config.php', 'bee-monitor' ),
			'server_config_changed'       => __( 'Server configuration file changed', 'bee-monitor' ),
			'server_config_risk'          => __( 'Risky directive in server configuration file', 'bee-monitor' ),
			'persistence_file_changed'    => __( 'Must-use plugin or drop-in changed', 'bee-monitor' ),
			'self_modified'               => __( 'Bee Monitor plugin files changed', 'bee-monitor' ),
			'component_file_changed'      => __( 'Plugin or theme file changed without a recorded update', 'bee-monitor' ),
			'update_changes'              => __( 'Files changed during a recorded update', 'bee-monitor' ),
			'unexpected_php_file'         => __( 'New PHP file in an unusual location', 'bee-monitor' ),
			'php_file_changed'            => __( 'PHP file changed', 'bee-monitor' ),
			'file_deleted'                => __( 'Monitored file deleted', 'bee-monitor' ),
			'file_unverifiable'           => __( 'Monitored file could not be read', 'bee-monitor' ),
			'baseline_tampered'           => __( 'Baseline record failed its integrity signature', 'bee-monitor' ),
			'baseline_missing'            => __( 'Baseline is missing or incomplete', 'bee-monitor' ),
			'baseline_key_changed'        => __( 'Baseline signing key changed', 'bee-monitor' ),
			'storage_unavailable'         => __( 'Bee Monitor database tables are unavailable', 'bee-monitor' ),
			'privileged_user_added'       => __( 'New privileged user account', 'bee-monitor' ),
			'privileged_role_changed'     => __( 'Privileged user role changed', 'bee-monitor' ),
			'privileged_email_changed'    => __( 'Privileged user email changed', 'bee-monitor' ),
			'privileged_user_removed'     => __( 'Privileged user removed or demoted', 'bee-monitor' ),
			'role_capabilities_changed'   => __( 'Role gained powerful capabilities', 'bee-monitor' ),
			'site_url_changed'            => __( 'Site address changed', 'bee-monitor' ),
			'admin_email_changed'         => __( 'Administration email changed', 'bee-monitor' ),
			'registration_opened'         => __( 'Public user registration enabled', 'bee-monitor' ),
			'default_role_changed'        => __( 'Default role for new users changed', 'bee-monitor' ),
			'plugin_activated'            => __( 'Plugin activated', 'bee-monitor' ),
			'plugin_deactivated'          => __( 'Plugin deactivated', 'bee-monitor' ),
			'theme_changed'               => __( 'Active theme changed', 'bee-monitor' ),
			'cron_hook_added'             => __( 'New scheduled task (WP-Cron hook)', 'bee-monitor' ),
			'cron_suspicious_callback'    => __( 'Scheduled task runs code from a suspicious location', 'bee-monitor' ),
			'mail_filter_suspicious'      => __( 'Email filter registered from a suspicious location', 'bee-monitor' ),
			'settings_changed'            => __( 'Bee Monitor settings changed', 'bee-monitor' ),
			'settings_changed_externally' => __( 'Bee Monitor settings changed outside its settings screen', 'bee-monitor' ),
			'scan_gap'                    => __( 'Scheduled scans were not running', 'bee-monitor' ),
			'injected_option_content'     => __( 'Suspicious content stored in a site option', 'bee-monitor' ),
			'injected_post_script'        => __( 'Script from an unlisted domain in post content', 'bee-monitor' ),
			'failed_login_burst'          => __( 'Repeated failed logins', 'bee-monitor' ),
			'privileged_login_new_net'    => __( 'Privileged login from a new network', 'bee-monitor' ),
		);
	}

	/**
	 * Recommended next steps for a rule.
	 *
	 * @param string $rule Rule ID.
	 * @return string
	 */
	public static function next_steps( $rule ) {
		$file_malware = __( 'Do not open the file in a browser. Check the access log for requests to this path, review other open Bee Monitor findings, and compare with a clean backup. If confirmed malicious, take a backup for evidence, then remove it manually and rotate passwords and keys.', 'bee-monitor' );
		$steps        = array(
			'core_checksum_mismatch'      => __( 'Compare the file with the same WordPress version from wordpress.org. If you did not edit it, reinstall core from Dashboard > Updates (Re-install) or with "wp core download --force --skip-content", then investigate how it was changed.', 'bee-monitor' ),
			'core_unknown_file'           => __( 'WordPress core directories should only contain official files. Check the file contents and access logs. If you did not add it, treat it as suspicious and remove it manually after taking a copy for evidence.', 'bee-monitor' ),
			'core_file_missing'           => __( 'Reinstall the current WordPress version to restore missing core files, then check whether a recent update failed.', 'bee-monitor' ),
			'executable_in_uploads'       => $file_malware,
			'executable_in_cache'         => __( 'Confirm which caching or optimization plugin created this file. If none did, treat it as suspicious.', 'bee-monitor' ),
			'php_in_media_file'           => __( 'Media files should never contain PHP. Check whether any code includes this file and remove it manually after review.', 'bee-monitor' ),
			'suspicious_code'             => __( 'Review the flagged lines. Legitimate libraries sometimes use these functions; if this file belongs to a known plugin or theme, compare it with a fresh download of the same version. Mark it Expected only if you are confident it is legitimate.', 'bee-monitor' ),
			'config_modified'             => __( 'Review recent changes to wp-config.php (compare with a backup). Look for new include or require lines, unexpected constants, or ini_set calls.', 'bee-monitor' ),
			'config_injection'            => __( 'Inspect the flagged line in wp-config.php immediately. Including non-PHP or uploaded files is a common persistence technique.', 'bee-monitor' ),
			'server_config_changed'       => __( 'Compare with a backup. If your host, a caching plugin, or a security plugin changed it, mark it Expected.', 'bee-monitor' ),
			'server_config_risk'          => __( 'Confirm that the flagged directive was added by you, your host, or a trusted plugin. Unknown PHP handlers, prepend files, and search-engine-based rewrites are common in compromises.', 'bee-monitor' ),
			'persistence_file_changed'    => __( 'Must-use plugins and drop-ins load on every request and cannot be disabled from the Plugins screen. Confirm who added or changed this file.', 'bee-monitor' ),
			'self_modified'               => __( 'Bee Monitor files should only change during a Bee Monitor update. Reinstall Bee Monitor from a trusted copy and investigate.', 'bee-monitor' ),
			'component_file_changed'      => __( 'Check whether someone edited this plugin or theme. Compare it with a fresh copy of the same version and mark it Expected if the change is legitimate.', 'bee-monitor' ),
			'unexpected_php_file'         => $file_malware,
			'php_file_changed'            => __( 'Confirm who changed this file and why.', 'bee-monitor' ),
			'file_deleted'                => __( 'Confirm the deletion was intended (for example, removing a plugin). Mark it Expected to remove it from the baseline.', 'bee-monitor' ),
			'file_unverifiable'           => __( 'Check file permissions and ownership. Bee Monitor needs read access to verify this file.', 'bee-monitor' ),
			'baseline_tampered'           => __( 'Someone may have edited Bee Monitor data to hide a change. Treat the site as possibly compromised, review all findings, and rebuild the baseline only after verifying files.', 'bee-monitor' ),
			'baseline_missing'            => __( 'Bee Monitor will not silently recreate a missing baseline. Verify the site is clean, then rebuild the baseline from Bee Monitor > Baseline.', 'bee-monitor' ),
			'baseline_key_changed'        => __( 'This happens when WordPress salts or BEE_MONITOR_HMAC_KEY change. If you rotated them, rebuild the baseline. If not, investigate wp-config.php changes.', 'bee-monitor' ),
			'storage_unavailable'         => __( 'Check the database for the Bee Monitor tables. Deactivating and reactivating Bee Monitor recreates them.', 'bee-monitor' ),
			'privileged_user_added'       => __( 'Confirm that someone on your team created this account. If not, preserve logs, remove the account, reset all administrator passwords, and look for related file changes.', 'bee-monitor' ),
			'privileged_role_changed'     => __( 'Confirm the role change was intentional.', 'bee-monitor' ),
			'privileged_email_changed'    => __( 'An attacker can change an administrator email to take over the account through password reset. Confirm with the account owner.', 'bee-monitor' ),
			'privileged_user_removed'     => __( 'Confirm the account was removed or demoted intentionally.', 'bee-monitor' ),
			'role_capabilities_changed'   => __( 'Review the role in a role editor plugin or with WP-CLI and remove capabilities you did not grant.', 'bee-monitor' ),
			'site_url_changed'            => __( 'A changed site address can redirect all visitors. Confirm the change and restore the correct values in Settings > General or wp-config.php.', 'bee-monitor' ),
			'admin_email_changed'         => __( 'Confirm the new administration email with the site owner.', 'bee-monitor' ),
			'registration_opened'         => __( 'Disable "Anyone can register" in Settings > General unless you need it.', 'bee-monitor' ),
			'default_role_changed'        => __( 'New users should get a low-privilege role such as Subscriber. Restore it in Settings > General.', 'bee-monitor' ),
			'plugin_activated'            => __( 'Confirm the plugin was activated intentionally.', 'bee-monitor' ),
			'plugin_deactivated'          => __( 'Confirm the plugin was deactivated intentionally, especially if it is a security plugin.', 'bee-monitor' ),
			'theme_changed'               => __( 'Confirm the theme change was intentional.', 'bee-monitor' ),
			'cron_hook_added'             => __( 'Usually added by plugins. Check that the source file belongs to a plugin you trust.', 'bee-monitor' ),
			'cron_suspicious_callback'    => __( 'A scheduled task runs code outside normal plugin locations. Inspect the source file listed.', 'bee-monitor' ),
			'mail_filter_suspicious'      => __( 'Code outside normal plugin locations can intercept outgoing email, including Bee Monitor alerts. Inspect the source file listed.', 'bee-monitor' ),
			'settings_changed'            => __( 'Confirm the change was made by someone on your team.', 'bee-monitor' ),
			'settings_changed_externally' => __( 'Bee Monitor settings were edited directly in the database. Review exclusions and recipients for unexpected changes.', 'bee-monitor' ),
			'scan_gap'                    => __( 'WP-Cron only runs when the site receives traffic. Configure a real server cron job and a heartbeat URL so gaps are detected.', 'bee-monitor' ),
			'injected_option_content'     => __( 'Check which plugin owns this option. Script or code in options is a common injection target.', 'bee-monitor' ),
			'injected_post_script'        => __( 'Open the post in the editor and confirm the script is intentional. Add trusted domains to the allowlist in Bee Monitor settings.', 'bee-monitor' ),
			'failed_login_burst'          => __( 'Use strong passwords and two-factor authentication. Consider rate limiting logins at the server or firewall.', 'bee-monitor' ),
			'privileged_login_new_net'    => __( 'Confirm the login with the account owner. If it was not them, reset the password and review recent activity.', 'bee-monitor' ),
			'update_changes'              => __( 'No action needed unless you did not perform this update.', 'bee-monitor' ),
		);
		return isset( $steps[ $rule ] ) ? $steps[ $rule ] : __( 'Review the change and confirm it was expected.', 'bee-monitor' );
	}

	/**
	 * Whether a rule concerns a file whose baseline can be updated when marked expected.
	 *
	 * @param string $rule Rule ID.
	 * @return bool
	 */
	public static function is_file_rule( $rule ) {
		return in_array( $rule, array( 'core_checksum_mismatch', 'core_unknown_file', 'core_file_missing', 'config_modified', 'server_config_changed', 'persistence_file_changed', 'self_modified', 'component_file_changed', 'unexpected_php_file', 'php_file_changed', 'file_deleted', 'suspicious_code', 'config_injection', 'server_config_risk' ), true );
	}
}
