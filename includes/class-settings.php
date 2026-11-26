<?php
/**
 * Bee Monitor settings: defaults, validation, and sanitization.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Settings model.
 */
final class Settings {

	const FREQUENCIES = array( 'bee_monitor_15min', 'hourly', 'twicedaily', 'daily' );
	const DIGESTS     = array( 'hourly', 'daily', 'off' );
	const SEVERITIES  = array( 'critical', 'high', 'medium' );

	/**
	 * Cached settings.
	 *
	 * @var array|null
	 */
	private static $cache = null;

	/**
	 * Default values.
	 *
	 * @return array
	 */
	public static function defaults() {
		return array(
			'enabled'                   => 1,
			'scan_frequency'            => 'hourly',
			'time_budget'               => 20,
			'max_inspect_kb'            => 2048,
			'extra_extensions'          => '',
			'inspect_upload_images'     => 0,
			'scan_parent_dir'           => 1,
			'exclusions'                => implode(
				"\n",
				array(
					'wp-content/ai1wm-backups/*',
					'wp-content/updraft/*',
					'wp-content/backups-dup-lite/*',
					'*/node_modules/*',
					'*/.git/*',
				)
			),
			'core_checksums'            => 1,
			'auto_accept_verified_core' => 1,
			'auto_accept_updates'       => 1,
			'update_grace_minutes'      => 30,
			'monitor_users'             => 1,
			'monitor_options'           => 1,
			'monitor_cron'              => 1,
			'monitor_logins'            => 1,
			'content_sweep'             => 1,
			'content_domain_allowlist'  => '',
			'failed_login_threshold'    => 20,
			'recipients'                => '',
			'immediate_severity'        => 'high',
			'digest_frequency'          => 'daily',
			'digest_all_clear'          => 0,
			'max_emails_per_hour'       => 6,
			'reminder_days'             => 3,
			'heartbeat_url'             => '',
			'retention_days'            => 180,
			'delete_data_on_uninstall'  => 0,
		);
	}

	/**
	 * Current settings merged with defaults.
	 *
	 * @return array
	 */
	public static function get() {
		if ( null === self::$cache ) {
			$stored      = Storage::get( 'settings', array() );
			self::$cache = wp_parse_args( is_array( $stored ) ? $stored : array(), self::defaults() );
		}
		return self::$cache;
	}

	/**
	 * Single setting.
	 *
	 * @param string $key Key.
	 * @return mixed
	 */
	public static function value( $key ) {
		$settings = self::get();
		return isset( $settings[ $key ] ) ? $settings[ $key ] : null;
	}

	/**
	 * Persist settings and record the integrity hash.
	 *
	 * @param array $settings Sanitized settings.
	 */
	public static function save( array $settings ) {
		Storage::set( 'settings', $settings );
		Storage::set( 'settings_hash', self::hash( $settings ) );
		self::$cache = null;
	}

	/**
	 * Integrity hash of settings.
	 *
	 * @param array|null $settings Settings or null for stored.
	 * @return string
	 */
	public static function hash( $settings = null ) {
		if ( null === $settings ) {
			$settings = Storage::get( 'settings', array() );
		}
		$settings = is_array( $settings ) ? $settings : array();
		ksort( $settings );
		return hash_hmac( 'sha256', wp_json_encode( $settings ), Storage::mac_key() );
	}

	/**
	 * Flush cache (after external changes).
	 */
	public static function flush() {
		self::$cache = null;
	}

	/**
	 * Sanitize and validate raw input.
	 *
	 * @param array $input Raw input (unslashed).
	 * @return array { settings: array, errors: string[], warnings: string[] }
	 */
	public static function sanitize( $input ) {
		$input    = is_array( $input ) ? $input : array();
		$defaults = self::defaults();
		$out      = array();
		$errors   = array();
		$warnings = array();

		$bools = array( 'enabled', 'inspect_upload_images', 'scan_parent_dir', 'core_checksums', 'auto_accept_verified_core', 'auto_accept_updates', 'monitor_users', 'monitor_options', 'monitor_cron', 'monitor_logins', 'content_sweep', 'digest_all_clear', 'delete_data_on_uninstall' );
		foreach ( $bools as $key ) {
			$out[ $key ] = empty( $input[ $key ] ) ? 0 : 1;
		}

		$out['scan_frequency']     = self::choice( $input, 'scan_frequency', self::FREQUENCIES, $defaults['scan_frequency'] );
		$out['digest_frequency']   = self::choice( $input, 'digest_frequency', self::DIGESTS, $defaults['digest_frequency'] );
		$out['immediate_severity'] = self::choice( $input, 'immediate_severity', self::SEVERITIES, $defaults['immediate_severity'] );

		$ints = array(
			'time_budget'            => array( 5, 120 ),
			'max_inspect_kb'         => array( 64, 20480 ),
			'update_grace_minutes'   => array( 0, 1440 ),
			'failed_login_threshold' => array( 3, 10000 ),
			'max_emails_per_hour'    => array( 1, 60 ),
			'reminder_days'          => array( 0, 90 ),
			'retention_days'         => array( 0, 3650 ),
		);
		foreach ( $ints as $key => $range ) {
			$raw = isset( $input[ $key ] ) ? $input[ $key ] : $defaults[ $key ];
			if ( ! is_numeric( $raw ) ) {
				/* translators: %s: setting name. */
				$errors[]    = sprintf( __( '%s must be a number. The previous value was kept.', 'bee-monitor' ), self::label( $key ) );
				$out[ $key ] = (int) self::value( $key );
				continue;
			}
			$val = (int) $raw;
			if ( $val < $range[0] || $val > $range[1] ) {
				/* translators: 1: setting name, 2: minimum, 3: maximum. */
				$warnings[] = sprintf( __( '%1$s was adjusted to stay between %2$d and %3$d.', 'bee-monitor' ), self::label( $key ), $range[0], $range[1] );
				$val        = max( $range[0], min( $range[1], $val ) );
			}
			$out[ $key ] = $val;
		}

		$exts = array();
		foreach ( preg_split( '/[\s,]+/', isset( $input['extra_extensions'] ) ? (string) $input['extra_extensions'] : '' ) as $ext ) {
			$ext = strtolower( ltrim( trim( $ext ), '.' ) );
			if ( '' !== $ext && preg_match( '/^[a-z0-9]{1,10}$/', $ext ) ) {
				$exts[ $ext ] = $ext;
			} elseif ( '' !== $ext ) {
				/* translators: %s: rejected extension. */
				$errors[] = sprintf( __( 'Ignored invalid extension "%s".', 'bee-monitor' ), $ext );
			}
		}
		$out['extra_extensions'] = implode( ', ', array_slice( $exts, 0, 20 ) );

		$exclusions = array();
		$lines      = preg_split( '/\r\n|\r|\n/', isset( $input['exclusions'] ) ? (string) $input['exclusions'] : '' );
		foreach ( $lines as $line ) {
			$line = ltrim( str_replace( '\\', '/', trim( sanitize_text_field( $line ) ) ), '/' );
			if ( '' === $line ) {
				continue;
			}
			if ( false !== strpos( $line, '..' ) || strlen( $line ) > 255 ) {
				/* translators: %s: rejected exclusion pattern. */
				$errors[] = sprintf( __( 'Ignored exclusion "%s": patterns cannot contain ".." or exceed 255 characters.', 'bee-monitor' ), $line );
				continue;
			}
			$exclusions[ $line ] = $line;
		}
		$exclusions        = array_slice( array_values( $exclusions ), 0, 200 );
		$out['exclusions'] = implode( "\n", $exclusions );
		foreach ( self::risky_exclusions( $exclusions ) as $risky ) {
			/* translators: %s: exclusion pattern. */
			$warnings[] = sprintf( __( 'Exclusion "%s" hides a high-risk location from Bee Monitor. Keep it only if you accept that malware there will not be detected.', 'bee-monitor' ), $risky );
		}

		$domains = array();
		foreach ( preg_split( '/[\s,]+/', isset( $input['content_domain_allowlist'] ) ? (string) $input['content_domain_allowlist'] : '' ) as $domain ) {
			$domain = strtolower( trim( $domain ) );
			$domain = preg_replace( '#^https?://#', '', $domain );
			$domain = trim( (string) strtok( $domain, '/' ) );
			if ( '' !== $domain && preg_match( '/^[a-z0-9.-]{3,253}$/', $domain ) ) {
				$domains[ $domain ] = $domain;
			}
		}
		$out['content_domain_allowlist'] = implode( "\n", array_slice( array_values( $domains ), 0, 100 ) );

		$recipients = array();
		foreach ( preg_split( '/[\s,;]+/', isset( $input['recipients'] ) ? (string) $input['recipients'] : '' ) as $email ) {
			$email = sanitize_email( $email );
			if ( '' === $email ) {
				continue;
			}
			if ( is_email( $email ) ) {
				$recipients[ strtolower( $email ) ] = $email;
			}
		}
		$entered = array_filter( array_map( 'trim', preg_split( '/[\s,;]+/', isset( $input['recipients'] ) ? (string) $input['recipients'] : '' ) ) );
		if ( $recipients && count( $entered ) > count( $recipients ) ) {
			/* translators: %d: number of ignored entries. */
			$warnings[] = sprintf( __( '%d recipient entries were not valid email addresses and were ignored.', 'bee-monitor' ), count( $entered ) - count( $recipients ) );
		}
		if ( isset( $input['recipients'] ) && '' !== trim( (string) $input['recipients'] ) && empty( $recipients ) ) {
			$errors[] = __( 'No valid alert recipients were entered, so alerts will go to the site administrator email.', 'bee-monitor' );
		}
		$out['recipients'] = implode( ', ', array_slice( array_values( $recipients ), 0, 10 ) );

		$url = isset( $input['heartbeat_url'] ) ? trim( (string) $input['heartbeat_url'] ) : '';
		if ( '' !== $url ) {
			$clean = esc_url_raw( $url, array( 'https' ) );
			if ( '' === $clean || ! wp_http_validate_url( $clean ) ) {
				$errors[] = __( 'The heartbeat URL must be a valid public https:// address. It was not saved.', 'bee-monitor' );
				$clean    = '';
			}
			$url = $clean;
		}
		$out['heartbeat_url'] = $url;

		return array(
			'settings' => $out,
			'errors'   => $errors,
			'warnings' => $warnings,
		);
	}

	/**
	 * Exclusion patterns that cover high-risk locations.
	 *
	 * @param string[] $patterns Patterns.
	 * @return string[]
	 */
	public static function risky_exclusions( array $patterns ) {
		$probes = array( 'wp-content/uploads/x.php', 'wp-content/mu-plugins/x.php', 'wp-admin/x.php', 'wp-includes/x.php', 'wp-config.php', '.htaccess', 'wp-content/x.php', 'x.php', 'wp-content/plugins/bee-monitor/bee-monitor.php' );
		$risky  = array();
		foreach ( $patterns as $pattern ) {
			foreach ( $probes as $probe ) {
				if ( Paths::matches( $pattern, $probe ) ) {
					$risky[ $pattern ] = $pattern;
					break;
				}
			}
		}
		return array_values( $risky );
	}

	/**
	 * Exclusion patterns as an array.
	 *
	 * @return string[]
	 */
	public static function exclusions() {
		return array_values( array_filter( array_map( 'trim', explode( "\n", (string) self::value( 'exclusions' ) ) ) ) );
	}

	/**
	 * Alert recipients, falling back to the admin email.
	 *
	 * @return string[]
	 */
	public static function recipients() {
		$list = array_filter( array_map( 'trim', explode( ',', (string) self::value( 'recipients' ) ) ) );
		if ( empty( $list ) ) {
			$admin = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
			$list  = $admin ? array( $admin ) : array();
		}
		return array_values( array_filter( $list, 'is_email' ) );
	}

	/**
	 * Scan interval in seconds.
	 *
	 * @return int
	 */
	public static function interval_seconds() {
		$map = array(
			'bee_monitor_15min' => 15 * MINUTE_IN_SECONDS,
			'hourly'            => HOUR_IN_SECONDS,
			'twicedaily'        => 12 * HOUR_IN_SECONDS,
			'daily'             => DAY_IN_SECONDS,
		);
		$key = (string) self::value( 'scan_frequency' );
		return isset( $map[ $key ] ) ? $map[ $key ] : HOUR_IN_SECONDS;
	}

	/**
	 * Human label for a setting key.
	 *
	 * @param string $key Key.
	 * @return string
	 */
	public static function label( $key ) {
		$labels = array(
			'time_budget'            => __( 'Time budget per scan step', 'bee-monitor' ),
			'max_inspect_kb'         => __( 'Maximum file size to inspect', 'bee-monitor' ),
			'update_grace_minutes'   => __( 'Update grace window', 'bee-monitor' ),
			'failed_login_threshold' => __( 'Failed login threshold', 'bee-monitor' ),
			'max_emails_per_hour'    => __( 'Maximum emails per hour', 'bee-monitor' ),
			'reminder_days'          => __( 'Reminder interval', 'bee-monitor' ),
			'retention_days'         => __( 'Finding retention', 'bee-monitor' ),
		);
		return isset( $labels[ $key ] ) ? $labels[ $key ] : $key;
	}

	/**
	 * Validate a choice field.
	 *
	 * @param array  $input   Input.
	 * @param string $key     Key.
	 * @param array  $allowed Allowed values.
	 * @param string $fallback Default.
	 * @return string
	 */
	private static function choice( $input, $key, $allowed, $fallback ) {
		$val = isset( $input[ $key ] ) ? sanitize_key( $input[ $key ] ) : $fallback;
		return in_array( $val, $allowed, true ) ? $val : $fallback;
	}
}
