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

	const FREQUENCIES  = array( 'bee_monitor_15min', 'hourly', 'twicedaily', 'daily' );
	const DIGESTS      = array( 'hourly', 'daily', 'weekly', 'off' );
	const SEVERITIES   = array( 'critical', 'high', 'medium', 'low' );
	const RISKY_IGNORE = array( '*', 'executable_in_uploads', 'core_checksum_mismatch', 'core_unknown_file', 'baseline_tampered', 'baseline_missing', 'self_modified', 'privileged_user_added', 'config_injection' );

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
			'recipient_rows'            => array(),
			'from_name'                 => 'Bee Monitor',
			'from_email'                => '',
			'reply_to'                  => '',
			'subject_label'             => '',
			'email_format'              => 'html',
			'evidence_detail'           => 'full',
			'digest_frequency'          => 'daily',
			'digest_time'               => '08:00',
			'digest_weekday'            => 1,
			'ignore_rules'              => '',
			'viewer_roles'              => array(),
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
			$stored = Storage::get( 'settings', array() );
			$stored = is_array( $stored ) ? $stored : array();
			if ( empty( $stored['recipient_rows'] ) && ! empty( $stored['recipients'] ) ) {
				$stored['recipient_rows'] = self::legacy_rows( $stored );
			}
			self::$cache = wp_parse_args( $stored, self::defaults() );
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

		$out['scan_frequency']  = self::choice( $input, 'scan_frequency', self::FREQUENCIES, $defaults['scan_frequency'] );
		$out['email_format']    = self::choice( $input, 'email_format', array( 'html', 'text' ), $defaults['email_format'] );
		$out['evidence_detail'] = self::choice( $input, 'evidence_detail', array( 'full', 'summary' ), $defaults['evidence_detail'] );
		$out['digest_weekday']  = isset( $input['digest_weekday'] ) ? max( 0, min( 6, (int) $input['digest_weekday'] ) ) : 1;
		$time                   = isset( $input['digest_time'] ) ? trim( (string) $input['digest_time'] ) : '';
		$out['digest_time']     = preg_match( '/^([01]\d|2[0-3]):[0-5]\d$/', $time ) ? $time : $defaults['digest_time'];

		$email_result = self::sanitize_email_settings( $input );
		$out          = array_merge( $out, $email_result['settings'] );
		$errors       = array_merge( $errors, $email_result['errors'] );
		$warnings     = array_merge( $warnings, $email_result['warnings'] );

		$ignore_result       = self::sanitize_ignore_rules( isset( $input['ignore_rules'] ) ? (string) $input['ignore_rules'] : '' );
		$out['ignore_rules'] = $ignore_result['value'];
		$errors              = array_merge( $errors, $ignore_result['errors'] );
		$warnings            = array_merge( $warnings, $ignore_result['warnings'] );

		$roles = array();
		if ( ! is_multisite() && isset( $input['viewer_roles'] ) && is_array( $input['viewer_roles'] ) ) {
			$all = wp_roles()->roles;
			foreach ( $input['viewer_roles'] as $role ) {
				$role = sanitize_key( $role );
				if ( isset( $all[ $role ] ) && empty( $all[ $role ]['capabilities']['manage_options'] ) ) {
					$roles[ $role ] = $role;
				}
			}
		}
		$out['viewer_roles']     = array_values( $roles );
		$out['digest_frequency'] = self::choice( $input, 'digest_frequency', self::DIGESTS, $defaults['digest_frequency'] );

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
		return array_values( array_unique( wp_list_pluck( self::recipient_rows(), 'email' ) ) );
	}

	/**
	 * Recipient routing rows, falling back to the admin email with default routing.
	 *
	 * @return array[] email, min_severity, digest, categories.
	 */
	public static function recipient_rows() {
		$rows = array();
		foreach ( (array) self::value( 'recipient_rows' ) as $row ) {
			if ( is_array( $row ) && ! empty( $row['email'] ) && is_email( $row['email'] ) ) {
				$rows[] = $row;
			}
		}
		if ( empty( $rows ) ) {
			$admin = is_multisite() ? get_site_option( 'admin_email' ) : get_option( 'admin_email' );
			if ( $admin && is_email( $admin ) ) {
				$rows[] = self::default_row( $admin, 'high' );
			}
		}
		return $rows;
	}

	/**
	 * A recipient row with default routing.
	 *
	 * @param string $email        Email.
	 * @param string $min_severity Minimum severity key for immediate alerts.
	 * @return array
	 */
	public static function default_row( $email, $min_severity ) {
		return array(
			'email'        => $email,
			'min_severity' => in_array( $min_severity, self::SEVERITIES, true ) ? $min_severity : 'high',
			'digest'       => 1,
			'categories'   => Findings::CATEGORIES,
		);
	}

	/**
	 * Convert 1.0.x recipient settings into routing rows.
	 *
	 * @param array $stored Stored settings.
	 * @return array[]
	 */
	private static function legacy_rows( array $stored ) {
		$rows = array();
		$min  = isset( $stored['immediate_severity'] ) ? (string) $stored['immediate_severity'] : 'high';
		foreach ( preg_split( '/[\s,;]+/', isset( $stored['recipients'] ) ? (string) $stored['recipients'] : '' ) as $email ) {
			$email = sanitize_email( $email );
			if ( $email && is_email( $email ) ) {
				$rows[] = self::default_row( $email, $min );
			}
		}
		return $rows;
	}

	/**
	 * Sanitize recipient rows and sender settings.
	 *
	 * @param array $input Raw input.
	 * @return array settings, errors, warnings.
	 */
	private static function sanitize_email_settings( array $input ) {
		$errors   = array();
		$warnings = array();
		$rows     = array();
		$seen     = array();
		$raw_rows = isset( $input['recipient_rows'] ) && is_array( $input['recipient_rows'] ) ? $input['recipient_rows'] : array();
		$invalid  = 0;
		foreach ( $raw_rows as $raw ) {
			if ( ! is_array( $raw ) ) {
				continue;
			}
			$given = isset( $raw['email'] ) ? trim( (string) $raw['email'] ) : '';
			if ( '' === $given ) {
				continue;
			}
			$email = sanitize_email( $given );
			if ( preg_match( '/\s/', $given ) || $email !== $given || ! is_email( $email ) ) {
				++$invalid;
				continue;
			}
			$key = strtolower( $email );
			if ( isset( $seen[ $key ] ) || count( $rows ) >= 20 ) {
				continue;
			}
			$seen[ $key ] = true;
			$min          = isset( $raw['min_severity'] ) ? sanitize_key( $raw['min_severity'] ) : 'high';
			$cats         = isset( $raw['categories'] ) && is_array( $raw['categories'] ) ? array_map( 'sanitize_key', $raw['categories'] ) : array();
			$cats         = array_values( array_intersect( Findings::CATEGORIES, $cats ) );
			if ( empty( $cats ) ) {
				/* translators: %s: email address. */
				$warnings[] = sprintf( __( '%s has no categories selected and will receive no alerts.', 'bee-monitor' ), $email );
			}
			$rows[] = array(
				'email'        => $email,
				'min_severity' => in_array( $min, self::SEVERITIES, true ) ? $min : 'high',
				'digest'       => empty( $raw['digest'] ) ? 0 : 1,
				'categories'   => $cats,
			);
		}
		if ( $invalid ) {
			/* translators: %d: number of rows. */
			$errors[] = sprintf( _n( '%d recipient row had an invalid email address and was removed.', '%d recipient rows had invalid email addresses and were removed.', $invalid, 'bee-monitor' ), $invalid );
		}
		if ( empty( $rows ) ) {
			$warnings[] = __( 'No recipients are configured, so alerts go to the site administration email.', 'bee-monitor' );
		} else {
			$covered = array();
			foreach ( $rows as $row ) {
				$covered = array_merge( $covered, $row['categories'] );
			}
			foreach ( array_diff( Findings::CATEGORIES, $covered ) as $missing ) {
				/* translators: %s: category name. */
				$warnings[] = sprintf( __( 'Nobody receives "%s" alerts.', 'bee-monitor' ), Findings::category_label( $missing ) );
			}
		}

		$out                  = array( 'recipient_rows' => $rows );
		$name                 = trim( preg_replace( '/[\r\n]+/', ' ', sanitize_text_field( isset( $input['from_name'] ) ? (string) $input['from_name'] : '' ) ) );
		$out['from_name']     = '' === $name ? 'Bee Monitor' : substr( $name, 0, 60 );
		$label                = trim( preg_replace( '/[\r\n]+/', ' ', sanitize_text_field( isset( $input['subject_label'] ) ? (string) $input['subject_label'] : '' ) ) );
		$out['subject_label'] = substr( $label, 0, 40 );

		$host = strtolower( (string) wp_parse_url( network_home_url(), PHP_URL_HOST ) );
		$host = preg_replace( '/^www\./', '', $host );
		foreach ( array( 'from_email', 'reply_to' ) as $key ) {
			$raw   = isset( $input[ $key ] ) ? trim( (string) $input[ $key ] ) : '';
			$value = '' === $raw ? '' : sanitize_email( $raw );
			if ( '' !== $raw && ( preg_match( '/\s/', $raw ) || $value !== $raw || ! is_email( $value ) ) ) {
				/* translators: %s: setting name. */
				$errors[] = sprintf( __( '%s is not a valid email address and was not saved.', 'bee-monitor' ), 'from_email' === $key ? __( 'From address', 'bee-monitor' ) : __( 'Reply-To address', 'bee-monitor' ) );
				$value    = '';
			}
			if ( 'from_email' === $key && '' !== $value && $host ) {
				$domain = strtolower( substr( strrchr( $value, '@' ), 1 ) );
				if ( $domain !== $host && substr( $domain, -strlen( '.' . $host ) ) !== '.' . $host ) {
					/* translators: %s: site domain. */
					$warnings[] = sprintf( __( 'The From address is not on %s. Many mail providers reject or spam-folder mail sent from a domain the server is not authorized for (SPF/DMARC).', 'bee-monitor' ), $host );
				}
			}
			$out[ $key ] = $value;
		}
		return array(
			'settings' => $out,
			'errors'   => $errors,
			'warnings' => $warnings,
		);
	}

	/**
	 * Sanitize ignore rules: one "rule_id path-glob" pair per line.
	 *
	 * @param string $raw Raw text.
	 * @return array value, errors, warnings.
	 */
	private static function sanitize_ignore_rules( $raw ) {
		$lines    = array();
		$errors   = array();
		$warnings = array();
		foreach ( preg_split( '/\r\n|\r|\n/', $raw ) as $line ) {
			$line = trim( sanitize_text_field( $line ) );
			if ( '' === $line ) {
				continue;
			}
			$parts = preg_split( '/\s+/', $line, 2 );
			$rule  = '*' === $parts[0] ? '*' : sanitize_key( $parts[0] );
			$glob  = isset( $parts[1] ) ? ltrim( str_replace( '\\', '/', trim( $parts[1] ) ), '/' ) : '';
			if ( '' === $rule || '' === $glob || false !== strpos( $glob, '..' ) || strlen( $glob ) > 255 ) {
				/* translators: %s: rejected line. */
				$errors[] = sprintf( __( 'Ignored invalid ignore rule "%s". Use: rule_id path/pattern/*', 'bee-monitor' ), $line );
				continue;
			}
			if ( in_array( $rule, self::RISKY_IGNORE, true ) || '*' === $glob ) {
				/* translators: %s: ignore rule. */
				$warnings[] = sprintf( __( 'Ignore rule "%s" can hide serious findings. Keep it as narrow as possible.', 'bee-monitor' ), $rule . ' ' . $glob );
			}
			$lines[ $rule . ' ' . $glob ] = $rule . ' ' . $glob;
		}
		return array(
			'value'    => implode( "\n", array_slice( array_values( $lines ), 0, 200 ) ),
			'errors'   => $errors,
			'warnings' => $warnings,
		);
	}

	/**
	 * Whether a file finding is covered by an ignore rule.
	 *
	 * @param string $rule Rule ID.
	 * @param string $rel  Relative path.
	 * @return bool
	 */
	public static function is_ignored( $rule, $rel ) {
		foreach ( explode( "\n", (string) self::value( 'ignore_rules' ) ) as $line ) {
			$parts = preg_split( '/\s+/', trim( $line ), 2 );
			if ( 2 !== count( $parts ) ) {
				continue;
			}
			if ( ( '*' === $parts[0] || $parts[0] === $rule ) && Paths::matches( $parts[1], $rel ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Digest schedule signature, used to detect schedule changes.
	 *
	 * @return string
	 */
	public static function digest_signature() {
		return self::value( 'digest_frequency' ) . '|' . self::value( 'digest_time' ) . '|' . (int) self::value( 'digest_weekday' ) . '|' . wp_timezone_string();
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
