<?php
/**
 * Database-level checks: privileged users, roles, key options, cron,
 * injected content, and Bee Monitor's own health.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- the content sweep reads the database directly so injected values are not hidden by a cache.

/**
 * Snapshot-based site checks. Snapshots catch changes made directly in the
 * database (which bypass WordPress hooks); recorded context lowers severity
 * for changes made through normal admin actions.
 */
final class Site_Monitor {

	const DANGEROUS_CAPS = array( 'manage_options', 'edit_plugins', 'edit_themes', 'edit_files', 'install_plugins', 'activate_plugins', 'update_core', 'edit_users', 'promote_users', 'create_users', 'unfiltered_upload', 'manage_network', 'manage_network_options' );
	const CONTEXT_WINDOW = 6 * HOUR_IN_SECONDS;

	/**
	 * Run all enabled site checks.
	 *
	 * @param array $state Scan state.
	 */
	public static function run( array $state ) {
		$settings = Settings::get();
		if ( $settings['monitor_users'] ) {
			self::check_roles();
			self::check_users();
			self::check_hidden_users();
			self::check_application_passwords();
		}
		if ( $settings['posture_checks'] ) {
			self::check_posture();
		}
		if ( $settings['monitor_options'] ) {
			self::check_options();
		}
		if ( $settings['monitor_cron'] ) {
			self::check_cron();
		}
		if ( $settings['content_sweep'] && time() - (int) Storage::get( 'last_content_sweep', 0 ) > DAY_IN_SECONDS ) {
			self::content_sweep();
			Storage::set( 'last_content_sweep', time() );
		}
		self::check_settings_integrity();
		self::check_mail_filters();
		self::check_scan_gap( $state );
	}

	/**
	 * Roles and their dangerous capabilities.
	 */
	private static function check_roles() {
		$current = array();
		foreach ( wp_roles()->roles as $role => $data ) {
			$caps = array();
			foreach ( (array) $data['capabilities'] as $cap => $granted ) {
				if ( $granted && in_array( $cap, self::DANGEROUS_CAPS, true ) ) {
					$caps[] = $cap;
				}
			}
			sort( $caps );
			$current[ $role ] = $caps;
		}
		$previous = Storage::get( 'snapshot_roles', null );
		Storage::set( 'snapshot_roles', $current );
		if ( ! is_array( $previous ) ) {
			return;
		}
		foreach ( $current as $role => $caps ) {
			$before = isset( $previous[ $role ] ) ? $previous[ $role ] : array();
			$gained = array_values( array_diff( $caps, $before ) );
			if ( empty( $gained ) ) {
				continue;
			}
			Findings::record(
				array(
					'rule'        => 'role_capabilities_changed',
					'severity'    => 'administrator' === $role ? Findings::LOW : Findings::HIGH,
					'confidence'  => 'confirmed',
					'basis'       => 'event',
					'change_type' => isset( $previous[ $role ] ) ? 'changed' : 'created',
					/* translators: %s: role slug. */
					'subject'     => sprintf( __( 'Role: %s', 'bee-monitor' ), $role ),
					/* translators: %s: list of capabilities. */
					'reason'      => sprintf( __( 'This role gained powerful capabilities: %s. Every user with this role can now use them.', 'bee-monitor' ), implode( ', ', $gained ) ),
					'evidence'    => array(
						'role'   => $role,
						'gained' => $gained,
					),
					'key'         => md5( wp_json_encode( $caps ) ),
				)
			);
		}
	}

	/**
	 * Privileged users.
	 */
	private static function check_users() {
		$current = array();
		$users   = get_users(
			array(
				'capability__in' => self::DANGEROUS_CAPS,
				'fields'         => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
				'number'         => 1000,
			)
		);
		foreach ( $users as $user ) {
			$data                       = get_userdata( $user->ID );
			$roles                      = $data ? array_values( (array) $data->roles ) : array();
			$current[ (int) $user->ID ] = array(
				'login'      => $user->user_login,
				'email'      => md5( strtolower( (string) $user->user_email ) ),
				'masked'     => Redactor::email( $user->user_email ),
				'roles'      => $roles,
				'registered' => $user->user_registered,
			);
		}
		if ( is_multisite() ) {
			foreach ( get_super_admins() as $login ) {
				$user = get_user_by( 'login', $login );
				if ( ! $user ) {
					continue;
				}
				$id = (int) $user->ID;
				if ( ! isset( $current[ $id ] ) ) {
					$current[ $id ] = array(
						'login'      => $user->user_login,
						'email'      => md5( strtolower( (string) $user->user_email ) ),
						'masked'     => Redactor::email( $user->user_email ),
						'roles'      => array(),
						'registered' => $user->user_registered,
					);
				}
				$current[ $id ]['roles'][] = 'super_admin';
			}
		}
		foreach ( $current as &$entry ) {
			$entry['roles'] = array_values( array_unique( $entry['roles'] ) );
			sort( $entry['roles'] );
		}
		unset( $entry );

		$previous = Storage::get( 'snapshot_users', null );
		Storage::set( 'snapshot_users', $current );
		if ( ! is_array( $previous ) ) {
			return;
		}

		foreach ( $current as $id => $user ) {
			$event    = Context::find( array( 'user_change' ), (string) $id, time() - self::CONTEXT_WINDOW );
			$known    = $event && ( $event['actor'] || 'wp-cli' === $event['via'] );
			$evidence = array(
				'user_id'    => $id,
				'login'      => $user['login'],
				'email'      => $user['masked'],
				'roles'      => $user['roles'],
				'registered' => $user['registered'],
				'context'    => Context::describe( $event ),
			);
			if ( ! isset( $previous[ $id ] ) ) {
				$admin_like = (bool) array_intersect( $user['roles'], array( 'administrator', 'super_admin' ) );
				Findings::record(
					array(
						'rule'        => 'privileged_user_added',
						'severity'    => $known ? Findings::HIGH : Findings::CRITICAL,
						'confidence'  => $known ? 'medium' : 'high',
						'basis'       => 'event',
						'change_type' => 'created',
						/* translators: 1: username, 2: user ID. */
						'subject'     => sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $user['login'], $id ),
						'reason'      => ( $admin_like
							? __( 'A user with administrator-level access appeared.', 'bee-monitor' )
							: __( 'A user with powerful capabilities appeared.', 'bee-monitor' ) ) . ' ' . ( $known
							? __( 'A matching admin action was recorded; confirm it was intended.', 'bee-monitor' )
							: __( 'No matching admin action was recorded, which suggests the account was created directly in the database or by code.', 'bee-monitor' ) ),
						'evidence'    => $evidence,
						'key'         => implode( ',', $user['roles'] ),
					)
				);
				continue;
			}
			$before = $previous[ $id ];
			if ( $before['roles'] !== $user['roles'] ) {
				$gained = array_diff( $user['roles'], $before['roles'] );
				$severe = (bool) array_intersect( $gained, array( 'administrator', 'super_admin' ) );
				Findings::record(
					array(
						'rule'        => 'privileged_role_changed',
						'severity'    => $severe ? ( $known ? Findings::HIGH : Findings::CRITICAL ) : Findings::MEDIUM,
						'confidence'  => 'confirmed',
						'basis'       => 'event',
						'change_type' => 'changed',
						/* translators: 1: username, 2: user ID. */
						'subject'     => sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $user['login'], $id ),
						/* translators: 1: old roles, 2: new roles. */
						'reason'      => sprintf( __( 'Roles changed from [%1$s] to [%2$s].', 'bee-monitor' ), implode( ', ', $before['roles'] ), implode( ', ', $user['roles'] ) ),
						'evidence'    => $evidence + array( 'previous_roles' => $before['roles'] ),
						'key'         => implode( ',', $user['roles'] ),
					)
				);
			}
			if ( $before['email'] !== $user['email'] ) {
				$self = Context::find( array( 'profile_update' ), (string) $id, time() - self::CONTEXT_WINDOW );
				Findings::record(
					array(
						'rule'        => 'privileged_email_changed',
						'severity'    => $self ? Findings::MEDIUM : Findings::HIGH,
						'confidence'  => 'confirmed',
						'basis'       => 'event',
						'change_type' => 'changed',
						/* translators: 1: username, 2: user ID. */
						'subject'     => sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $user['login'], $id ),
						/* translators: 1: old masked email, 2: new masked email. */
						'reason'      => sprintf( __( 'Email changed from %1$s to %2$s.', 'bee-monitor' ), $before['masked'], $user['masked'] ),
						'evidence'    => $evidence + array( 'context' => Context::describe( $self ) ),
						'key'         => $user['email'],
					)
				);
			}
		}
		foreach ( $previous as $id => $user ) {
			if ( isset( $current[ $id ] ) ) {
				continue;
			}
			Findings::record(
				array(
					'rule'        => 'privileged_user_removed',
					'severity'    => Findings::LOW,
					'confidence'  => 'confirmed',
					'basis'       => 'event',
					'change_type' => 'removed',
					/* translators: 1: username, 2: user ID. */
					'subject'     => sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $user['login'], $id ),
					'reason'      => __( 'This user no longer has powerful capabilities (removed or demoted).', 'bee-monitor' ),
					'evidence'    => array(
						'user_id' => $id,
						'roles'   => $user['roles'],
					),
					'key'         => (string) time(),
				)
			);
		}
	}

	/**
	 * Administrators that exist in the database but are hidden from WordPress user queries.
	 */
	private static function check_hidden_users() {
		global $wpdb;
		if ( is_multisite() ) {
			return;
		}
		$like = '%' . $wpdb->esc_like( '"administrator"' ) . '%';
		$raw  = array_map( 'intval', (array) $wpdb->get_col( $wpdb->prepare( 'SELECT user_id FROM %i WHERE meta_key = %s AND meta_value LIKE %s', $wpdb->usermeta, $wpdb->get_blog_prefix() . 'capabilities', $like ) ) );
		$seen = array_map(
			'intval',
			(array) get_users(
				array(
					'role'   => 'administrator',
					'fields' => 'ID',
					'number' => 1000,
				)
			)
		);
		$keep = array();
		foreach ( array_diff( $raw, $seen ) as $id ) {
			$login = (string) $wpdb->get_var( $wpdb->prepare( 'SELECT user_login FROM %i WHERE ID = %d', $wpdb->users, $id ) );
			if ( '' === $login ) {
				continue;
			}
			/* translators: 1: username, 2: user ID. */
			$subject = sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $login, $id );
			$keep[]  = $subject;
			Findings::record(
				array(
					'rule'        => 'hidden_privileged_user',
					'severity'    => Findings::CRITICAL,
					'confidence'  => 'high',
					'basis'       => 'integrity',
					'change_type' => 'detected',
					'subject'     => $subject,
					'reason'      => __( 'The database shows this account as an administrator, but WordPress user queries do not return it. Code is filtering the user list to hide the account.', 'bee-monitor' ),
					'evidence'    => array(
						'user_id' => $id,
						'login'   => $login,
						'sources' => array_map( array( Paths::class, 'display' ), array_merge( Paths::hook_files( 'pre_user_query' ), Paths::hook_files( 'users_list_table_query_args' ) ) ),
					),
					'key'         => (string) $id,
				)
			);
		}
		Findings::auto_resolve( 'hidden_privileged_user', $keep );
	}

	/**
	 * New application passwords on privileged accounts (API access that bypasses the login form).
	 */
	private static function check_application_passwords() {
		if ( ! class_exists( '\WP_Application_Passwords' ) ) {
			return;
		}
		$users = Storage::get( 'snapshot_users', array() );
		if ( ! is_array( $users ) ) {
			return;
		}
		$current  = array();
		$previous = Storage::get( 'snapshot_app_passwords', null );
		foreach ( array_keys( $users ) as $id ) {
			foreach ( (array) \WP_Application_Passwords::get_user_application_passwords( (int) $id ) as $item ) {
				if ( empty( $item['uuid'] ) ) {
					continue;
				}
				$key             = Context::app_password_key( $item['uuid'] );
				$current[ $key ] = (int) $id;
				if ( is_array( $previous ) && isset( $previous[ $key ] ) ) {
					continue;
				}
				$event = Context::find( array( 'app_password' ), $key, time() - self::CONTEXT_WINDOW );
				$known = $event && ( $event['actor'] || 'wp-cli' === $event['via'] );
				Findings::record(
					array(
						'rule'        => 'application_password_added',
						'severity'    => ! is_array( $previous ) ? Findings::LOW : ( $known ? Findings::MEDIUM : Findings::HIGH ),
						'confidence'  => 'confirmed',
						'basis'       => 'event',
						'change_type' => is_array( $previous ) ? 'added' : 'present_at_baseline',
						/* translators: 1: username, 2: user ID. */
						'subject'     => sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $users[ $id ]['login'], $id ),
						'reason'      => is_array( $previous )
							? __( 'An application password was added to an account with powerful capabilities. Application passwords grant REST and XML-RPC access without the login form or two-factor prompts.', 'bee-monitor' ) . ' ' . Context::describe( $event )
							: __( 'This privileged account already had an application password when Bee Monitor started checking. Confirm it is still needed.', 'bee-monitor' ),
						'evidence'    => array(
							'user_id'  => (int) $id,
							'login'    => $users[ $id ]['login'],
							'app_name' => substr( sanitize_text_field( (string) $item['name'] ), 0, 80 ),
							'created'  => ! empty( $item['created'] ) ? gmdate( 'c', (int) $item['created'] ) : '',
						),
						'key'         => $key,
					)
				);
			}
		}
		Storage::set( 'snapshot_app_passwords', $current );
	}

	/**
	 * Read-only configuration and hardening checks. Findings close automatically when the condition is fixed.
	 */
	private static function check_posture() {
		$d = Paths::dirs();

		$present = array();
		foreach ( array( 'auto_prepend_file', 'auto_append_file' ) as $directive ) {
			$value = trim( (string) ini_get( $directive ) );
			if ( '' === $value || 'none' === strtolower( $value ) ) {
				continue;
			}
			$known     = (bool) preg_match( '/wordfence-waf\.php$/i', $value );
			$subject   = 'php.ini: ' . $directive;
			$present[] = $subject;
			self::posture(
				'runtime_prepend',
				$known ? Findings::LOW : Findings::HIGH,
				$known ? 'high' : 'medium',
				$subject,
				$known
					? __( 'PHP loads a web application firewall file on every request. This is expected if you use that firewall.', 'bee-monitor' )
					: __( 'PHP is configured to run this file on every request. Attackers use this to keep a backdoor running even after files in WordPress are cleaned.', 'bee-monitor' ),
				array( 'file' => Paths::display( Paths::normalize( $value ) ) ),
				md5( $value )
			);
		}
		Findings::auto_resolve( 'runtime_prepend', $present );

		$editor = ! ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) && ! ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS );
		self::posture_toggle( $editor, 'file_editor_enabled', Findings::LOW, 'wp-config.php: DISALLOW_FILE_EDIT', __( 'Administrators can edit plugin and theme PHP from the dashboard, so a stolen admin session can plant code without file access.', 'bee-monitor' ) );

		$production = function_exists( 'wp_get_environment_type' ) && 'production' === wp_get_environment_type();
		$display    = defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );
		self::posture_toggle( $production && $display, 'debug_display_enabled', Findings::MEDIUM, 'wp-config.php: WP_DEBUG_DISPLAY', __( 'This is a production site and PHP errors are displayed to visitors, which can reveal file paths and internals.', 'bee-monitor' ) );

		$logs = array( WP_CONTENT_DIR . '/debug.log' );
		if ( defined( 'WP_DEBUG_LOG' ) && is_string( WP_DEBUG_LOG ) && ! in_array( strtolower( WP_DEBUG_LOG ), array( '1', 'true' ), true ) ) {
			$logs[] = WP_DEBUG_LOG;
		}
		$keep = array();
		foreach ( array_unique( $logs ) as $log ) {
			$norm = Paths::normalize( $log );
			if ( Paths::within( $norm, $d['abspath'] ) && @is_file( $norm ) && (int) @filesize( $norm ) > 0 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$subject = Paths::display( $norm );
				$keep[]  = $subject;
				self::posture( 'debug_log_public', Findings::MEDIUM, 'confirmed', $subject, __( 'A PHP debug log exists inside the web root. Unless the web server blocks it, anyone can download it, and logs often contain paths, queries, and user data.', 'bee-monitor' ), array( 'size' => (int) @filesize( $norm ) ), '' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			}
		}
		Findings::auto_resolve( 'debug_log_public', $keep );

		$writable = array();
		$readable = false;
		if ( '\\' !== DIRECTORY_SEPARATOR ) {
			$config  = @is_file( $d['abspath'] . '/wp-config.php' ) ? $d['abspath'] . '/wp-config.php' : $d['parent'] . '/wp-config.php'; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$targets = array( $config, $d['abspath'] . '/.htaccess', $d['abspath'] . '/index.php', $d['abspath'] . '/wp-settings.php', $d['mu'], $d['plugins'] );
			foreach ( $targets as $target ) {
				$perms = @fileperms( $target ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false !== $perms && ( $perms & 0x0002 ) ) {
					$writable[ Paths::display( Paths::normalize( $target ) ) ] = substr( sprintf( '%o', $perms ), -4 );
				}
			}
			$perms    = @fileperms( $config ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$readable = false !== $perms && ( $perms & 0x0004 );
		}
		$keep = array();
		foreach ( $writable as $path => $mode ) {
			$keep[] = $path;
			self::posture( 'world_writable_sensitive', Findings::HIGH, 'confirmed', $path, __( 'Any account on the server can modify this file or folder.', 'bee-monitor' ), array( 'mode' => $mode ), $mode );
		}
		Findings::auto_resolve( 'world_writable_sensitive', $keep );
		self::posture_toggle( $readable, 'config_world_readable', Findings::LOW, 'wp-config.php', __( 'wp-config.php, which holds database credentials and keys, is readable by every account on the server.', 'bee-monitor' ) );

		$admin = get_user_by( 'login', 'admin' );
		self::posture_toggle( $admin && user_can( $admin, 'manage_options' ), 'default_admin_username', Findings::LOW, 'User admin', __( 'An administrator uses the username "admin", which is the first name tried in brute-force attacks.', 'bee-monitor' ) );

		$php = get_site_transient( 'php_check_' . md5( PHP_VERSION ) );
		if ( is_array( $php ) && isset( $php['is_secure'] ) ) {
			/* translators: 1: current PHP version, 2: recommended version. */
			self::posture_toggle( ! $php['is_secure'], 'php_unsupported', Findings::MEDIUM, 'PHP ' . PHP_VERSION, sprintf( __( 'WordPress.org reports that PHP %1$s no longer receives security updates. Recommended: %2$s or newer.', 'bee-monitor' ), PHP_VERSION, isset( $php['recommended_version'] ) ? sanitize_text_field( $php['recommended_version'] ) : '' ) );
		}
	}

	/**
	 * Record or resolve a single on/off posture condition.
	 *
	 * @param bool   $active   Whether the condition is present.
	 * @param string $rule     Rule.
	 * @param int    $severity Severity.
	 * @param string $subject  Subject.
	 * @param string $reason   Reason.
	 * @param array  $evidence Evidence.
	 */
	private static function posture_toggle( $active, $rule, $severity, $subject, $reason, array $evidence = array() ) {
		if ( $active ) {
			self::posture( $rule, $severity, 'confirmed', $subject, $reason, $evidence, '' );
			Findings::auto_resolve( $rule, array( $subject ) );
		} else {
			Findings::auto_resolve( $rule );
		}
	}

	/**
	 * Record a posture finding.
	 *
	 * @param string $rule       Rule.
	 * @param int    $severity   Severity.
	 * @param string $confidence Confidence.
	 * @param string $subject    Subject.
	 * @param string $reason     Reason.
	 * @param array  $evidence   Evidence.
	 * @param string $key        Dedup key.
	 */
	private static function posture( $rule, $severity, $confidence, $subject, $reason, array $evidence, $key ) {
		Findings::record(
			array(
				'rule'        => $rule,
				'severity'    => $severity,
				'confidence'  => $confidence,
				'basis'       => 'runtime_prepend' === $rule ? 'heuristic' : 'integrity',
				'change_type' => 'detected',
				'subject'     => $subject,
				'reason'      => $reason,
				'evidence'    => $evidence,
				'key'         => $key,
			)
		);
	}

	/**
	 * Key site options.
	 */
	private static function check_options() {
		$admin_email = (string) get_option( 'admin_email' );
		$active      = (array) get_option( 'active_plugins', array() );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		}
		$active   = array_values( array_unique( $active ) );
		$current  = array(
			'siteurl'            => (string) get_option( 'siteurl' ),
			'home'               => (string) get_option( 'home' ),
			'admin_email'        => md5( strtolower( $admin_email ) ),
			'admin_email_masked' => Redactor::email( $admin_email ),
			'users_can_register' => (int) get_option( 'users_can_register' ),
			'default_role'       => (string) get_option( 'default_role' ),
			'template'           => (string) get_option( 'template' ),
			'stylesheet'         => (string) get_option( 'stylesheet' ),
			'active_plugins'     => $active,
		);
		$previous = Storage::get( 'snapshot_options', null );
		Storage::set( 'snapshot_options', $current );
		if ( ! is_array( $previous ) ) {
			return;
		}
		$since = time() - self::CONTEXT_WINDOW;

		foreach ( array( 'siteurl', 'home' ) as $key ) {
			if ( $previous[ $key ] !== $current[ $key ] ) {
				$event = Context::find( array( 'option_update' ), $key, $since );
				self::option_finding( 'site_url_changed', $event ? Findings::MEDIUM : Findings::HIGH, $key, $previous[ $key ], $current[ $key ], $event );
			}
		}
		if ( $previous['admin_email'] !== $current['admin_email'] ) {
			$event = Context::find( array( 'option_update' ), 'admin_email', $since );
			self::option_finding( 'admin_email_changed', $event ? Findings::MEDIUM : Findings::HIGH, 'admin_email', $previous['admin_email_masked'], $current['admin_email_masked'], $event );
		}
		if ( ! $previous['users_can_register'] && $current['users_can_register'] ) {
			$event = Context::find( array( 'option_update' ), 'users_can_register', $since );
			self::option_finding( 'registration_opened', $event ? Findings::MEDIUM : Findings::HIGH, 'users_can_register', '0', '1', $event );
		}
		if ( $previous['default_role'] !== $current['default_role'] ) {
			$role   = get_role( $current['default_role'] );
			$severe = false;
			if ( $role ) {
				foreach ( self::DANGEROUS_CAPS as $cap ) {
					if ( $role->has_cap( $cap ) ) {
						$severe = true;
						break;
					}
				}
			}
			$event = Context::find( array( 'option_update' ), 'default_role', $since );
			self::option_finding( 'default_role_changed', $severe ? Findings::CRITICAL : Findings::MEDIUM, 'default_role', $previous['default_role'], $current['default_role'], $event );
		}
		if ( $previous['stylesheet'] !== $current['stylesheet'] || $previous['template'] !== $current['template'] ) {
			$event = Context::find( array( 'switch_theme', 'option_update' ), '*', $since );
			self::option_finding( 'theme_changed', $event ? Findings::LOW : Findings::MEDIUM, 'stylesheet', $previous['stylesheet'], $current['stylesheet'], $event );
		}
		foreach ( array_diff( $current['active_plugins'], (array) $previous['active_plugins'] ) as $plugin ) {
			$event = Context::find( array( 'activated_plugin' ), $plugin, $since );
			self::option_finding( 'plugin_activated', $event ? Findings::LOW : Findings::MEDIUM, 'active_plugins', '', $plugin, $event );
		}
		foreach ( array_diff( (array) $previous['active_plugins'], $current['active_plugins'] ) as $plugin ) {
			$event = Context::find( array( 'deactivated_plugin' ), $plugin, $since );
			self::option_finding( 'plugin_deactivated', $event ? Findings::LOW : Findings::MEDIUM, 'active_plugins', $plugin, '', $event );
		}
	}

	/**
	 * Record an option change finding.
	 *
	 * @param string     $rule     Rule.
	 * @param int        $severity Severity.
	 * @param string     $option   Option.
	 * @param string     $old      Old display value.
	 * @param string     $new_value New display value.
	 * @param array|null $event    Context event.
	 */
	private static function option_finding( $rule, $severity, $option, $old, $new_value, $event ) {
		Findings::record(
			array(
				'rule'        => $rule,
				'severity'    => $severity,
				'confidence'  => 'confirmed',
				'basis'       => 'event',
				'change_type' => 'changed',
				/* translators: %s: option name. */
				'subject'     => sprintf( __( 'Option: %s', 'bee-monitor' ), $option ),
				/* translators: 1: old value, 2: new value. */
				'reason'      => sprintf( __( 'Changed from "%1$s" to "%2$s".', 'bee-monitor' ), $old, $new_value ) . ' ' . Context::describe( $event ),
				'evidence'    => array(
					'option' => $option,
					'old'    => $old,
					'new'    => $new_value,
				),
				'key'         => md5( $old . '|' . $new_value . '|' . gmdate( 'Y-m-d' ) ),
			)
		);
	}

	/**
	 * New WP-Cron hooks and where their callbacks live.
	 */
	private static function check_cron() {
		$cron  = get_option( 'cron' );
		$hooks = array();
		if ( is_array( $cron ) ) {
			foreach ( $cron as $timestamp => $events ) {
				if ( ! is_array( $events ) ) {
					continue;
				}
				foreach ( array_keys( $events ) as $hook ) {
					$hooks[ (string) $hook ] = true;
				}
			}
		}
		$hooks    = array_slice( array_keys( $hooks ), 0, 2000 );
		$previous = Storage::get( 'snapshot_cron', null );
		Storage::set( 'snapshot_cron', is_array( $previous ) ? array_values( array_unique( array_merge( $previous, $hooks ) ) ) : $hooks );
		if ( ! is_array( $previous ) ) {
			foreach ( $hooks as $hook ) {
				self::cron_source_check( $hook, true );
			}
			return;
		}
		foreach ( array_diff( $hooks, $previous ) as $hook ) {
			self::cron_source_check( $hook, false );
		}
	}

	/**
	 * Report a cron hook, escalating when its callback lives somewhere suspicious.
	 *
	 * @param string $hook     Hook.
	 * @param bool   $baseline Whether this is the first snapshot.
	 */
	private static function cron_source_check( $hook, $baseline ) {
		$files      = Paths::hook_files( $hook );
		$suspicious = array_values( array_filter( $files, array( Paths::class, 'is_suspicious_source' ) ) );
		$display    = array_map( array( Paths::class, 'display' ), $files );
		if ( $suspicious ) {
			Findings::record(
				array(
					'rule'        => 'cron_suspicious_callback',
					'severity'    => Findings::CRITICAL,
					'confidence'  => 'high',
					'basis'       => 'event',
					'change_type' => $baseline ? 'present_at_baseline' : 'added',
					/* translators: %s: hook name. */
					'subject'     => sprintf( __( 'Cron hook: %s', 'bee-monitor' ), substr( $hook, 0, 120 ) ),
					'reason'      => __( 'A scheduled task runs code defined outside plugins, themes, and core, a common persistence technique.', 'bee-monitor' ),
					'evidence'    => array(
						'hook'    => substr( $hook, 0, 120 ),
						'sources' => array_map( array( Paths::class, 'display' ), $suspicious ),
					),
					'key'         => md5( implode( '|', $suspicious ) ),
				)
			);
			return;
		}
		if ( $baseline ) {
			return;
		}
		$event = Context::find( array( 'activated_plugin', 'update_plugin', 'update_theme', 'switch_theme' ), '*', time() - self::CONTEXT_WINDOW );
		Findings::record(
			array(
				'rule'        => 'cron_hook_added',
				'severity'    => $event ? Findings::INFO : Findings::LOW,
				'confidence'  => 'medium',
				'basis'       => 'event',
				'change_type' => 'added',
				/* translators: %s: hook name. */
				'subject'     => sprintf( __( 'Cron hook: %s', 'bee-monitor' ), substr( $hook, 0, 120 ) ),
				'reason'      => empty( $files )
					? __( 'A new scheduled task appeared and no code currently handles it (it may be left over from a removed plugin, or registered only on some requests).', 'bee-monitor' )
					: __( 'A new scheduled task appeared. Its handler is defined in the source listed in the evidence.', 'bee-monitor' ),
				'evidence'    => array(
					'hook'    => substr( $hook, 0, 120 ),
					'sources' => $display,
				),
				'key'         => '',
				'status'      => $event ? Findings::STATUS_AUTO : Findings::STATUS_OPEN,
			)
		);
	}

	/**
	 * Daily search for injected scripts and code in options and posts.
	 */
	private static function content_sweep() {
		global $wpdb;
		$allow = array_filter( array_map( 'trim', explode( "\n", (string) Settings::value( 'content_domain_allowlist' ) ) ) );
		$host  = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( $host ) {
			$allow[] = preg_replace( '/^www\./', '', strtolower( $host ) );
		}

		$options = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} WHERE ( option_value LIKE %s OR option_value LIKE %s OR option_value LIKE %s ) AND option_name NOT LIKE %s AND option_name NOT LIKE %s AND option_name NOT LIKE %s LIMIT 200",
				'%' . $wpdb->esc_like( '<script' ) . '%',
				'%' . $wpdb->esc_like( 'eval(' ) . '%',
				'%' . $wpdb->esc_like( 'base64_decode(' ) . '%',
				$wpdb->esc_like( '_transient_' ) . '%',
				$wpdb->esc_like( '_site_transient_' ) . '%',
				$wpdb->esc_like( 'bee_monitor_' ) . '%'
			),
			ARRAY_A
		);
		foreach ( (array) $options as $opt ) {
			$value   = (string) $opt['option_value'];
			$reasons = array();
			$domains = self::external_script_domains( $value, $allow );
			if ( $domains ) {
				/* translators: %s: list of domains. */
				$reasons[] = sprintf( __( 'loads scripts from %s', 'bee-monitor' ), implode( ', ', $domains ) );
			}
			if ( preg_match( '~\b(?:eval|base64_decode)\s*\(~i', $value, $m, PREG_OFFSET_CAPTURE ) ) {
				$reasons[] = __( 'contains eval() or base64_decode()', 'bee-monitor' );
			}
			if ( ! $reasons ) {
				continue;
			}
			Findings::record(
				array(
					'rule'        => 'injected_option_content',
					'severity'    => Findings::MEDIUM,
					'confidence'  => 'low',
					'basis'       => 'heuristic',
					'change_type' => 'detected',
					/* translators: %s: option name. */
					'subject'     => sprintf( __( 'Option: %s', 'bee-monitor' ), substr( $opt['option_name'], 0, 150 ) ),
					/* translators: %s: reasons. */
					'reason'      => sprintf( __( 'This option %s. Some plugins store scripts legitimately (for example, header code or widgets).', 'bee-monitor' ), implode( '; ', $reasons ) ),
					'evidence'    => array(
						'option'  => substr( $opt['option_name'], 0, 150 ),
						'domains' => $domains,
						'length'  => strlen( $value ),
					),
					'key'         => md5( $value ),
				)
			);
		}

		$posts = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ID, post_type, post_content FROM {$wpdb->posts} WHERE post_type <> %s AND post_status IN ('publish','future','draft','pending','private') AND post_content LIKE %s ORDER BY post_modified_gmt DESC LIMIT 200",
				'revision',
				'%' . $wpdb->esc_like( '<script' ) . '%'
			),
			ARRAY_A
		);
		foreach ( (array) $posts as $post ) {
			$content = (string) $post['post_content'];
			$domains = self::external_script_domains( $content, $allow );
			$obf     = (bool) preg_match( '~<script[^>]*>[^<]*(?:eval\(|atob\(|String\.fromCharCode|document\.write\(\s*unescape)~i', $content );
			if ( ! $domains && ! $obf ) {
				continue;
			}
			Findings::record(
				array(
					'rule'        => 'injected_post_script',
					'severity'    => $obf ? Findings::HIGH : Findings::MEDIUM,
					'confidence'  => 'low',
					'basis'       => 'heuristic',
					'change_type' => 'detected',
					/* translators: 1: post type, 2: post ID. */
					'subject'     => sprintf( __( '%1$s ID %2$d', 'bee-monitor' ), $post['post_type'], (int) $post['ID'] ),
					'reason'      => $obf
						? __( 'Post content contains an inline script with obfuscation patterns (eval, atob, fromCharCode, or unescape).', 'bee-monitor' )
						/* translators: %s: list of domains. */
						: sprintf( __( 'Post content loads scripts from domains not on the allowlist: %s.', 'bee-monitor' ), implode( ', ', $domains ) ),
					'evidence'    => array(
						'post_id' => (int) $post['ID'],
						'domains' => $domains,
					),
					'key'         => md5( $content ),
				)
			);
		}
	}

	/**
	 * External script domains not on the allowlist.
	 *
	 * @param string   $html  HTML.
	 * @param string[] $allow Allowed domains.
	 * @return string[]
	 */
	private static function external_script_domains( $html, array $allow ) {
		$found = array();
		if ( ! preg_match_all( '~<script[^>]+src\s*=\s*["\']?\s*(?:https?:)?//([^/"\'\s>]+)~i', $html, $m ) ) {
			return $found;
		}
		foreach ( $m[1] as $domain ) {
			$domain = strtolower( preg_replace( '/:\d+$/', '', $domain ) );
			$ok     = false;
			foreach ( $allow as $allowed ) {
				if ( $domain === $allowed || substr( $domain, -strlen( '.' . $allowed ) ) === '.' . $allowed ) {
					$ok = true;
					break;
				}
			}
			if ( ! $ok ) {
				$found[ $domain ] = $domain;
			}
		}
		return array_slice( array_values( $found ), 0, 10 );
	}

	/**
	 * Detect Bee Monitor settings edited outside its screen.
	 */
	private static function check_settings_integrity() {
		$stored = (string) Storage::get( 'settings_hash', '' );
		$actual = Settings::hash();
		if ( '' === $stored ) {
			Storage::set( 'settings_hash', $actual );
			return;
		}
		if ( hash_equals( $stored, $actual ) ) {
			return;
		}
		Settings::flush();
		Findings::record(
			array(
				'rule'        => 'settings_changed_externally',
				'severity'    => Findings::HIGH,
				'confidence'  => 'medium',
				'basis'       => 'monitor',
				'change_type' => 'changed',
				'subject'     => __( 'Bee Monitor settings', 'bee-monitor' ),
				'reason'      => __( 'Bee Monitor settings no longer match the signature saved by its settings screen. They may have been edited directly in the database, or the site salts changed.', 'bee-monitor' ),
				'evidence'    => array(
					'enabled'    => (int) Settings::value( 'enabled' ),
					'exclusions' => Settings::exclusions(),
					'recipients' => array_map( array( Redactor::class, 'email' ), Settings::recipients() ),
				),
				'key'         => $actual,
			)
		);
		Storage::set( 'settings_hash', $actual );
	}

	/**
	 * Detect email interception code in unusual locations.
	 */
	private static function check_mail_filters() {
		$suspicious = array();
		foreach ( array( 'pre_wp_mail', 'wp_mail', 'phpmailer_init', 'wp_mail_from' ) as $hook ) {
			foreach ( Paths::hook_files( $hook ) as $file ) {
				if ( Paths::is_suspicious_source( $file ) ) {
					$suspicious[ $hook . ':' . $file ] = $hook . ' → ' . Paths::display( $file );
				}
			}
		}
		if ( ! $suspicious ) {
			return;
		}
		Findings::record(
			array(
				'rule'        => 'mail_filter_suspicious',
				'severity'    => Findings::HIGH,
				'confidence'  => 'medium',
				'basis'       => 'heuristic',
				'change_type' => 'detected',
				'subject'     => __( 'Outgoing email hooks', 'bee-monitor' ),
				'reason'      => __( 'Code outside plugins, themes, and core is hooked into WordPress email. It could intercept or suppress alerts.', 'bee-monitor' ),
				'evidence'    => array( 'sources' => array_values( $suspicious ) ),
				'key'         => md5( implode( '|', array_keys( $suspicious ) ) ),
			)
		);
	}

	/**
	 * Detect long gaps between scans (WP-Cron not running or monitor disabled).
	 *
	 * @param array $state Scan state.
	 */
	private static function check_scan_gap( array $state ) {
		$last = Storage::get( 'last_scan', array() );
		if ( ! is_array( $last ) || empty( $last['finished'] ) ) {
			return;
		}
		$interval = Settings::interval_seconds();
		$gap      = (int) $state['started'] - (int) $last['finished'];
		$limit    = max( 3 * $interval, $interval + 2 * HOUR_IN_SECONDS );
		if ( $gap <= $limit ) {
			return;
		}
		Findings::record(
			array(
				'rule'        => 'scan_gap',
				'severity'    => Findings::MEDIUM,
				'confidence'  => 'confirmed',
				'basis'       => 'monitor',
				'change_type' => 'detected',
				'subject'     => __( 'Bee Monitor schedule', 'bee-monitor' ),
				/* translators: 1: hours, 2: expected interval in minutes. */
				'reason'      => sprintf( __( 'No scan completed for %1$s hours, although scans are scheduled every %2$d minutes. Changes made during the gap are still detected now, but alerts were delayed.', 'bee-monitor' ), number_format_i18n( $gap / HOUR_IN_SECONDS, 1 ), (int) ( $interval / MINUTE_IN_SECONDS ) ),
				'evidence'    => array(
					'previous_finished' => gmdate( 'c', (int) $last['finished'] ),
					'this_started'      => gmdate( 'c', (int) $state['started'] ),
				),
				'key'         => (string) $last['finished'],
			)
		);
	}
}
