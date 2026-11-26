<?php
/**
 * Admin screens: findings, baseline, settings, and tools.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Admin UI and request handlers.
 */
final class Admin {

	const PER_PAGE = 50;

	/**
	 * Register hooks.
	 */
	public function __construct() {
		add_action( is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'assets' ) );
		add_action( is_multisite() ? 'network_admin_notices' : 'admin_notices', array( $this, 'notices' ) );
		add_action( 'admin_post_bee_monitor_save_settings', array( $this, 'handle_settings' ) );
		add_action( 'admin_post_bee_monitor_findings', array( $this, 'handle_findings' ) );
		add_action( 'admin_post_bee_monitor_baseline', array( $this, 'handle_baseline' ) );
		add_action( 'admin_post_bee_monitor_email', array( $this, 'handle_email' ) );
		add_action( 'wp_ajax_bee_monitor_scan_step', array( $this, 'ajax_scan_step' ) );
		add_action( 'wp_ajax_bee_monitor_scan_cancel', array( $this, 'ajax_scan_cancel' ) );
		add_action( 'admin_post_bee_monitor_export', array( $this, 'handle_export' ) );
		add_action( 'admin_post_bee_monitor_fix', array( $this, 'handle_fix' ) );
		add_action( 'admin_post_bee_monitor_activity', array( $this, 'handle_activity' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( BEE_MONITOR_FILE ), array( $this, 'action_links' ) );
		add_filter( 'network_admin_plugin_action_links_' . plugin_basename( BEE_MONITOR_FILE ), array( $this, 'action_links' ) );
	}

	/**
	 * Required capability.
	 *
	 * @return string
	 */
	public static function capability() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	/**
	 * Capability to view findings (read-only). Multisite keeps network-admin-only access.
	 *
	 * @return string
	 */
	public static function view_capability() {
		return is_multisite() ? self::capability() : 'bee_monitor_view';
	}

	/**
	 * Whether the current user can manage (not just view) Bee Monitor.
	 *
	 * @return bool
	 */
	private static function can_manage() {
		return current_user_can( self::capability() );
	}

	/**
	 * URL of a Bee Monitor admin page.
	 *
	 * @param string $page Page slug.
	 * @param array  $args Query args.
	 * @return string
	 */
	public static function page_url( $page, array $args = array() ) {
		$base = is_multisite() ? network_admin_url( 'admin.php' ) : admin_url( 'admin.php' );
		return add_query_arg( array_merge( array( 'page' => $page ), $args ), $base );
	}

	/**
	 * Settings link on the Plugins screen.
	 *
	 * @param array $links Links.
	 * @return array
	 */
	public function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( self::page_url( 'bee-monitor-settings' ) ) . '">' . esc_html__( 'Settings', 'bee-monitor' ) . '</a>' );
		return $links;
	}

	/**
	 * Menus.
	 */
	public function menu() {
		$cap    = self::capability();
		$counts = Storage::tables_exist() ? Findings::open_counts() : array_fill( 0, 5, 0 );
		$urgent = $counts[ Findings::CRITICAL ] + $counts[ Findings::HIGH ];
		$badge  = $urgent ? ' <span class="awaiting-mod"><span class="pending-count">' . (int) $urgent . '</span></span>' : '';

		$view = self::view_capability();
		add_menu_page( __( 'Bee Monitor', 'bee-monitor' ), __( 'Bee Monitor', 'bee-monitor' ) . $badge, $view, 'bee-monitor', array( $this, 'page_findings' ), Brand::menu_icon(), 81 );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Findings', 'bee-monitor' ), __( 'Findings', 'bee-monitor' ), $view, 'bee-monitor', array( $this, 'page_findings' ) );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Baseline', 'bee-monitor' ), __( 'Baseline', 'bee-monitor' ), $cap, 'bee-monitor-baseline', array( $this, 'page_baseline' ) );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Settings', 'bee-monitor' ), __( 'Settings', 'bee-monitor' ), $cap, 'bee-monitor-settings', array( $this, 'page_settings' ) );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Activity', 'bee-monitor' ), __( 'Activity', 'bee-monitor' ), $cap, 'bee-monitor-activity', array( $this, 'page_activity' ) );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Tools', 'bee-monitor' ), __( 'Tools & Status', 'bee-monitor' ), $cap, 'bee-monitor-tools', array( $this, 'page_tools' ) );
	}

	/**
	 * Whether the current screen is a Bee Monitor page.
	 *
	 * @return bool
	 */
	private function is_our_page() {
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		return 0 === strpos( $page, 'bee-monitor' );
	}

	/**
	 * Enqueue assets on Bee Monitor pages only.
	 */
	public function assets() {
		if ( ! $this->is_our_page() ) {
			return;
		}
		wp_enqueue_style( 'bee-monitor-admin', BEE_MONITOR_URL . 'assets/admin.css', array(), BEE_MONITOR_VERSION );
		wp_enqueue_script( 'bee-monitor-admin', BEE_MONITOR_URL . 'assets/admin.js', array(), BEE_MONITOR_VERSION, true );
		wp_localize_script(
			'bee-monitor-admin',
			'BeeMonitorAdmin',
			array(
				'ajaxUrl'     => admin_url( 'admin-ajax.php' ),
				'nonce'       => wp_create_nonce( 'bee_monitor_scan' ),
				'findingsUrl' => self::page_url( 'bee-monitor' ),
				'i18n'        => array(
					'starting'       => __( 'Starting scan…', 'bee-monitor' ),
					/* translators: 1: scan phase, 2: files checked, 3: new findings. */
					'running'        => __( 'Scanning: phase %1$s, %2$d files checked, %3$d new findings…', 'bee-monitor' ),
					/* translators: 1: files checked, 2: new findings. */
					'done'           => __( 'Scan complete: %1$d files checked, %2$d new findings.', 'bee-monitor' ),
					'view'           => __( 'View findings', 'bee-monitor' ),
					'error'          => __( 'The scan request failed. Bee Monitor will continue in the background via WP-Cron. Check Tools & Status for errors.', 'bee-monitor' ),
					'confirm'        => __( 'Are you sure? This cannot be undone.', 'bee-monitor' ),
					'cancelling'     => __( 'Cancelling…', 'bee-monitor' ),
					'startingRemote' => __( 'Starting scan with public page checks…', 'bee-monitor' ),
					'startingFull'   => __( 'Starting full integrity scan…', 'bee-monitor' ),
					'copied'         => __( 'Copied', 'bee-monitor' ),
					'copyFailed'     => __( 'Selected — press Ctrl+C or Cmd+C to copy', 'bee-monitor' ),
					'cancelled'      => __( 'Scan cancelled. The baseline was not changed.', 'bee-monitor' ),
					'forbidden'      => __( 'You do not have permission to run scans.', 'bee-monitor' ),
					'expired'        => __( 'Your session expired. Reload the page and try again.', 'bee-monitor' ),
					'resume'         => __( 'Resume scan', 'bee-monitor' ),
					/* translators: 1: phase, 2: files checked, 3: new findings. */
					'progress'       => __( '%1$s · %2$d files checked · %3$d new findings', 'bee-monitor' ),
				),
			)
		);
	}

	/**
	 * Admin notices: stored results and open urgent findings.
	 */
	public function notices() {
		if ( ! current_user_can( self::capability() ) ) {
			return;
		}
		$key    = 'bee_monitor_notices_' . get_current_user_id();
		$stored = get_transient( $key );
		if ( is_array( $stored ) && $this->is_our_page() ) {
			delete_transient( $key );
			foreach ( $stored as $notice ) {
				printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $notice['type'] ), esc_html( $notice['message'] ) );
			}
		}
		$screen = get_current_screen();
		if ( ! $this->is_our_page() && ! ( $screen && in_array( $screen->base, array( 'dashboard', 'dashboard-network' ), true ) ) ) {
			return;
		}
		if ( ! Storage::tables_exist() ) {
			echo '<div class="notice notice-error"><p>' . esc_html__( 'Bee Monitor database tables are missing. Deactivate and reactivate Bee Monitor to recreate them.', 'bee-monitor' ) . '</p></div>';
			return;
		}
		$counts    = Findings::open_counts();
		$dashboard = $screen && 'toplevel_page_bee-monitor' === $screen->id && ! isset( $_GET['finding'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- view state only.
		if ( ( $counts[ Findings::CRITICAL ] || $counts[ Findings::HIGH ] ) && ! $dashboard ) {
			printf(
				'<div class="notice notice-error"><p><strong>%1$s</strong> %2$s <a href="%3$s">%4$s</a></p></div>',
				esc_html__( 'Bee Monitor:', 'bee-monitor' ),
				/* translators: 1: critical count, 2: high count. */
				esc_html( sprintf( __( '%1$d critical and %2$d high-severity findings are open.', 'bee-monitor' ), $counts[ Findings::CRITICAL ], $counts[ Findings::HIGH ] ) ),
				esc_url( self::page_url( 'bee-monitor' ) ),
				esc_html__( 'Review findings', 'bee-monitor' )
			);
		}
		$mail = Storage::get( 'mail_status', array() );
		if ( is_array( $mail ) && ! empty( $mail['time'] ) && empty( $mail['ok'] ) ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Bee Monitor: the last alert email failed to send. Use Tools & Status > Send test email to diagnose delivery.', 'bee-monitor' ) . '</p></div>';
		}
	}

	/**
	 * Queue a notice for the next page load.
	 *
	 * @param string $type    success|error|warning|info.
	 * @param string $message Message.
	 */
	private function flash( $type, $message ) {
		$key      = 'bee_monitor_notices_' . get_current_user_id();
		$stored   = get_transient( $key );
		$stored   = is_array( $stored ) ? $stored : array();
		$stored[] = array(
			'type'    => $type,
			'message' => $message,
		);
		set_transient( $key, $stored, 5 * MINUTE_IN_SECONDS );
	}

	/**
	 * Verify capability and nonce for a POST handler.
	 *
	 * @param string $action Nonce action.
	 */
	private function guard( $action ) {
		if ( ! current_user_can( self::capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to manage Bee Monitor.', 'bee-monitor' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	// Settings.

	/**
	 * Settings API sections and fields.
	 */
	public function register_settings() {
		$page     = 'bee-monitor-settings';
		$sections = array(
			'bee_monitor_scanning' => array( __( 'Scanning', 'bee-monitor' ), __( 'How often Bee Monitor checks files and how much work each step does.', 'bee-monitor' ), 'scan-search' ),
			'bee_monitor_scope'    => array( __( 'Scope and exclusions', 'bee-monitor' ), __( 'Excluded paths are not checked at all. Every exclusion is a place where malware would go unnoticed, so keep this list short.', 'bee-monitor' ), 'folder' ),
			'bee_monitor_checks'   => array( __( 'Integrity and site checks', 'bee-monitor' ), '', 'shield-check' ),
			'bee_monitor_alerts'   => array( __( 'Email alerts', 'bee-monitor' ), __( 'Alerts are sent with wp_mail(). Use an SMTP or transactional email plugin for reliable delivery.', 'bee-monitor' ), 'mail' ),
			'bee_monitor_advanced' => array( __( 'Tamper detection and data', 'bee-monitor' ), '', 'key-round' ),
		);
		foreach ( $sections as $id => $section ) {
			$desc = $section[1];
			add_settings_section(
				$id,
				Icons::svg( $section[2] ) . esc_html( $section[0] ),
				function () use ( $desc ) {
					if ( $desc ) {
						echo '<p>' . esc_html( $desc ) . '</p>';
					}
				},
				$page
			);
		}

		$fields = array(
			array( 'enabled', 'bee_monitor_scanning', 'checkbox', __( 'Enable monitoring', 'bee-monitor' ), __( 'Run scheduled scans and send alerts.', 'bee-monitor' ) ),
			array(
				'scan_frequency',
				'bee_monitor_scanning',
				'select',
				__( 'Scan frequency', 'bee-monitor' ),
				__( 'WP-Cron runs only when the site gets traffic. For reliable timing, disable WP-Cron and call wp-cron.php from a server cron job.', 'bee-monitor' ),
				array(
					'bee_monitor_15min' => __( 'Every 15 minutes', 'bee-monitor' ),
					'hourly'            => __( 'Hourly', 'bee-monitor' ),
					'twicedaily'        => __( 'Twice daily', 'bee-monitor' ),
					'daily'             => __( 'Daily', 'bee-monitor' ),
				),
			),
			array( 'time_budget', 'bee_monitor_scanning', 'number', __( 'Time budget per step (seconds)', 'bee-monitor' ), __( 'Large sites are scanned in several steps. Lower this if your host has a short PHP time limit.', 'bee-monitor' ) ),
			array( 'max_inspect_kb', 'bee_monitor_scanning', 'number', __( 'Maximum file size to inspect (KB)', 'bee-monitor' ), __( 'Larger files are still hashed but not searched for code indicators.', 'bee-monitor' ) ),
			array( 'exclusions', 'bee_monitor_scope', 'textarea', __( 'Excluded paths', 'bee-monitor' ), __( 'One pattern per line, relative to the WordPress root. * matches any characters, including /. Example: wp-content/updraft/*', 'bee-monitor' ) ),
			array( 'extra_extensions', 'bee_monitor_scope', 'text', __( 'Extra executable extensions', 'bee-monitor' ), __( 'Comma-separated, in addition to php, phtml, phar, php3–8, pht, phpt, phps, and inc.', 'bee-monitor' ) ),
			array( 'scan_parent_dir', 'bee_monitor_scope', 'checkbox', __( 'Check the directory above WordPress', 'bee-monitor' ), __( 'Checks PHP and config files directly above the WordPress root (not subdirectories), where wp-config.php and prepend payloads can live.', 'bee-monitor' ) ),
			array( 'inspect_upload_images', 'bee_monitor_scope', 'checkbox', __( 'Inspect media files in uploads for PHP', 'bee-monitor' ), __( 'Reads images and text files in uploads to find hidden PHP. Slower on large media libraries.', 'bee-monitor' ) ),
			array( 'core_checksums', 'bee_monitor_checks', 'checkbox', __( 'Verify core with official checksums', 'bee-monitor' ), __( 'Fetches checksums for your WordPress version from api.wordpress.org.', 'bee-monitor' ) ),
			array( 'plugin_checksums', 'bee_monitor_checks', 'checkbox', __( 'Verify plugins against WordPress.org checksums', 'bee-monitor' ), __( 'Off by default. When on, changed plugin files are compared with the official release of the installed version (the same data as "wp plugin verify-checksums"). Sends the plugin folder name and version to downloads.wordpress.org; results are cached for a day.', 'bee-monitor' ) ),
			array( 'remote_checks', 'bee_monitor_checks', 'checkbox', __( 'Check public pages', 'bee-monitor' ), __( 'Off by default. Once a day (and on demand), Bee Monitor loads the home page, login page, and up to five recent posts and pages from this site, as a visitor and as a search engine, to look for injected scripts, hidden frames or links, redirects, cloaking, and visible errors. Requests go only to this site. Remote checks see rendered pages, not server files.', 'bee-monitor' ) ),
			array( 'posture_checks', 'bee_monitor_checks', 'checkbox', __( 'Configuration and persistence checks', 'bee-monitor' ), __( 'Read-only checks for runtime prepend files, hidden administrators, the dashboard file editor, debug output, world-writable files, and unsupported PHP. Findings close automatically once fixed.', 'bee-monitor' ) ),
			array( 'auto_accept_verified_core', 'bee_monitor_checks', 'checkbox', __( 'Accept core changes that match official checksums', 'bee-monitor' ), __( 'Core updates are verified file by file, so they do not create alerts.', 'bee-monitor' ) ),
			array( 'auto_accept_updates', 'bee_monitor_checks', 'checkbox', __( 'Accept plugin, theme, and translation changes during recorded updates', 'bee-monitor' ), __( 'Files changed within the grace window of an update recorded by WordPress are accepted unless they contain suspicious code. Turn off to review every change manually.', 'bee-monitor' ) ),
			array( 'update_grace_minutes', 'bee_monitor_checks', 'number', __( 'Update grace window (minutes)', 'bee-monitor' ), '' ),
			array( 'monitor_users', 'bee_monitor_checks', 'checkbox', __( 'Monitor privileged users and roles', 'bee-monitor' ), '' ),
			array( 'monitor_options', 'bee_monitor_checks', 'checkbox', __( 'Monitor key site options', 'bee-monitor' ), __( 'Site address, admin email, registration, default role, active plugins, and theme.', 'bee-monitor' ) ),
			array( 'monitor_cron', 'bee_monitor_checks', 'checkbox', __( 'Monitor scheduled tasks', 'bee-monitor' ), '' ),
			array( 'content_sweep', 'bee_monitor_checks', 'checkbox', __( 'Daily content injection sweep', 'bee-monitor' ), __( 'Looks for scripts and code injected into options and posts.', 'bee-monitor' ) ),
			array( 'content_domain_allowlist', 'bee_monitor_checks', 'textarea', __( 'Trusted script domains', 'bee-monitor' ), __( 'One per line, for example your analytics or tag manager domain. Subdomains are included. Your own domain is always trusted.', 'bee-monitor' ) ),
			array( 'monitor_logins', 'bee_monitor_checks', 'checkbox', __( 'Monitor login activity', 'bee-monitor' ), __( 'Uses REMOTE_ADDR only. Behind a proxy or CDN, all visitors may appear to come from the proxy.', 'bee-monitor' ) ),
			array( 'failed_login_threshold', 'bee_monitor_checks', 'number', __( 'Failed logins per 15 minutes before alerting', 'bee-monitor' ), '' ),
			array( 'recipient_rows', 'bee_monitor_alerts', 'recipients', __( 'Recipients and routing', 'bee-monitor' ), __( 'Each recipient gets findings in the chosen categories immediately at or above their severity, and everything else in the digest if enabled. Leave empty to use the site administration email.', 'bee-monitor' ) ),
			array( 'from_name', 'bee_monitor_alerts', 'text', __( 'From name', 'bee-monitor' ), '' ),
			array( 'from_email', 'bee_monitor_alerts', 'text', __( 'From address', 'bee-monitor' ), __( 'Optional. Leave empty to use the address your email or SMTP plugin sends from. Use an address on this site\'s domain for reliable delivery.', 'bee-monitor' ) ),
			array( 'reply_to', 'bee_monitor_alerts', 'text', __( 'Reply-To address', 'bee-monitor' ), __( 'Optional, for example your support inbox.', 'bee-monitor' ) ),
			array( 'subject_label', 'bee_monitor_alerts', 'text', __( 'Subject label', 'bee-monitor' ), __( 'Shown in subjects instead of the site name, for example a client code. Up to 40 characters.', 'bee-monitor' ) ),
			array(
				'email_format',
				'bee_monitor_alerts',
				'select',
				__( 'Email format', 'bee-monitor' ),
				'',
				array(
					'html' => __( 'HTML with plain-text version', 'bee-monitor' ),
					'text' => __( 'Plain text only', 'bee-monitor' ),
				),
			),
			array(
				'evidence_detail',
				'bee_monitor_alerts',
				'select',
				__( 'Evidence in emails', 'bee-monitor' ),
				__( 'Summary leaves out code snippets and hashes, for recipients who should not receive code by email.', 'bee-monitor' ),
				array(
					'full'    => __( 'Full (redacted snippets and hashes)', 'bee-monitor' ),
					'summary' => __( 'Summary (path, reason, next steps)', 'bee-monitor' ),
				),
			),
			array(
				'digest_frequency',
				'bee_monitor_alerts',
				'select',
				__( 'Digest', 'bee-monitor' ),
				'',
				array(
					'hourly' => __( 'Hourly', 'bee-monitor' ),
					'daily'  => __( 'Daily', 'bee-monitor' ),
					'weekly' => __( 'Weekly', 'bee-monitor' ),
					'off'    => __( 'Off (findings below each recipient\'s threshold are not emailed)', 'bee-monitor' ),
				),
			),
			array( 'digest_time', 'bee_monitor_alerts', 'time', __( 'Digest time', 'bee-monitor' ), __( 'In the site timezone. Used for daily and weekly digests.', 'bee-monitor' ) ),
			array(
				'digest_weekday',
				'bee_monitor_alerts',
				'select',
				__( 'Weekly digest day', 'bee-monitor' ),
				'',
				self::weekdays(),
			),
			array( 'digest_all_clear', 'bee_monitor_alerts', 'checkbox', __( 'Send digest even when there is nothing new', 'bee-monitor' ), __( 'A regular "all clear" email confirms monitoring is still running.', 'bee-monitor' ) ),
			array( 'max_emails_per_hour', 'bee_monitor_alerts', 'number', __( 'Maximum emails per hour, per recipient', 'bee-monitor' ), __( 'Extra findings are held and included in the next email.', 'bee-monitor' ) ),
			array( 'reminder_days', 'bee_monitor_alerts', 'number', __( 'Remind about open high and critical findings every (days)', 'bee-monitor' ), __( '0 turns reminders off.', 'bee-monitor' ) ),
			array( 'ignore_rules', 'bee_monitor_scope', 'textarea', __( 'Ignore rules', 'bee-monitor' ), __( 'One rule per line: a finding type and a path pattern, for example "suspicious_code wp-content/plugins/my-plugin/vendor/*". Matching findings are recorded as Ignored and not emailed. Use "*" as the type to ignore every type (not recommended).', 'bee-monitor' ) ),
			array( 'activity_retention_days', 'bee_monitor_advanced', 'number', __( 'Keep activity log for (days)', 'bee-monitor' ), __( 'Older entries are deleted after each scan. You can also delete the whole log from Bee Monitor > Activity.', 'bee-monitor' ) ),
			array( 'allow_repairs', 'bee_monitor_advanced', 'checkbox', __( 'Allow administrator-reviewed repairs', 'bee-monitor' ), __( 'Off by default. Lets administrators repair WordPress core and WordPress.org plugin files from official, checksum-verified sources, and quarantine flagged files. Every action needs confirmation, keeps a recoverable copy, and is logged. Nothing is ever changed automatically. Not available when DISALLOW_FILE_MODS is set.', 'bee-monitor' ) ),
			array( 'retention_days', 'bee_monitor_advanced', 'number', __( 'Delete closed findings after (days)', 'bee-monitor' ), __( 'Resolved, expected, and auto-verified findings not seen for this many days are deleted. Open findings are never deleted automatically. 0 keeps them forever.', 'bee-monitor' ) ),
			array( 'heartbeat_url', 'bee_monitor_advanced', 'url', __( 'Heartbeat URL', 'bee-monitor' ), __( 'Optional https URL pinged after every completed scan (for example, a Healthchecks.io check). If pings stop, that service alerts you, even when this site is compromised or offline.', 'bee-monitor' ) ),
			array( 'delete_data_on_uninstall', 'bee_monitor_advanced', 'checkbox', __( 'Delete all Bee Monitor data on uninstall', 'bee-monitor' ), __( 'When off (default), findings, baseline, and settings are kept if the plugin is deleted, so history survives a reinstall.', 'bee-monitor' ) ),
		);
		if ( ! is_multisite() ) {
			$fields[] = array( 'viewer_roles', 'bee_monitor_advanced', 'roles', __( 'Read-only access', 'bee-monitor' ), __( 'Users with these roles can view findings but cannot change settings, accept changes, or run scans. Useful for clients.', 'bee-monitor' ) );
		}
		foreach ( $fields as $field ) {
			add_settings_field(
				'bee_monitor_' . $field[0],
				$field[3],
				array( $this, 'render_field' ),
				$page,
				$field[1],
				array(
					'key'       => $field[0],
					'type'      => $field[2],
					'help'      => $field[4],
					'choices'   => isset( $field[5] ) ? $field[5] : array(),
					'label_for' => in_array( $field[2], array( 'checkbox', 'recipients', 'roles' ), true ) ? null : 'bee-monitor-' . $field[0],
				)
			);
		}
	}

	/**
	 * Render a settings field.
	 *
	 * @param array $args Args.
	 */
	public function render_field( $args ) {
		$key   = $args['key'];
		$value = Settings::value( $key );
		$id    = 'bee-monitor-' . $key;
		$name  = 'bee_monitor[' . $key . ']';
		$descr = $args['help'] ? $id . '-help' : '';

		switch ( $args['type'] ) {
			case 'checkbox':
				printf( '<label for="%1$s"><input type="checkbox" id="%1$s" name="%2$s" value="1" %3$s aria-describedby="%4$s"> %5$s</label>', esc_attr( $id ), esc_attr( $name ), checked( 1, (int) $value, false ), esc_attr( $descr ), esc_html__( 'Enabled', 'bee-monitor' ) );
				break;
			case 'select':
				printf( '<select id="%1$s" name="%2$s" aria-describedby="%3$s">', esc_attr( $id ), esc_attr( $name ), esc_attr( $descr ) );
				foreach ( $args['choices'] as $choice => $label ) {
					printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $choice ), selected( $value, $choice, false ), esc_html( $label ) );
				}
				echo '</select>';
				break;
			case 'textarea':
				printf( '<textarea id="%1$s" name="%2$s" rows="6" cols="60" class="large-text code" aria-describedby="%3$s">%4$s</textarea>', esc_attr( $id ), esc_attr( $name ), esc_attr( $descr ), esc_textarea( (string) $value ) );
				break;
			case 'number':
				printf( '<input type="number" id="%1$s" name="%2$s" value="%3$s" class="small-text" min="0" aria-describedby="%4$s">', esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $value ), esc_attr( $descr ) );
				break;
			case 'time':
				printf( '<input type="time" id="%1$s" name="%2$s" value="%3$s" aria-describedby="%4$s">', esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $value ), esc_attr( $descr ) );
				break;
			case 'recipients':
				$this->render_recipients( (array) $value );
				break;
			case 'roles':
				foreach ( wp_roles()->roles as $role => $data ) {
					if ( ! empty( $data['capabilities']['manage_options'] ) ) {
						continue;
					}
					printf( '<label style="display:inline-block;margin:0 14px 6px 0;"><input type="checkbox" name="%1$s[]" value="%2$s" %3$s> %4$s</label>', esc_attr( $name ), esc_attr( $role ), checked( in_array( $role, (array) $value, true ), true, false ), esc_html( translate_user_role( $data['name'] ) ) );
				}
				break;
			case 'url':
				printf( '<input type="url" id="%1$s" name="%2$s" value="%3$s" class="regular-text code" placeholder="https://" aria-describedby="%4$s">', esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $value ), esc_attr( $descr ) );
				break;
			default:
				printf( '<input type="text" id="%1$s" name="%2$s" value="%3$s" class="regular-text" aria-describedby="%4$s">', esc_attr( $id ), esc_attr( $name ), esc_attr( (string) $value ), esc_attr( $descr ) );
		}
		if ( $args['help'] ) {
			printf( '<p class="description" id="%1$s">%2$s</p>', esc_attr( $descr ), esc_html( $args['help'] ) );
		}
		if ( 'exclusions' === $key ) {
			$risky = Settings::risky_exclusions( Settings::exclusions() );
			if ( $risky ) {
				echo '<p class="bee-monitor-warning">' . esc_html__( 'These exclusions hide high-risk locations:', 'bee-monitor' ) . ' <code>' . esc_html( implode( '</code>, <code>', $risky ) ) . '</code></p>';
			}
		}
	}

	/**
	 * Weekday choices.
	 *
	 * @return array
	 */
	private static function weekdays() {
		global $wp_locale;
		$days = array();
		for ( $i = 0; $i < 7; $i++ ) {
			$days[ (string) $i ] = $wp_locale ? $wp_locale->get_weekday( $i ) : (string) $i;
		}
		return $days;
	}

	/**
	 * Recipient routing table.
	 *
	 * @param array $rows Rows.
	 */
	private function render_recipients( array $rows ) {
		$severities = array(
			'critical' => __( 'Critical only', 'bee-monitor' ),
			'high'     => __( 'High and above', 'bee-monitor' ),
			'medium'   => __( 'Medium and above', 'bee-monitor' ),
			'low'      => __( 'Everything', 'bee-monitor' ),
		);
		echo '<table class="widefat bee-monitor-recipients"><thead><tr>';
		echo '<th scope="col">' . esc_html__( 'Email', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Send immediately', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Digest', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Categories', 'bee-monitor' ) . '</th><th scope="col"><span class="screen-reader-text">' . esc_html__( 'Remove', 'bee-monitor' ) . '</span></th>';
		echo '</tr></thead><tbody id="bee-monitor-recipient-rows">';
		$index = 0;
		foreach ( $rows as $row ) {
			$this->render_recipient_row( (string) $index, $row, $severities );
			++$index;
		}
		echo '</tbody></table>';
		echo '<template id="bee-monitor-recipient-template">';
		$this->render_recipient_row( '__INDEX__', Settings::default_row( '', 'high' ), $severities );
		echo '</template>';
		echo '<p><button type="button" class="button" id="bee-monitor-add-recipient">' . esc_html__( 'Add recipient', 'bee-monitor' ) . '</button></p>';
	}

	/**
	 * One recipient row.
	 *
	 * @param string $index      Row index.
	 * @param array  $row        Row.
	 * @param array  $severities Severity choices.
	 */
	private function render_recipient_row( $index, array $row, array $severities ) {
		$base = 'bee_monitor[recipient_rows][' . $index . ']';
		$id   = 'bee-monitor-r-' . $index;
		echo '<tr class="bee-monitor-recipient">';
		printf( '<td><label class="screen-reader-text" for="%1$s-email">%2$s</label><input type="email" class="regular-text" id="%1$s-email" name="%3$s[email]" value="%4$s"></td>', esc_attr( $id ), esc_html__( 'Email', 'bee-monitor' ), esc_attr( $base ), esc_attr( (string) $row['email'] ) );
		printf( '<td><label class="screen-reader-text" for="%1$s-min">%2$s</label><select id="%1$s-min" name="%3$s[min_severity]">', esc_attr( $id ), esc_html__( 'Send immediately', 'bee-monitor' ), esc_attr( $base ) );
		foreach ( $severities as $key => $label ) {
			printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $key ), selected( $row['min_severity'], $key, false ), esc_html( $label ) );
		}
		echo '</select></td>';
		printf( '<td><label><input type="checkbox" name="%1$s[digest]" value="1" %2$s> %3$s</label></td>', esc_attr( $base ), checked( ! empty( $row['digest'] ), true, false ), esc_html__( 'Include', 'bee-monitor' ) );
		echo '<td><fieldset><legend class="screen-reader-text">' . esc_html__( 'Categories', 'bee-monitor' ) . '</legend>';
		foreach ( Findings::CATEGORIES as $cat ) {
			printf( '<label class="bee-monitor-cat"><input type="checkbox" name="%1$s[categories][]" value="%2$s" %3$s> %4$s</label>', esc_attr( $base ), esc_attr( $cat ), checked( in_array( $cat, (array) $row['categories'], true ), true, false ), esc_html( Findings::category_label( $cat ) ) );
		}
		echo '</fieldset></td>';
		echo '<td><button type="button" class="button-link bee-monitor-remove-recipient">' . esc_html__( 'Remove', 'bee-monitor' ) . '</button></td>';
		echo '</tr>';
	}

	/**
	 * Settings page.
	 */
	public function page_settings() {
		$this->header( __( 'Bee Monitor Settings', 'bee-monitor' ) );
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" novalidate>';
		echo '<input type="hidden" name="action" value="bee_monitor_save_settings">';
		wp_nonce_field( 'bee_monitor_save_settings' );
		do_settings_sections( 'bee-monitor-settings' );
		submit_button( __( 'Save Bee Monitor settings', 'bee-monitor' ) );
		echo '</form></div>';
	}

	/**
	 * Save settings. Uses a nonce-verified admin-post handler so the same screen
	 * works in Network Admin, where options.php is not available.
	 */
	public function handle_settings() {
		$this->guard( 'bee_monitor_save_settings' );
		$raw    = isset( $_POST['bee_monitor'] ) && is_array( $_POST['bee_monitor'] ) ? wp_unslash( $_POST['bee_monitor'] ) : array(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.NonceVerification.Missing -- nonce verified in guard(); sanitized in Settings::sanitize().
		$old    = Settings::get();
		$result = Settings::sanitize( $raw );
		$new    = $result['settings'];

		$changed = array();
		foreach ( array( 'enabled', 'exclusions', 'recipient_rows', 'ignore_rules', 'viewer_roles', 'from_email', 'extra_extensions', 'auto_accept_updates', 'core_checksums', 'heartbeat_url' ) as $key ) {
			if ( wp_json_encode( isset( $old[ $key ] ) ? $old[ $key ] : '' ) !== wp_json_encode( $new[ $key ] ) ) {
				$changed[] = $key;
			}
		}
		Settings::save( $new );
		Activity::log( 'bm_settings', 'Bee Monitor', $changed ? 'changed: ' . implode( ', ', $changed ) : '' );
		Storage::remember_urls();
		Plugin::schedule( true );

		if ( $changed ) {
			$user = wp_get_current_user();
			Findings::record(
				array(
					'rule'        => 'settings_changed',
					'severity'    => array_intersect( $changed, array( 'enabled', 'exclusions', 'recipient_rows', 'ignore_rules' ) ) ? Findings::MEDIUM : Findings::LOW,
					'confidence'  => 'confirmed',
					'basis'       => 'monitor',
					'change_type' => 'changed',
					'subject'     => __( 'Bee Monitor settings', 'bee-monitor' ),
					/* translators: 1: username, 2: changed settings. */
					'reason'      => sprintf( __( '%1$s changed: %2$s. Changes to exclusions, recipients, or the enabled state can be used to blind monitoring.', 'bee-monitor' ), $user->user_login, implode( ', ', $changed ) ),
					'evidence'    => array(
						'changed'    => $changed,
						'enabled'    => (int) $new['enabled'],
						'exclusions' => Settings::exclusions(),
					),
					'key'         => md5( wp_json_encode( $new ) ),
				)
			);
		}

		foreach ( $result['errors'] as $error ) {
			$this->flash( 'error', $error );
		}
		foreach ( $result['warnings'] as $warning ) {
			$this->flash( 'warning', $warning );
		}
		$this->flash( 'success', __( 'Bee Monitor settings saved.', 'bee-monitor' ) );
		wp_safe_redirect( self::page_url( 'bee-monitor-settings' ) );
		exit;
	}

	// Findings.

	/**
	 * Findings page (list or detail).
	 */
	public function page_findings() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only view filters.
		if ( isset( $_GET['finding'] ) ) {
			$this->page_finding( absint( $_GET['finding'] ) );
			return;
		}
		$status  = isset( $_GET['status'] ) ? sanitize_key( wp_unslash( $_GET['status'] ) ) : 'open';
		$min_sev = isset( $_GET['min_severity'] ) ? absint( $_GET['min_severity'] ) : Findings::LOW;
		$paged   = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		$cat     = isset( $_GET['category'] ) ? sanitize_key( wp_unslash( $_GET['category'] ) ) : '';
		$search  = isset( $_GET['s'] ) ? substr( sanitize_text_field( wp_unslash( $_GET['s'] ) ), 0, 100 ) : '';
		// phpcs:enable
		if ( ! in_array( $cat, Findings::CATEGORIES, true ) ) {
			$cat = '';
		}
		if ( ! in_array( $status, array( 'open', 'expected', 'resolved', 'auto', 'ignored', 'all' ), true ) ) {
			$status = 'open';
		}
		$min_sev = min( Findings::CRITICAL, $min_sev );

		$this->header( __( 'Bee Monitor', 'bee-monitor' ), self::view_capability() );
		$manage = self::can_manage();
		$this->summary_cards();

		echo '<h2 class="screen-reader-text">' . esc_html__( 'Filter findings', 'bee-monitor' ) . '</h2><ul class="subsubsub">';
		$tabs = array(
			'open'     => Findings::term( 'status', 'open' ),
			'expected' => Findings::term( 'status', 'expected' ),
			'resolved' => Findings::term( 'status', 'resolved' ),
			'auto'     => Findings::term( 'status', 'auto' ),
			'ignored'  => Findings::term( 'status', 'ignored' ),
			'all'      => __( 'All', 'bee-monitor' ),
		);
		$last = array_key_last( $tabs );
		foreach ( $tabs as $key => $label ) {
			printf(
				'<li><a href="%1$s" class="%2$s" aria-current="%3$s">%4$s</a>%5$s</li>',
				esc_url(
					self::page_url(
						'bee-monitor',
						array(
							'status'       => $key,
							'min_severity' => 'auto' === $key ? 0 : $min_sev,
						)
					)
				),
				esc_attr( $key === $status ? 'current' : '' ),
				esc_attr( $key === $status ? 'page' : 'false' ),
				esc_html( $label ),
				esc_html( $key === $last ? '' : ' |' )
			);
		}
		echo '</ul>';

		echo '<form method="get" class="bee-monitor-filter"><input type="hidden" name="page" value="bee-monitor"><input type="hidden" name="status" value="' . esc_attr( $status ) . '">';
		echo '<label for="bee-monitor-min-sev">' . esc_html__( 'Minimum severity', 'bee-monitor' ) . '</label> <select id="bee-monitor-min-sev" name="min_severity">';
		for ( $sev = Findings::INFO; $sev <= Findings::CRITICAL; $sev++ ) {
			printf( '<option value="%1$d" %2$s>%3$s</option>', (int) $sev, selected( $min_sev, $sev, false ), esc_html( Findings::severity_label( $sev ) ) );
		}
		echo '</select> ';
		echo '<label for="bee-monitor-cat">' . esc_html__( 'Category', 'bee-monitor' ) . '</label> <select id="bee-monitor-cat" name="category"><option value="">' . esc_html__( 'All categories', 'bee-monitor' ) . '</option>';
		foreach ( Findings::CATEGORIES as $key ) {
			printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $key ), selected( $cat, $key, false ), esc_html( Findings::category_label( $key ) ) );
		}
		echo '</select> <label for="bee-monitor-search">' . esc_html__( 'Path or subject contains', 'bee-monitor' ) . '</label> <input type="search" id="bee-monitor-search" name="s" value="' . esc_attr( $search ) . '"> ';
		submit_button( __( 'Filter', 'bee-monitor' ), 'secondary', '', false );
		if ( '' !== $cat || '' !== $search || Findings::LOW !== $min_sev ) {
			echo ' <a class="button-link" href="' . esc_url( self::page_url( 'bee-monitor', array( 'status' => $status ) ) ) . '">' . esc_html__( 'Clear filters', 'bee-monitor' ) . '</a>';
		}
		echo '</form>';

		$filtered = '' !== $cat || '' !== $search;
		$result   = Findings::query(
			array(
				'status'       => $status,
				'min_severity' => $min_sev,
				'per_page'     => $filtered ? 5000 : self::PER_PAGE,
				'page'         => $filtered ? 1 : $paged,
			)
		);
		if ( $filtered ) {
			$matches = Findings::filter( $result['items'], $cat, $search );
			$result  = array(
				'items' => array_slice( $matches, ( $paged - 1 ) * self::PER_PAGE, self::PER_PAGE ),
				'total' => count( $matches ),
			);
		}

		if ( $manage ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
			echo '<input type="hidden" name="action" value="bee_monitor_findings">';
			wp_nonce_field( 'bee_monitor_findings' );
			$this->bulk_controls( 'top' );
		}
		echo '<table class="wp-list-table widefat fixed striped bee-monitor-table"><caption class="screen-reader-text">' . esc_html__( 'Findings', 'bee-monitor' ) . '</caption><thead><tr>';
		if ( $manage ) {
			echo '<td class="manage-column column-cb check-column"><label class="screen-reader-text" for="bee-monitor-select-all">' . esc_html__( 'Select all', 'bee-monitor' ) . '</label><input type="checkbox" id="bee-monitor-select-all" class="bee-monitor-select-all"></td>';
		}
		foreach ( array( __( 'Severity', 'bee-monitor' ), __( 'Finding', 'bee-monitor' ), __( 'Affected', 'bee-monitor' ), __( 'Confidence', 'bee-monitor' ), __( 'Last seen', 'bee-monitor' ), __( 'Status', 'bee-monitor' ) ) as $col ) {
			echo '<th scope="col">' . esc_html( $col ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		if ( empty( $result['items'] ) ) {
			$empty = ( 'open' === $status && ! $filtered && Findings::LOW >= $min_sev )
				? __( 'No open findings. New findings appear here after each scan.', 'bee-monitor' )
				: __( 'No findings match these filters.', 'bee-monitor' );
			echo '<tr><td class="bee-monitor-empty" colspan="' . esc_attr( $manage ? '7' : '6' ) . '">';
			Icons::render(
				'open' === $status && ! $filtered ? 'shield-check' : 'search',
				array(
					'size'  => 32,
					'class' => 'bee-monitor-empty-icon',
				)
			);
			echo '<span>' . esc_html( $empty ) . '</span></td></tr>';
		}
		foreach ( $result['items'] as $item ) {
			$url = self::page_url( 'bee-monitor', array( 'finding' => $item['id'] ) );
			echo '<tr>';
			if ( $manage ) {
				printf( '<th scope="row" class="check-column"><label class="screen-reader-text" for="bm-f-%1$d">%2$s</label><input type="checkbox" id="bm-f-%1$d" name="ids[]" value="%1$d"></th>', (int) $item['id'], esc_html__( 'Select finding', 'bee-monitor' ) );
			}
			echo '<td>';
			$this->print_badge( $item['severity'] );
			echo '</td>';
			$category = Findings::category( $item['rule'] );
			printf( '<td><a href="%1$s"><strong>%2$s</strong></a><br><span class="description bee-monitor-meta">', esc_url( $url ), esc_html( Findings::title( $item['rule'] ) ) );
			Icons::render( self::category_icon( $category ), array( 'size' => 14 ) );
			printf( '%1$s · %2$s · %3$s</span></td>', esc_html( Findings::category_label( $category ) ), esc_html( Findings::term( 'basis', $item['basis'] ) ), esc_html( Findings::term( 'change', $item['change_type'] ) ) );
			printf( '<td><code class="bee-monitor-path">%s</code></td>', esc_html( $item['subject'] ) );
			printf( '<td>%s</td>', esc_html( Findings::term( 'confidence', $item['confidence'] ) ) );
			echo '<td>' . esc_html( Notifier::local_time( $item['last_seen'] ) );
			if ( $item['occurrences'] > 1 ) {
				/* translators: %d: count. */
				echo '<br><span class="description">' . esc_html( sprintf( __( 'seen %d times', 'bee-monitor' ), (int) $item['occurrences'] ) ) . '</span>';
			}
			echo '</td>';
			printf( '<td>%s</td>', esc_html( Findings::term( 'status', $item['status'] ) ) );
			echo '</tr>';
		}
		echo '</tbody></table>';
		if ( $manage ) {
			$this->bulk_controls( 'bottom' );
			echo '</form>';
		}

		$pages = (int) ceil( $result['total'] / self::PER_PAGE );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo wp_kses_post(
				paginate_links(
					array(
						'base'    => add_query_arg(
							'paged',
							'%#%',
							self::page_url(
								'bee-monitor',
								array(
									'status'       => $status,
									'min_severity' => $min_sev,
									'category'     => $cat,
									's'            => $search,
								)
							)
						),
						'format'  => '',
						'current' => $paged,
						'total'   => $pages,
					)
				)
			);
			echo '</div></div>';
		}
		echo '</div>';
	}

	/**
	 * Bulk action controls.
	 *
	 * @param string $which top|bottom.
	 */
	private function bulk_controls( $which ) {
		$id = 'bee-monitor-bulk-' . $which;
		echo '<div class="tablenav ' . esc_attr( $which ) . '"><div class="alignleft actions bulkactions">';
		echo '<label for="' . esc_attr( $id ) . '" class="screen-reader-text">' . esc_html__( 'Bulk action', 'bee-monitor' ) . '</label>';
		echo '<select name="bulk_' . esc_attr( $which ) . '" id="' . esc_attr( $id ) . '">';
		echo '<option value="">' . esc_html__( 'Bulk actions', 'bee-monitor' ) . '</option>';
		echo '<option value="expected">' . esc_html__( 'Mark expected (accept change)', 'bee-monitor' ) . '</option>';
		echo '<option value="resolved">' . esc_html__( 'Mark resolved (I fixed it)', 'bee-monitor' ) . '</option>';
		echo '<option value="open">' . esc_html__( 'Reopen', 'bee-monitor' ) . '</option>';
		echo '</select> ';
		submit_button( __( 'Apply', 'bee-monitor' ), 'action', 'apply_' . $which, false );
		echo '</div><br class="clear"></div>';
	}

	/**
	 * Detail view.
	 *
	 * @param int $id Finding ID.
	 */
	private function page_finding( $id ) {
		$item = Findings::get( $id );
		$fix  = isset( $_GET['fix'] ) ? sanitize_key( wp_unslash( $_GET['fix'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only confirmation view; the action itself is nonce-checked.
		if ( $item && in_array( $fix, array( 'repair', 'quarantine' ), true ) && self::can_manage() ) {
			$this->fix_confirm( $item, $fix );
			return;
		}
		$this->header( __( 'Bee Monitor Finding', 'bee-monitor' ), self::view_capability() );
		echo '<p><a href="' . esc_url( self::page_url( 'bee-monitor' ) ) . '">&larr; ' . esc_html__( 'Back to findings', 'bee-monitor' ) . '</a></p>';
		if ( ! $item ) {
			echo '<p>' . esc_html__( 'Finding not found.', 'bee-monitor' ) . '</p></div>';
			return;
		}
		echo '<h2>';
		$this->print_badge( $item['severity'] );
		echo ' ' . esc_html( Findings::title( $item['rule'] ) ) . '</h2>';
		echo '<table class="widefat striped bee-monitor-detail"><tbody>';
		$rows = array(
			__( 'Affected', 'bee-monitor' )     => '<code class="bee-monitor-path">' . esc_html( $item['subject'] ) . '</code>',
			__( 'Change', 'bee-monitor' )       => esc_html( Findings::term( 'change', $item['change_type'] ) ),
			__( 'Basis', 'bee-monitor' )        => esc_html( Findings::term( 'basis', $item['basis'] ) ) . ( 'heuristic' === $item['basis'] ? ' — ' . esc_html__( 'an indicator for review, not proof of malware', 'bee-monitor' ) : '' ),
			__( 'Confidence', 'bee-monitor' )   => esc_html( Findings::term( 'confidence', $item['confidence'] ) ),
			__( 'Verification', 'bee-monitor' ) => ! empty( $item['evidence']['verification'] ) ? esc_html( Findings::term( 'verification', $item['evidence']['verification'] ) ) : '—',
			__( 'Why flagged', 'bee-monitor' )  => esc_html( $item['reason'] ),
			__( 'Next steps', 'bee-monitor' )   => esc_html( Findings::next_steps( $item['rule'] ) ),
			__( 'First seen', 'bee-monitor' )   => esc_html( Notifier::local_time( $item['first_seen'] ) ),
			__( 'Last seen', 'bee-monitor' )    => esc_html( Notifier::local_time( $item['last_seen'] ) ) . ' (' . esc_html( sprintf( /* translators: %d: count. */ __( 'seen %d times', 'bee-monitor' ), (int) $item['occurrences'] ) ) . ')',
			__( 'Emailed', 'bee-monitor' )      => $item['notified_at'] ? esc_html( Notifier::local_time( $item['notified_at'] ) ) : esc_html__( 'Not yet', 'bee-monitor' ),
			__( 'Status', 'bee-monitor' )       => esc_html( Findings::term( 'status', $item['status'] ) ) . ( $item['resolution_note'] ? ' — ' . esc_html( $item['resolution_note'] ) : '' ),
		);
		foreach ( $rows as $label => $html ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . wp_kses( $html, self::allowed_html() ) . '</td></tr>';
		}
		echo '<tr><th scope="row">' . esc_html__( 'Evidence (redacted)', 'bee-monitor' ) . '</th><td>';
		$this->render_evidence( $item['evidence'] );
		echo '</td></tr></tbody></table>';
		$this->investigation( $item );
		$this->fix_options( $item );

		if ( ! self::can_manage() ) {
			echo '</div>';
			return;
		}
		echo '<h3>' . esc_html__( 'Update this finding', 'bee-monitor' ) . '</h3>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="bee-monitor-actions">';
		echo '<input type="hidden" name="action" value="bee_monitor_findings"><input type="hidden" name="ids[]" value="' . (int) $item['id'] . '"><input type="hidden" name="return" value="detail">';
		wp_nonce_field( 'bee_monitor_findings' );
		echo '<p><label for="bee-monitor-note">' . esc_html__( 'Note (optional)', 'bee-monitor' ) . '</label><br><input type="text" class="large-text" id="bee-monitor-note" name="note" maxlength="500"></p><p>';
		if ( Findings::is_file_rule( $item['rule'] ) ) {
			echo '<span class="description">' . esc_html__( 'Marking a file change as expected updates the baseline with the file as it is now, only if it still matches the hash in this finding.', 'bee-monitor' ) . '</span><br>';
		}
		self::button(
			__( 'Mark expected', 'bee-monitor' ),
			'check',
			array(
				'name'    => 'single_expected',
				'primary' => true,
			)
		);
		echo ' ';
		self::button( __( 'Mark resolved', 'bee-monitor' ), 'check-check', array( 'name' => 'single_resolved' ) );
		echo ' ';
		self::button( __( 'Reopen', 'bee-monitor' ), 'rotate-ccw', array( 'name' => 'single_open' ) );
		if ( ! empty( $item['evidence']['path'] ) ) {
			echo ' ';
			self::button( __( 'Ignore similar findings in this folder', 'bee-monitor' ), 'eye-off', array( 'name' => 'single_ignore' ) );
			/* translators: %s: ignore rule. */
			echo '<br><span class="description">' . esc_html( sprintf( __( 'Adds the ignore rule "%s". Future findings of this type in this folder are recorded as Ignored and not emailed.', 'bee-monitor' ), self::ignore_rule_for( $item ) ) ) . '</span>';
		}
		echo '</p></form></div>';
	}

	/**
	 * Render evidence recursively, escaped.
	 *
	 * @param mixed $evidence Evidence.
	 */
	private function render_evidence( $evidence ) {
		if ( ! is_array( $evidence ) || empty( $evidence ) ) {
			echo '<em>' . esc_html__( 'None', 'bee-monitor' ) . '</em>';
			return;
		}
		echo '<dl class="bee-monitor-evidence">';
		foreach ( $evidence as $key => $value ) {
			echo '<dt>' . esc_html( (string) $key ) . '</dt><dd>';
			if ( 'indicators' === $key && is_array( $value ) ) {
				echo '<ul>';
				foreach ( $value as $ind ) {
					$line = ! empty( $ind['line'] ) ? sprintf( /* translators: %d: line number. */ __( 'line %d', 'bee-monitor' ), (int) $ind['line'] ) : '';
					echo '<li>' . esc_html( isset( $ind['label'] ) ? $ind['label'] : '' ) . ( $line ? ' <span class="description">(' . esc_html( $line ) . ')</span>' : '' );
					if ( ! empty( $ind['text'] ) ) {
						echo '<br><code>' . esc_html( $ind['text'] ) . '</code>';
					}
					echo '</li>';
				}
				echo '</ul>';
			} elseif ( is_array( $value ) ) {
				echo '<code>' . esc_html( wp_json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) ) . '</code>';
			} else {
				echo '<code>' . esc_html( (string) $value ) . '</code>';
			}
			echo '</dd>';
		}
		echo '</dl>';
	}

	/**
	 * Ignore rule covering a finding's rule in its folder.
	 *
	 * @param array $item Finding.
	 * @return string
	 */
	private static function ignore_rule_for( array $item ) {
		$dir = dirname( (string) $item['evidence']['path'] );
		return $item['rule'] . ' ' . ( '.' === $dir ? '' : $dir . '/' ) . '*';
	}

	/**
	 * Add an ignore rule for a finding and mark it ignored.
	 *
	 * @param int $id Finding ID.
	 */
	private function ignore_similar( $id ) {
		$item = Findings::get( $id );
		if ( ! $item || empty( $item['evidence']['path'] ) ) {
			return;
		}
		$rule     = self::ignore_rule_for( $item );
		$settings = Settings::get();
		$lines    = array_filter( array_map( 'trim', explode( "\n", (string) $settings['ignore_rules'] ) ) );
		if ( ! in_array( $rule, $lines, true ) ) {
			$lines[]                  = $rule;
			$settings['ignore_rules'] = implode( "\n", $lines );
			Settings::save( $settings );
			Findings::record(
				array(
					'rule'        => 'settings_changed',
					'severity'    => in_array( $item['rule'], Settings::RISKY_IGNORE, true ) ? Findings::MEDIUM : Findings::LOW,
					'confidence'  => 'confirmed',
					'basis'       => 'monitor',
					'change_type' => 'changed',
					'subject'     => __( 'Bee Monitor settings', 'bee-monitor' ),
					/* translators: 1: username, 2: ignore rule. */
					'reason'      => sprintf( __( '%1$s added the ignore rule "%2$s".', 'bee-monitor' ), wp_get_current_user()->user_login, $rule ),
					'evidence'    => array( 'ignore_rule' => $rule ),
					'key'         => md5( $rule ),
				)
			);
		}
		Findings::set_status( array( $id ), Findings::STATUS_IGNORED, $rule, get_current_user_id() );
		/* translators: %s: ignore rule. */
		$this->flash( 'success', sprintf( __( 'Ignore rule "%s" added.', 'bee-monitor' ), $rule ) );
	}

	/**
	 * Handle bulk or single finding actions.
	 */
	public function handle_findings() {
		$this->guard( 'bee_monitor_findings' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in guard().
		$ids    = isset( $_POST['ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['ids'] ) ) : array();
		$note   = isset( $_POST['note'] ) ? sanitize_text_field( wp_unslash( $_POST['note'] ) ) : '';
		$detail = isset( $_POST['return'] ) && 'detail' === sanitize_key( wp_unslash( $_POST['return'] ) );
		$action = '';
		if ( isset( $_POST['single_ignore'] ) && 1 === count( $ids ) ) {
			$this->ignore_similar( $ids[0] );
			wp_safe_redirect( self::page_url( 'bee-monitor', array( 'finding' => $ids[0] ) ) );
			exit;
		}
		foreach ( array( 'expected', 'resolved', 'open' ) as $candidate ) {
			if ( isset( $_POST[ 'single_' . $candidate ] ) ) {
				$action = $candidate;
			}
		}
		if ( '' === $action ) {
			$which  = isset( $_POST['apply_bottom'] ) ? 'bulk_bottom' : 'bulk_top';
			$action = isset( $_POST[ $which ] ) ? sanitize_key( wp_unslash( $_POST[ $which ] ) ) : '';
		}
		// phpcs:enable
		$ids = array_slice( array_filter( $ids ), 0, 500 );

		if ( empty( $ids ) || ! in_array( $action, array( 'expected', 'resolved', 'open' ), true ) ) {
			$this->flash( 'warning', __( 'Select at least one finding and an action.', 'bee-monitor' ) );
		} else {
			$apply   = array();
			$changed = 0;
			foreach ( $ids as $id ) {
				$item = Findings::get( $id );
				if ( ! $item ) {
					continue;
				}
				if ( 'expected' === $action ) {
					$res = Scanner::accept_file( $item );
					if ( 'changed' === $res ) {
						++$changed;
						continue;
					}
				}
				$apply[] = $id;
			}
			$count = Findings::set_status( $apply, $action, $note, get_current_user_id() );
			Activity::log( 'finding_status', implode( ',', array_slice( $apply, 0, 20 ) ), $action . ( count( $apply ) > 20 ? ' (+' . ( count( $apply ) - 20 ) . ')' : '' ) );
			/* translators: 1: number of findings, 2: status. */
			$this->flash( 'success', sprintf( __( '%1$d findings marked %2$s.', 'bee-monitor' ), $count, Findings::term( 'status', $action ) ) );
			if ( $changed ) {
				/* translators: %d: number of findings. */
				$this->flash( 'warning', sprintf( __( '%d findings were not marked expected because the file changed again after it was flagged. Run a new scan and review the latest version.', 'bee-monitor' ), $changed ) );
			}
			Storage::log(
				'info',
				sprintf( 'Bee Monitor findings marked %s', $action ),
				array(
					'count' => $count,
					'user'  => get_current_user_id(),
				)
			);
		}
		$url = ( $detail && 1 === count( $ids ) ) ? self::page_url( 'bee-monitor', array( 'finding' => $ids[0] ) ) : wp_get_referer();
		wp_safe_redirect( $url ? $url : self::page_url( 'bee-monitor' ) );
		exit;
	}

	// Baseline.

	/**
	 * Baseline page.
	 */
	public function page_baseline() {
		$this->header( __( 'Bee Monitor Baseline', 'bee-monitor' ) );
		$meta = Storage::get( 'baseline_meta', array() );
		$meta = is_array( $meta ) ? $meta : array();

		echo '<p>' . esc_html__( 'The baseline is the list of monitored files and their SHA-256 hashes that Bee Monitor treats as known-good. Each record is signed, so edits made directly in the database are detected.', 'bee-monitor' ) . '</p>';
		echo '<table class="widefat striped bee-monitor-detail"><tbody>';
		$status = isset( $meta['status'] ) ? $meta['status'] : __( 'not created', 'bee-monitor' );
		$rows   = array(
			__( 'Status', 'bee-monitor' )            => $status,
			__( 'Created', 'bee-monitor' )           => ! empty( $meta['created'] ) ? wp_date( 'Y-m-d H:i', (int) $meta['created'] ) : '—',
			__( 'WordPress version', 'bee-monitor' ) => isset( $meta['wp_version'] ) ? $meta['wp_version'] : '—',
			__( 'Files in baseline', 'bee-monitor' ) => (string) Storage::baseline_count(),
			__( 'Last full re-hash', 'bee-monitor' ) => ! empty( $meta['last_full_hash'] ) ? wp_date( 'Y-m-d H:i', (int) $meta['last_full_hash'] ) : '—',
			__( 'Signing key', 'bee-monitor' )       => defined( 'BEE_MONITOR_HMAC_KEY' ) ? __( 'BEE_MONITOR_HMAC_KEY constant', 'bee-monitor' ) : __( 'derived from WordPress salts', 'bee-monitor' ),
		);
		foreach ( $rows as $label => $value ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . esc_html( $value ) . '</td></tr>';
		}
		$areas = array();
		foreach ( Storage::baseline_area_counts() as $area => $n ) {
			$areas[] = $area . ': ' . $n;
		}
		echo '<tr><th scope="row">' . esc_html__( 'Files by area', 'bee-monitor' ) . '</th><td>' . esc_html( $areas ? implode( ', ', $areas ) : '—' ) . '</td></tr>';
		$exclusions = Settings::exclusions();
		$risky      = Settings::risky_exclusions( $exclusions );
		echo '<tr><th scope="row">' . esc_html__( 'Active exclusions', 'bee-monitor' ) . '</th><td>';
		if ( $exclusions ) {
			echo '<ul class="bee-monitor-list">';
			foreach ( $exclusions as $pattern ) {
				echo '<li><code>' . esc_html( $pattern ) . '</code>' . ( in_array( $pattern, $risky, true ) ? ' <strong class="bee-monitor-warning">' . esc_html__( 'hides a high-risk location', 'bee-monitor' ) . '</strong>' : '' ) . '</li>';
			}
			echo '</ul>';
		} else {
			esc_html_e( 'None', 'bee-monitor' );
		}
		echo '<p><a href="' . esc_url( self::page_url( 'bee-monitor-settings' ) ) . '">' . esc_html__( 'Edit exclusions', 'bee-monitor' ) . '</a></p></td></tr>';
		echo '</tbody></table>';

		echo '<h2>';
		Icons::render( 'check-check' );
		echo esc_html__( 'Accept all open file changes', 'bee-monitor' ) . '</h2>';
		echo '<p>' . esc_html__( 'Use after a deployment you performed. Every open file finding is marked expected and its current file is written to the baseline (only if unchanged since it was flagged). Heuristic findings are accepted too, so review them first.', 'bee-monitor' ) . '</p>';
		$this->baseline_form( 'accept_all', __( 'I reviewed the open file findings and the changes are legitimate.', 'bee-monitor' ), __( 'Accept all open file changes', 'bee-monitor' ) );

		echo '<h2>';
		Icons::render( 'refresh-cw' );
		echo esc_html__( 'Rebuild baseline', 'bee-monitor' ) . '</h2>';
		echo '<p>' . esc_html__( 'Replaces the baseline with the files as they are now. Anything malicious currently on disk becomes part of the new baseline, so only rebuild after verifying the site is clean. Pre-existing indicators are still reported.', 'bee-monitor' ) . '</p>';
		$this->baseline_form( 'rebuild', __( 'I verified the site is clean and want to replace the baseline.', 'bee-monitor' ), __( 'Rebuild baseline', 'bee-monitor' ) );
		echo '</div>';
	}

	/**
	 * Confirmation form for baseline actions.
	 *
	 * @param string $op      Operation.
	 * @param string $confirm Confirmation text.
	 * @param string $button  Button label.
	 */
	private function baseline_form( $op, $confirm, $button ) {
		$id = 'bee-monitor-confirm-' . $op;
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="bee_monitor_baseline"><input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
		wp_nonce_field( 'bee_monitor_baseline_' . $op );
		echo '<p><label for="' . esc_attr( $id ) . '"><input type="checkbox" id="' . esc_attr( $id ) . '" name="confirm" value="1" required> ' . esc_html( $confirm ) . '</label></p>';
		submit_button( $button, 'rebuild' === $op ? 'delete' : 'secondary', 'submit', false, array( 'data-bee-monitor-confirm' => '1' ) );
		echo '</form>';
	}

	/**
	 * Baseline actions.
	 */
	public function handle_baseline() {
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified below.
		if ( ! in_array( $op, array( 'rebuild', 'accept_all' ), true ) ) {
			wp_die( esc_html__( 'Unknown Bee Monitor action.', 'bee-monitor' ), '', array( 'response' => 400 ) );
		}
		$this->guard( 'bee_monitor_baseline_' . $op );
		if ( empty( $_POST['confirm'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
			$this->flash( 'error', __( 'Please tick the confirmation box.', 'bee-monitor' ) );
			wp_safe_redirect( self::page_url( 'bee-monitor-baseline' ) );
			exit;
		}

		if ( 'rebuild' === $op ) {
			Storage::delete( 'lock' );
			Storage::delete( 'scan_state' );
			( new Scanner() )->start( 'manual', true );
			Storage::log( 'warning', 'Bee Monitor baseline rebuild started', array( 'user' => get_current_user_id() ) );
			Activity::log( 'baseline', 'baseline', 'rebuild started' );
			$this->flash( 'success', __( 'Baseline rebuild started. Keep this page open to run it now, or let WP-Cron finish it in the background.', 'bee-monitor' ) );
			wp_safe_redirect(
				self::page_url(
					'bee-monitor-tools',
					array(
						'run'    => 1,
						'_bmrun' => wp_create_nonce( 'bee_monitor_run' ),
					)
				)
			);
			exit;
		}

		$accepted = 0;
		$changed  = 0;
		$result   = Findings::query(
			array(
				'status'       => Findings::STATUS_OPEN,
				'min_severity' => 0,
				'per_page'     => 500,
			)
		);
		$ids      = array();
		foreach ( $result['items'] as $item ) {
			if ( ! Findings::is_file_rule( $item['rule'] ) ) {
				continue;
			}
			if ( 'changed' === Scanner::accept_file( $item ) ) {
				++$changed;
				continue;
			}
			$ids[] = $item['id'];
		}
		$accepted = Findings::set_status( $ids, Findings::STATUS_EXPECTED, __( 'Accepted in bulk from the Baseline screen', 'bee-monitor' ), get_current_user_id() );
		Activity::log( 'baseline', 'baseline', 'accepted all open file changes' );
		Storage::log(
			'warning',
			'Bee Monitor accepted all open file changes',
			array(
				'count' => $accepted,
				'user'  => get_current_user_id(),
			)
		);
		/* translators: %d: number of findings. */
		$this->flash( 'success', sprintf( __( '%d file findings accepted into the baseline.', 'bee-monitor' ), $accepted ) );
		if ( $changed ) {
			/* translators: %d: number of findings. */
			$this->flash( 'warning', sprintf( __( '%d findings were skipped because the file changed again after it was flagged.', 'bee-monitor' ), $changed ) );
		}
		wp_safe_redirect( self::page_url( 'bee-monitor-baseline' ) );
		exit;
	}

	// Tools & status.

	/**
	 * Tools page.
	 */
	public function page_tools() {
		$autorun = isset( $_GET['run'], $_GET['_bmrun'] ) && wp_verify_nonce( sanitize_text_field( wp_unslash( $_GET['_bmrun'] ) ), 'bee_monitor_run' );
		$this->header( __( 'Bee Monitor Tools & Status', 'bee-monitor' ) );

		echo '<div class="bee-monitor-tools">';
		$running = Scanner::is_running();
		echo '<div class="bee-monitor-card"><h2>';
		Icons::render( 'scan-search' );
		echo esc_html__( 'Scan', 'bee-monitor' ) . '</h2>';
		echo '<p>' . esc_html__( 'Runs in short, time-limited steps. You can leave this page; WP-Cron finishes an unfinished scan. Cancelling keeps the current baseline.', 'bee-monitor' ) . '</p>';
		echo '<p class="bee-monitor-actions-row">';
		self::button(
			$running ? __( 'Resume scan', 'bee-monitor' ) : __( 'Run scan now', 'bee-monitor' ),
			'play',
			array(
				'type'    => 'button',
				'id'      => 'bee-monitor-run',
				'primary' => true,
				'data'    => array( 'autostart' => $autorun || $running ? '1' : '' ),
			)
		);
		self::button(
			__( 'Full integrity scan', 'bee-monitor' ),
			'refresh-cw',
			array(
				'type' => 'button',
				'id'   => 'bee-monitor-run-full',
			)
		);
		if ( Settings::value( 'remote_checks' ) ) {
			self::button(
				__( 'Scan and check public pages', 'bee-monitor' ),
				'globe',
				array(
					'type' => 'button',
					'id'   => 'bee-monitor-run-remote',
				)
			);
		}
		self::button(
			__( 'Cancel scan', 'bee-monitor' ),
			'square',
			array(
				'type'   => 'button',
				'id'     => 'bee-monitor-cancel',
				'hidden' => ! $running,
			)
		);
		echo '</p><p class="description">' . esc_html__( 'A full integrity scan re-hashes every monitored file and re-verifies core and plugin checksums now, instead of waiting for the daily full pass. It takes longer.', 'bee-monitor' ) . '</p>';
		echo '<div class="bee-monitor-scan-status" id="bee-monitor-scan-status" hidden><progress id="bee-monitor-progress-bar" max="100" aria-describedby="bee-monitor-progress"></progress>';
		echo '<p id="bee-monitor-progress" role="status" aria-live="polite"></p></div></div>';

		echo '<div class="bee-monitor-card"><h2>';
		Icons::render( 'download' );
		echo esc_html__( 'Export report', 'bee-monitor' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="bee_monitor_export">';
		wp_nonce_field( 'bee_monitor_export' );
		echo '<p><label for="bee-monitor-export-format">' . esc_html__( 'Format', 'bee-monitor' ) . '</label> <select id="bee-monitor-export-format" name="format"><option value="json">JSON</option><option value="csv">CSV</option></select> ';
		echo '<label for="bee-monitor-export-status">' . esc_html__( 'Findings', 'bee-monitor' ) . '</label> <select id="bee-monitor-export-status" name="status"><option value="open">' . esc_html__( 'Open', 'bee-monitor' ) . '</option><option value="all">' . esc_html__( 'All', 'bee-monitor' ) . '</option></select></p>';
		echo '<p><label><input type="checkbox" name="include_personal" value="1"> ' . esc_html__( 'Include personal data (usernames, user IDs, masked emails and networks)', 'bee-monitor' ) . '</label><br><label><input type="checkbox" name="include_site" value="1"> ' . esc_html__( 'Include site name and address', 'bee-monitor' ) . '</label></p>';
		echo '<p class="description">' . esc_html__( 'Secrets and file contents are never included. Evidence snippets are the redacted versions stored by Bee Monitor.', 'bee-monitor' ) . '</p>';
		self::button( __( 'Download report', 'bee-monitor' ), 'download' );
		echo '</form></div>';

		echo '<div class="bee-monitor-card"><h2>';
		Icons::render( 'mail' );
		echo esc_html__( 'Email delivery', 'bee-monitor' ) . '</h2>';
		/* translators: %s: recipients. */
		echo '<p>' . esc_html( sprintf( __( 'Alerts go to: %s', 'bee-monitor' ), implode( ', ', Settings::recipients() ) ) ) . '</p>';
		if ( count( Settings::recipients() ) > 1 ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="bee_monitor_email"><input type="hidden" name="op" value="test_one">';
			wp_nonce_field( 'bee_monitor_email' );
			echo '<p><label for="bee-monitor-test-one">' . esc_html__( 'Test one recipient', 'bee-monitor' ) . '</label> <select id="bee-monitor-test-one" name="recipient">';
			foreach ( Settings::recipients() as $email ) {
				printf( '<option value="%1$s">%2$s</option>', esc_attr( $email ), esc_html( $email ) );
			}
			echo '</select> ';
			self::button( __( 'Send test', 'bee-monitor' ), 'send' );
			echo '</p></form>';
		}
		$icon_for = array(
			'test'   => 'send',
			'sample' => 'mail',
		);
		foreach ( array(
			'test'   => __( 'Send test email', 'bee-monitor' ),
			'sample' => __( 'Send sample alert', 'bee-monitor' ),
		) as $op => $label ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="bee-monitor-inline">';
			echo '<input type="hidden" name="action" value="bee_monitor_email"><input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
			wp_nonce_field( 'bee_monitor_email' );
			self::button( $label, $icon_for[ $op ] );
			echo '</form> ';
		}
		echo '<p class="description">' . esc_html__( 'The sample alert uses the real alert format with a clearly labeled fake finding.', 'bee-monitor' ) . '</p></div>';
		echo '</div>';
		echo '<details class="bee-monitor-preview"><summary>' . esc_html__( 'Preview the HTML alert email', 'bee-monitor' ) . '</summary>';
		echo wp_kses( Notifier::preview_html(), Notifier::allowed_email_html() );
		echo '</details>';

		echo '<h2>';
		Icons::render( 'activity' );
		echo esc_html__( 'Status', 'bee-monitor' ) . '</h2><table class="widefat striped bee-monitor-detail"><tbody>';
		foreach ( $this->status_rows() as $label => $value ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . esc_html( $value ) . '</td></tr>';
		}
		echo '</tbody></table>';

		$this->quarantine_section();

		echo '<h2>';
		Icons::render( 'plug' );
		echo esc_html__( 'Email hooks', 'bee-monitor' ) . '</h2><p>' . esc_html__( 'Code hooked into WordPress email can change or suppress Bee Monitor alerts. SMTP plugins legitimately appear here.', 'bee-monitor' ) . '</p><ul class="bee-monitor-list">';
		$any = false;
		foreach ( array( 'pre_wp_mail', 'wp_mail', 'phpmailer_init' ) as $hook ) {
			foreach ( Paths::hook_files( $hook ) as $file ) {
				$any = true;
				echo '<li><code>' . esc_html( $hook ) . '</code> &rarr; <code>' . esc_html( Paths::display( $file ) ) . '</code>' . ( Paths::is_suspicious_source( $file ) ? ' <strong class="bee-monitor-warning">' . esc_html__( 'unusual location', 'bee-monitor' ) . '</strong>' : '' ) . '</li>';
			}
		}
		if ( ! $any ) {
			echo '<li>' . esc_html__( 'None registered.', 'bee-monitor' ) . '</li>';
		}
		echo '</ul>';

		echo '<h2>';
		Icons::render( 'file-text' );
		echo esc_html__( 'Recent Bee Monitor log', 'bee-monitor' ) . '</h2><table class="widefat striped"><thead><tr><th scope="col">' . esc_html__( 'Time', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Level', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Message', 'bee-monitor' ) . '</th></tr></thead><tbody>';
		foreach ( Storage::recent_log( 50 ) as $row ) {
			echo '<tr><td>' . esc_html( Notifier::local_time( $row['created_at'] ) ) . '</td><td>' . esc_html( $row['level'] ) . '</td><td>' . esc_html( $row['message'] );
			if ( $row['context'] ) {
				echo '<br><code class="bee-monitor-path">' . esc_html( $row['context'] ) . '</code>';
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/**
	 * Status rows for the tools page.
	 *
	 * @return array
	 */
	private function status_rows() {
		global $wp_version;
		$last  = Storage::get( 'last_scan', array() );
		$mail  = Storage::get( 'mail_status', array() );
		$beat  = Storage::get( 'heartbeat_status', array() );
		$state = Scanner::state();
		$next  = wp_next_scheduled( Plugin::CRON_SCAN );
		$dig   = wp_next_scheduled( Plugin::CRON_DIGEST );
		$rows  = array();

		$rows[ __( 'Monitoring', 'bee-monitor' ) ]          = Settings::value( 'enabled' ) ? __( 'Enabled', 'bee-monitor' ) : __( 'Disabled', 'bee-monitor' );
		$rows[ __( 'Current scan', 'bee-monitor' ) ]        = Scanner::is_running() ? sprintf( /* translators: 1: scan ID, 2: mode, 3: phase. */ __( '#%1$d (%2$s) in phase %3$s', 'bee-monitor' ), (int) $state['id'], $state['mode'], $state['phase'] ) : __( 'None', 'bee-monitor' );
		$rows[ __( 'Last completed scan', 'bee-monitor' ) ] = is_array( $last ) && ! empty( $last['finished'] )
			/* translators: 1: date, 2: mode, 3: files, 4: findings. */
			? sprintf( __( '%1$s (%2$s): %3$d files checked, %4$d new findings', 'bee-monitor' ), wp_date( 'Y-m-d H:i', (int) $last['finished'] ), $last['mode'], (int) $last['stats']['files'], (int) $last['stats']['findings'] )
			: __( 'Never', 'bee-monitor' );
		if ( is_array( $last ) && ! empty( $last['unreadable'] ) ) {
			$rows[ __( 'Unreadable paths (sample)', 'bee-monitor' ) ] = implode( ', ', array_slice( $last['unreadable'], 0, 10 ) );
		}
		if ( is_array( $last ) && ! empty( $last['errors'] ) ) {
			$rows[ __( 'Scan errors', 'bee-monitor' ) ] = implode( ' | ', $last['errors'] );
		}
		$rows[ __( 'Next scheduled scan', 'bee-monitor' ) ] = $next ? wp_date( 'Y-m-d H:i', $next ) : __( 'Not scheduled', 'bee-monitor' );
		$rows[ __( 'Next digest', 'bee-monitor' ) ]         = $dig ? wp_date( 'Y-m-d H:i', $dig ) : __( 'Off', 'bee-monitor' );
		$rows[ __( 'WP-Cron', 'bee-monitor' ) ]             = ( defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON ) ? __( 'Disabled in wp-config.php (a server cron job must call wp-cron.php)', 'bee-monitor' ) : __( 'Enabled (runs on site traffic)', 'bee-monitor' );
		$rows[ __( 'Core checksums', 'bee-monitor' ) ]      = is_array( $last ) && isset( $last['checksums'] ) ? ( $last['checksums'] ? __( 'Verified against api.wordpress.org', 'bee-monitor' ) : __( 'Unavailable in last scan', 'bee-monitor' ) ) : '—';
		$rows[ __( 'Last email', 'bee-monitor' ) ]          = is_array( $mail ) && ! empty( $mail['time'] ) ? sprintf( '%s — %s (%s)%s', wp_date( 'Y-m-d H:i', (int) $mail['time'] ), $mail['ok'] ? __( 'sent', 'bee-monitor' ) : __( 'FAILED', 'bee-monitor' ), $mail['kind'], $mail['error'] ? ': ' . $mail['error'] : '' ) : __( 'None yet', 'bee-monitor' );
		$rows[ __( 'Heartbeat', 'bee-monitor' ) ]           = '' === Settings::value( 'heartbeat_url' ) ? __( 'Not configured', 'bee-monitor' ) : ( is_array( $beat ) && ! empty( $beat['time'] ) ? sprintf( '%s — HTTP %d %s', wp_date( 'Y-m-d H:i', (int) $beat['time'] ), (int) $beat['code'], $beat['error'] ) : __( 'No ping yet', 'bee-monitor' ) );
		$rows[ __( 'Environment', 'bee-monitor' ) ]         = sprintf( 'WordPress %s, PHP %s, %s', $wp_version, PHP_VERSION, is_multisite() ? __( 'multisite (network-activated)', 'bee-monitor' ) : __( 'single site', 'bee-monitor' ) );
		$rows[ __( 'open_basedir', 'bee-monitor' ) ]        = ini_get( 'open_basedir' ) ? __( 'Set (some paths may be outside Bee Monitor\'s reach)', 'bee-monitor' ) : __( 'Not set', 'bee-monitor' );
		$roots = array();
		foreach ( Paths::roots( (bool) Settings::value( 'scan_parent_dir' ) ) as $root ) {
			$roots[] = ( $root['label'] ? $root['label'] : 'ABSPATH' ) . ( $root['recursive'] ? '' : ' ' . __( '(files only)', 'bee-monitor' ) );
		}
		$rows[ __( 'Scan roots', 'bee-monitor' ) ] = implode( ', ', $roots );
		return $rows;
	}

	/**
	 * Test email and sample alert.
	 */
	public function handle_email() {
		$this->guard( 'bee_monitor_email' );
		$op = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : 'test'; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
		if ( 'sample' === $op ) {
			$ok = Notifier::send_sample();
			$this->flash( $ok ? 'success' : 'error', $ok ? __( 'Sample Bee Monitor alert sent. Check your inbox and spam folder.', 'bee-monitor' ) : __( 'The sample alert could not be sent. See the status table for the error.', 'bee-monitor' ) );
		} elseif ( 'test_one' === $op ) {
			$to  = isset( $_POST['recipient'] ) ? sanitize_email( wp_unslash( $_POST['recipient'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
			$res = in_array( $to, Settings::recipients(), true ) ? Notifier::send_test( $to ) : array(
				'ok'    => false,
				'error' => __( 'That address is not a configured recipient.', 'bee-monitor' ),
			);
			/* translators: %s: error message. */
			$this->flash( $res['ok'] ? 'success' : 'error', $res['ok'] ? __( 'Bee Monitor test email sent. Check your inbox and spam folder.', 'bee-monitor' ) : sprintf( __( 'Bee Monitor test email failed: %s', 'bee-monitor' ), $res['error'] ) );
		} else {
			$res = Notifier::send_test();
			/* translators: %s: error message. */
			$this->flash( $res['ok'] ? 'success' : 'error', $res['ok'] ? __( 'Bee Monitor test email sent. Check your inbox and spam folder.', 'bee-monitor' ) : sprintf( __( 'Bee Monitor test email failed: %s', 'bee-monitor' ), $res['error'] ) );
		}
		wp_safe_redirect( self::page_url( 'bee-monitor-tools' ) );
		exit;
	}

	/**
	 * AJAX: run one scan step.
	 */
	public function ajax_scan_step() {
		check_ajax_referer( 'bee_monitor_scan', 'nonce' );
		if ( ! current_user_can( self::capability() ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'bee-monitor' ) ), 403 );
		}
		$scanner = new Scanner();
		if ( ! empty( $_POST['start'] ) && ! Scanner::is_running() ) {
			$scanner->start( 'manual', false, ! empty( $_POST['full'] ), ! empty( $_POST['remote'] ) );
		}
		wp_send_json_success( $scanner->run_step( 'manual' ) );
	}

	// Shared rendering.

	/**
	 * Page header.
	 *
	 * @param string $title Title.
	 * @param string $cap   Required capability (defaults to manage).
	 */
	private function header( $title, $cap = '' ) {
		if ( ! current_user_can( '' !== $cap ? $cap : self::capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to manage Bee Monitor.', 'bee-monitor' ), '', array( 'response' => 403 ) );
		}
		$page    = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : 'bee-monitor'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- navigation state only.
		$display = trim( preg_replace( '/^Bee Monitor\s*/', '', $title ) );
		echo '<div class="wrap bee-monitor"><header class="bee-monitor-masthead"><div class="bee-monitor-brandline">';
		Brand::render( Brand::badge( 44, '', true ) );
		echo '<div><p class="bee-monitor-eyebrow">' . esc_html__( 'Bee Monitor', 'bee-monitor' ) . '</p><h1 class="bee-monitor-title">' . esc_html( '' !== $display ? $display : __( 'Security dashboard', 'bee-monitor' ) ) . '</h1></div></div>';
		$links = array(
			'bee-monitor' => array( __( 'Dashboard', 'bee-monitor' ), 'shield-check' ),
		);
		if ( self::can_manage() ) {
			$links['bee-monitor-activity'] = array( __( 'Activity', 'bee-monitor' ), 'list' );
			$links['bee-monitor-tools']    = array( __( 'Tools & Status', 'bee-monitor' ), 'activity' );
			$links['bee-monitor-baseline'] = array( __( 'Baseline', 'bee-monitor' ), 'database' );
			$links['bee-monitor-settings'] = array( __( 'Settings', 'bee-monitor' ), 'settings' );
		}
		echo '<nav class="bee-monitor-nav" aria-label="' . esc_attr__( 'Bee Monitor sections', 'bee-monitor' ) . '"><ul>';
		foreach ( $links as $slug => $link ) {
			$current = $slug === $page;
			echo '<li><a href="' . esc_url( self::page_url( $slug ) ) . '"' . ( $current ? ' class="is-current" aria-current="page"' : '' ) . '>';
			Icons::render( $link[1] );
			echo '<span>' . esc_html( $link[0] ) . '</span></a></li>';
		}
		echo '</ul></nav></header><hr class="wp-header-end">';
	}

	/**
	 * Summary cards on the findings page.
	 */
	private function summary_cards() {
		$counts   = Findings::open_counts();
		$last     = Storage::get( 'last_scan', array() );
		$last     = is_array( $last ) ? $last : array();
		$meta     = Storage::get( 'baseline_meta', array() );
		$meta     = is_array( $meta ) ? $meta : array();
		$mail     = Storage::get( 'mail_status', array() );
		$mail     = is_array( $mail ) ? $mail : array();
		$problems = Notifier::health_problems();
		$urgent   = $counts[ Findings::CRITICAL ] + $counts[ Findings::HIGH ];
		$manage   = self::can_manage();
		$running  = Scanner::is_running();
		$progress = ( new Scanner() )->progress();
		$has_base = isset( $meta['status'] ) && 'valid' === $meta['status'];

		if ( $running ) {
			$state = array( 'is-running', 'scan-search', __( 'Scan in progress', 'bee-monitor' ), $progress['phase_label'] ? $progress['phase_label'] . '.' : __( 'Bee Monitor is checking your site.', 'bee-monitor' ) );
		} elseif ( ! $has_base ) {
			$state = array( 'is-new', 'shield', __( 'Set up monitoring', 'bee-monitor' ), __( 'Run the first scan to record how your site looks today. Later scans compare against this baseline.', 'bee-monitor' ) );
		} elseif ( $urgent ) {
			/* translators: 1: critical count, 2: high count. */
			$state = array( 'is-critical', 'shield-exclamation-point', __( 'Action needed', 'bee-monitor' ), sprintf( __( '%1$d critical and %2$d high-severity findings are open. Review them first.', 'bee-monitor' ), $counts[ Findings::CRITICAL ], $counts[ Findings::HIGH ] ) );
		} elseif ( $problems ) {
			$state = array( 'is-warning', 'triangle-exclamation-point', __( 'Monitoring needs attention', 'bee-monitor' ), implode( ' ', $problems ) );
		} else {
			$state = array( 'is-ok', 'shield-check', __( 'No high-severity findings', 'bee-monitor' ), __( 'Nothing urgent was found in the latest scan. Keep reviewing lower-severity findings and the activity log.', 'bee-monitor' ) );
		}

		echo '<div class="bee-monitor-overview">';
		echo '<section class="bee-monitor-status ' . esc_attr( $state[0] ) . '" aria-labelledby="bm-status-title"><div class="bee-monitor-hex" aria-hidden="true">';
		Icons::render( $state[1], array( 'size' => 26 ) );
		echo '</div><div class="bee-monitor-status-body"><p class="bee-monitor-kicker">' . esc_html__( 'Security status', 'bee-monitor' ) . '</p><h2 id="bm-status-title">' . esc_html( $state[2] ) . '</h2><p>' . esc_html( $state[3] ) . '</p>';
		if ( 'is-critical' === $state[0] ) {
			$url = self::page_url(
				'bee-monitor',
				array(
					'status'       => 'open',
					'min_severity' => Findings::HIGH,
				)
			);
			echo '<p><a class="button button-primary bee-monitor-btn" href="' . esc_url( $url ) . '">';
			Icons::render( 'search' );
			echo '<span>' . esc_html__( 'Review high-severity findings', 'bee-monitor' ) . '</span></a></p>';
		} elseif ( 'is-warning' === $state[0] && $manage ) {
			echo '<p><a class="button bee-monitor-btn" href="' . esc_url( self::page_url( 'bee-monitor-tools' ) ) . '">';
			Icons::render( 'activity' );
			echo '<span>' . esc_html__( 'Open Tools & Status', 'bee-monitor' ) . '</span></a></p>';
		}
		echo '</div></section>';

		echo '<section class="bee-monitor-panel bee-monitor-scan" aria-labelledby="bm-scan-title"><h2 id="bm-scan-title">';
		Icons::render( 'scan-search' );
		echo esc_html__( 'Scan', 'bee-monitor' ) . '</h2>';
		$next = wp_next_scheduled( Plugin::CRON_SCAN );
		$rows = array(
			/* translators: %s: time difference. */
			__( 'Last scan', 'bee-monitor' )      => ! empty( $last['finished'] ) ? sprintf( __( '%s ago', 'bee-monitor' ), human_time_diff( (int) $last['finished'] ) ) : __( 'Not yet', 'bee-monitor' ),
			/* translators: %s: time difference. */
			__( 'Next scheduled', 'bee-monitor' ) => $next ? ( $next > time() ? sprintf( __( 'in %s', 'bee-monitor' ), human_time_diff( time(), $next ) ) : __( 'Due now', 'bee-monitor' ) ) : __( 'Not scheduled', 'bee-monitor' ),
			__( 'Files checked', 'bee-monitor' )  => ! empty( $last['stats']['files'] ) ? number_format_i18n( (int) $last['stats']['files'] ) : '—',
		);
		$this->dl( $rows );
		if ( $manage ) {
			echo '<p class="bee-monitor-actions-row">';
			self::button(
				$running ? __( 'Resume scan', 'bee-monitor' ) : __( 'Run scan now', 'bee-monitor' ),
				'play',
				array(
					'type'    => 'button',
					'id'      => 'bee-monitor-run',
					'primary' => true,
				)
			);
			self::button(
				__( 'Full integrity scan', 'bee-monitor' ),
				'refresh-cw',
				array(
					'type' => 'button',
					'id'   => 'bee-monitor-run-full',
				)
			);
			self::button(
				__( 'Cancel scan', 'bee-monitor' ),
				'square',
				array(
					'type'   => 'button',
					'id'     => 'bee-monitor-cancel',
					'hidden' => ! $running,
				)
			);
			echo '</p><div class="bee-monitor-scan-status" id="bee-monitor-scan-status" hidden><progress id="bee-monitor-progress-bar" max="100" aria-describedby="bee-monitor-progress"></progress><p id="bee-monitor-progress" role="status" aria-live="polite"></p></div>';
		}
		echo '</section></div>';

		$week     = Activity::count_since( time() - WEEK_IN_SECONDS );
		$verified = Settings::value( 'core_checksums' ) ? ( isset( $last['checksums'] ) && ! $last['checksums'] ? __( 'Core checksums unavailable', 'bee-monitor' ) : __( 'Core verified against WordPress.org', 'bee-monitor' ) ) : __( 'Core checksums off', 'bee-monitor' );
		$tiles    = array(
			array(
				'shield-exclamation-point',
				(string) $urgent,
				__( 'Critical or high', 'bee-monitor' ),
				/* translators: %d: count. */
				sprintf( _n( '%d open finding in total', '%d open findings in total', array_sum( $counts ), 'bee-monitor' ), array_sum( $counts ) ),
				self::page_url(
					'bee-monitor',
					array(
						'status'       => 'open',
						'min_severity' => Findings::HIGH,
					)
				),
				$urgent ? 'is-alert' : '',
			),
			array( 'file-code', isset( $meta['files'] ) ? number_format_i18n( (int) $meta['files'] ) : '—', __( 'Files in baseline', 'bee-monitor' ), $verified . ( Settings::value( 'plugin_checksums' ) ? ' · ' . __( 'plugins verified', 'bee-monitor' ) : '' ), $manage ? self::page_url( 'bee-monitor-baseline' ) : '', '' ),
			array( 'list', (string) $week, __( 'Activity this week', 'bee-monitor' ), __( 'Updates, user changes, settings, scans', 'bee-monitor' ), $manage ? self::page_url( 'bee-monitor-activity' ) : '', '' ),
			array(
				! empty( $mail['time'] ) && empty( $mail['ok'] ) ? 'triangle-exclamation-point' : 'mail',
				(string) count( Settings::recipients() ),
				__( 'Alert recipients', 'bee-monitor' ),
				! empty( $mail['time'] ) ? ( $mail['ok'] ? __( 'Last email sent', 'bee-monitor' ) : __( 'Last email failed', 'bee-monitor' ) ) . ' · ' . wp_date( 'M j, H:i', (int) $mail['time'] ) : __( 'No email sent yet', 'bee-monitor' ),
				$manage ? self::page_url( 'bee-monitor-tools' ) : '',
				! empty( $mail['time'] ) && empty( $mail['ok'] ) ? 'is-warn' : '',
			),
		);
		echo '<ul class="bee-monitor-tiles" aria-label="' . esc_attr__( 'Key figures', 'bee-monitor' ) . '">';
		foreach ( $tiles as $tile ) {
			echo '<li class="bee-monitor-tile ' . esc_attr( $tile[5] ) . '">' . ( $tile[4] ? '<a href="' . esc_url( $tile[4] ) . '">' : '<div>' );
			Icons::render( $tile[0], array( 'size' => 20 ) );
			echo '<span class="bee-monitor-tile-value">' . esc_html( $tile[1] ) . '</span><span class="bee-monitor-tile-label">' . esc_html( $tile[2] ) . '</span><span class="bee-monitor-tile-sub">' . esc_html( $tile[3] ) . '</span>' . ( $tile[4] ? '</a>' : '</div>' ) . '</li>';
		}
		echo '</ul>';

		echo '<div class="bee-monitor-columns"><section class="bee-monitor-panel bee-monitor-priorities" aria-labelledby="bm-priorities"><h2 id="bm-priorities">';
		Icons::render( 'activity' );
		echo esc_html__( 'Top priorities', 'bee-monitor' ) . '</h2>';
		$top = Findings::query(
			array(
				'status'       => Findings::STATUS_OPEN,
				'min_severity' => Findings::LOW,
				'per_page'     => 5,
			)
		);
		if ( ! $top['items'] ) {
			echo '<div class="bee-monitor-empty-state">';
			Icons::render( 'shield-check', array( 'size' => 28 ) );
			echo '<p><strong>' . esc_html__( 'No open findings to review', 'bee-monitor' ) . '</strong><br>' . esc_html( $has_base ? __( 'New findings appear here, highest severity first.', 'bee-monitor' ) : __( 'Run the first scan to start monitoring.', 'bee-monitor' ) ) . '</p></div>';
		} else {
			$short = array(
				'official' => __( 'Verified source', 'bee-monitor' ),
				'baseline' => __( 'Unverified', 'bee-monitor' ),
				'pattern'  => __( 'Pattern lead', 'bee-monitor' ),
			);
			echo '<ol class="bee-monitor-priority-list">';
			foreach ( $top['items'] as $item ) {
				$category = Findings::category( $item['rule'] );
				$next     = Findings::next_steps( $item['rule'] );
				$next     = preg_match( '/^.*?[.!?](\s|$)/', $next, $m ) ? trim( $m[0] ) : $next;
				$verify   = isset( $item['evidence']['verification'] ) && isset( $short[ $item['evidence']['verification'] ] ) ? $short[ $item['evidence']['verification'] ] : '';
				echo '<li><div class="bee-monitor-priority-head">';
				$this->print_badge( $item['severity'] );
				echo ' <a href="' . esc_url( self::page_url( 'bee-monitor', array( 'finding' => $item['id'] ) ) ) . '">' . esc_html( Findings::title( $item['rule'] ) ) . '</a></div>';
				echo '<code class="bee-monitor-path">' . esc_html( $item['subject'] ) . '</code><p class="bee-monitor-meta">';
				Icons::render( self::category_icon( $category ), array( 'size' => 14 ) );
				echo esc_html( Findings::category_label( $category ) . ( '' !== $verify ? ' · ' . $verify : '' ) ) . '</p><p class="bee-monitor-next"><strong>' . esc_html__( 'Next step:', 'bee-monitor' ) . '</strong> ' . esc_html( $next ) . '</p></li>';
			}
			echo '</ol>';
		}
		echo '</section><div class="bee-monitor-side">';

		echo '<section class="bee-monitor-panel" aria-labelledby="bm-severity"><h2 id="bm-severity">';
		Icons::render( 'shield-exclamation-point' );
		echo esc_html__( 'Open findings by severity', 'bee-monitor' ) . '</h2><ul class="bee-monitor-bars">';
		$max = max( 1, max( $counts ) );
		for ( $sev = Findings::CRITICAL; $sev >= Findings::LOW; $sev-- ) {
			$url = self::page_url(
				'bee-monitor',
				array(
					'status'       => 'open',
					'min_severity' => $sev,
				)
			);
			echo '<li><a href="' . esc_url( $url ) . '">';
			$this->print_badge( $sev );
			echo '<span class="bee-monitor-bar" aria-hidden="true"><span class="bee-monitor-bar-fill bee-monitor-bar-' . esc_attr( Findings::severity_key( $sev ) ) . '" style="width:' . esc_attr( (string) round( $counts[ $sev ] / $max * 100 ) ) . '%"></span></span><strong class="bee-monitor-bar-count">' . esc_html( (string) (int) $counts[ $sev ] ) . '</strong></a></li>';
		}
		echo '</ul></section>';

		if ( $manage ) {
			echo '<section class="bee-monitor-panel" aria-labelledby="bm-recent"><h2 id="bm-recent">';
			Icons::render( 'list' );
			echo esc_html__( 'Recent activity', 'bee-monitor' ) . '</h2>';
			$recent = array_slice( Activity::query( '', 1 )['items'], 0, 5 );
			if ( ! $recent ) {
				echo '<p class="description">' . esc_html__( 'No activity recorded yet.', 'bee-monitor' ) . '</p>';
			} else {
				echo '<ul class="bee-monitor-timeline">';
				foreach ( $recent as $row ) {
					/* translators: %s: time difference. */
					echo '<li><span class="bee-monitor-time">' . esc_html( sprintf( __( '%s ago', 'bee-monitor' ), human_time_diff( (int) strtotime( $row['created_at'] . ' UTC' ) ) ) ) . '</span><span>' . esc_html( Activity::label( $row['type'] ) ) . '</span><code class="bee-monitor-path">' . esc_html( $row['object'] ) . '</code></li>';
				}
				echo '</ul>';
			}
			echo '<p><a href="' . esc_url( self::page_url( 'bee-monitor-activity' ) ) . '">' . esc_html__( 'View full activity log', 'bee-monitor' ) . '</a></p></section>';
		}
		echo '</div></div><h2 class="bee-monitor-section-title">';
		Icons::render( 'file-search' );
		echo esc_html__( 'All findings', 'bee-monitor' ) . '</h2>';
	}

	/**
	 * Escaped definition list.
	 *
	 * @param array $rows Label => value.
	 */
	private function dl( array $rows ) {
		echo '<dl class="bee-monitor-dl">';
		foreach ( $rows as $label => $value ) {
			echo '<dt>' . esc_html( $label ) . '</dt><dd>' . esc_html( (string) $value ) . '</dd>';
		}
		echo '</dl>';
	}

	/**
	 * Read-only investigation aids for file findings, plus related findings.
	 *
	 * @param array $item Finding.
	 */
	private function investigation( array $item ) {
		$rel = isset( $item['evidence']['path'] ) ? (string) $item['evidence']['path'] : '';
		if ( '' !== $rel ) {
			$abs  = Paths::to_abs( $rel );
			$rows = array();
			if ( ! @file_exists( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$rows[ __( 'Current state', 'bee-monitor' ) ] = __( 'The file no longer exists.', 'bee-monitor' );
			} else {
				$size  = (int) @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$perms = @fileperms( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$owner = @fileowner( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				if ( false !== $owner && function_exists( 'posix_getpwuid' ) ) {
					$info  = posix_getpwuid( $owner );
					$owner = is_array( $info ) && isset( $info['name'] ) ? $info['name'] : $owner;
				}
				$rows[ __( 'Size', 'bee-monitor' ) ]        = size_format( $size, 1 ) . ' (' . number_format_i18n( $size ) . ' bytes)';
				$rows[ __( 'Modified', 'bee-monitor' ) ]    = wp_date( 'Y-m-d H:i:s', (int) @filemtime( $abs ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
				$rows[ __( 'Permissions', 'bee-monitor' ) ] = false !== $perms ? substr( sprintf( '%o', $perms ), -4 ) : '?';
				$rows[ __( 'Owner', 'bee-monitor' ) ]       = false !== $owner ? (string) $owner : '?';
				$expected                                   = isset( $item['evidence']['sha256'] ) ? (string) $item['evidence']['sha256'] : '';
				if ( $size <= (int) Settings::value( 'max_inspect_kb' ) * 1024 ) {
					$now                                        = (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
					$rows[ __( 'SHA-256 now', 'bee-monitor' ) ] = $now;
					if ( '' !== $expected ) {
						$rows[ __( 'Since this finding', 'bee-monitor' ) ] = hash_equals( $expected, $now ) ? __( 'Unchanged', 'bee-monitor' ) : __( 'Changed again after it was flagged', 'bee-monitor' );
					}
				}
			}
			echo '<h3>';
			Icons::render( 'search' );
			echo esc_html__( 'Investigation', 'bee-monitor' ) . '</h3><table class="widefat striped bee-monitor-detail"><tbody>';
			foreach ( $rows as $label => $value ) {
				echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><code class="bee-monitor-path">' . esc_html( $value ) . '</code></td></tr>';
			}
			echo '</tbody></table>';
			if ( self::can_manage() ) {
				$quoted   = "'" . str_replace( "'", "'\\''", 0 === strpos( $rel, '@' ) ? $abs : $rel ) . "'";
				$commands = array(
					'sha256sum ' . $quoted,
					'stat ' . $quoted,
					'grep -nE "eval|assert|base64_decode|gzinflate|str_rot13|shell_exec|system\\(|passthru|proc_open" ' . $quoted,
				);
				$area     = isset( $item['evidence']['area'] ) ? $item['evidence']['area'] : '';
				if ( 'core' === $area ) {
					$commands[] = 'wp core verify-checksums';
				} elseif ( 'plugin' === $area && ! empty( $item['evidence']['component'] ) ) {
					$commands[] = 'wp plugin verify-checksums ' . sanitize_key( $item['evidence']['component'] );
				}
				$pre_id = 'bee-monitor-commands-' . (int) $item['id'];
				echo '<p class="description">';
				Icons::render( 'terminal' );
				echo esc_html__( 'Read-only commands to run from the WordPress root on the server:', 'bee-monitor' ) . '</p><div class="bee-monitor-commands-wrap"><pre class="bee-monitor-commands" id="' . esc_attr( $pre_id ) . '"><code>' . esc_html( implode( "\n", $commands ) ) . '</code></pre>';
				self::button(
					__( 'Copy commands', 'bee-monitor' ),
					'copy',
					array(
						'type'  => 'button',
						'class' => 'button-small bee-monitor-copy',
						'data'  => array( 'bee-monitor-copy' => $pre_id ),
					)
				);
				echo '<span class="screen-reader-text bee-monitor-copy-status" role="status" aria-live="polite"></span></div>';
			}
		}
		$related = Findings::related( $item['subject'], (int) $item['id'] );
		if ( $related ) {
			echo '<h3>';
			Icons::render( 'link' );
			echo esc_html__( 'Related findings', 'bee-monitor' ) . '</h3><ul class="bee-monitor-related">';
			foreach ( $related as $other ) {
				echo '<li>';
				$this->print_badge( $other['severity'] );
				echo ' <a href="' . esc_url( self::page_url( 'bee-monitor', array( 'finding' => $other['id'] ) ) ) . '">' . esc_html( Findings::title( $other['rule'] ) ) . '</a> <span class="description">(' . esc_html( Findings::term( 'status', $other['status'] ) ) . ', ' . esc_html( Notifier::local_time( $other['last_seen'] ) ) . ')</span></li>';
			}
			echo '</ul>';
		}
	}

	/**
	 * AJAX: cancel the running scan.
	 */
	public function ajax_scan_cancel() {
		check_ajax_referer( 'bee_monitor_scan', 'nonce' );
		if ( ! current_user_can( self::capability() ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'bee-monitor' ) ), 403 );
		}
		$requested = Scanner::request_cancel();
		$progress  = ( new Scanner() )->progress();
		wp_send_json_success( array_merge( $progress, array( 'requested' => $requested ) ) );
	}

	/**
	 * Download a findings report.
	 */
	public function handle_export() {
		$this->guard( 'bee_monitor_export' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in guard().
		$format = isset( $_POST['format'] ) && 'csv' === sanitize_key( wp_unslash( $_POST['format'] ) ) ? 'csv' : 'json';
		$status = isset( $_POST['status'] ) && 'all' === sanitize_key( wp_unslash( $_POST['status'] ) ) ? 'all' : 'open';
		$args   = array(
			'status'           => $status,
			'include_personal' => ! empty( $_POST['include_personal'] ),
			'include_site'     => ! empty( $_POST['include_site'] ),
		);
		// phpcs:enable
		$report = Report::build( $args );
		Activity::log( 'report_exported', $format, $args['include_personal'] ? 'with personal data' : 'personal data excluded' );
		Storage::log(
			'info',
			'Bee Monitor report exported',
			array(
				'user'     => get_current_user_id(),
				'format'   => $format,
				'status'   => $status,
				'personal' => $args['include_personal'],
				'count'    => count( $report['findings'] ),
			)
		);
		nocache_headers();
		header( 'Content-Type: ' . ( 'csv' === $format ? 'text/csv' : 'application/json' ) . '; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . Report::filename( $format ) . '"' );
		header( 'X-Content-Type-Options: nosniff' );
		echo 'csv' === $format ? Report::to_csv( $report ) : Report::to_json( $report ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- file download, not HTML; contents are JSON/CSV encoded.
		exit;
	}

	/**
	 * Repair and quarantine options on a finding.
	 *
	 * @param array $item Finding.
	 */
	private function fix_options( array $item ) {
		if ( ! self::can_manage() ) {
			return;
		}
		$opt = Repair::options( array_merge( $item, array( 'status' => Findings::STATUS_OPEN ) ) );
		if ( ! $opt['repair'] && ! $opt['quarantine'] ) {
			return;
		}
		echo '<h3>';
		Icons::render( 'wrench' );
		echo esc_html__( 'Repair options', 'bee-monitor' ) . '</h3>';
		$reason = Repair::unavailable_reason();
		if ( '' !== $reason || Findings::STATUS_OPEN !== $item['status'] ) {
			echo '<p class="description">' . esc_html( '' !== $reason ? $reason : __( 'Repair options are available for open findings only.', 'bee-monitor' ) ) . '</p>';
			return;
		}
		echo '<p class="bee-monitor-actions-row">';
		if ( $opt['repair'] ) {
			echo '<a class="button bee-monitor-btn" href="' . esc_url(
				self::page_url(
					'bee-monitor',
					array(
						'finding' => $item['id'],
						'fix'     => 'repair',
					)
				)
			) . '">';
			Icons::render( 'wrench' );
			echo '<span>' . esc_html__( 'Review repair from official source', 'bee-monitor' ) . '</span></a>';
		}
		if ( $opt['quarantine'] ) {
			echo '<a class="button bee-monitor-btn" href="' . esc_url(
				self::page_url(
					'bee-monitor',
					array(
						'finding' => $item['id'],
						'fix'     => 'quarantine',
					)
				)
			) . '">';
			Icons::render( 'archive' );
			echo '<span>' . esc_html__( 'Review quarantine', 'bee-monitor' ) . '</span></a>';
		}
		echo '</p>';
	}

	/**
	 * Confirmation screen for repair or quarantine.
	 *
	 * @param array  $item Finding.
	 * @param string $fix  repair|quarantine.
	 */
	private function fix_confirm( array $item, $fix ) {
		$this->header( 'repair' === $fix ? __( 'Repair file from official source', 'bee-monitor' ) : __( 'Quarantine file', 'bee-monitor' ) );
		echo '<p><a href="' . esc_url( self::page_url( 'bee-monitor', array( 'finding' => $item['id'] ) ) ) . '">&larr; ' . esc_html__( 'Back to finding', 'bee-monitor' ) . '</a></p>';
		$opt    = Repair::options( $item );
		$reason = Repair::unavailable_reason();
		if ( '' !== $reason || ! $opt[ $fix ] ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( '' !== $reason ? $reason : __( 'This action is not available for this finding.', 'bee-monitor' ) ) . '</p></div></div>';
			return;
		}
		$rows = array(
			__( 'File', 'bee-monitor' )    => $opt['rel'],
			__( 'Finding', 'bee-monitor' ) => Findings::title( $item['rule'] ),
		);
		if ( @file_exists( $opt['abs'] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$rows[ __( 'Current SHA-256', 'bee-monitor' ) ] = (string) @hash_file( 'sha256', $opt['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		if ( 'repair' === $fix ) {
			$source = Repair::source( $item );
			if ( is_wp_error( $source ) ) {
				echo '<div class="notice notice-error inline"><p>' . esc_html( $source->get_error_message() ) . '</p></div></div>';
				return;
			}
			$rows[ __( 'Official source', 'bee-monitor' ) ]   = $source['url'];
			$rows[ __( 'Expected checksum', 'bee-monitor' ) ] = $source['sha256'] ? 'SHA-256 ' . $source['sha256'][0] : 'MD5 ' . $source['md5'][0];
			$steps = __( 'Bee Monitor will download the official file, verify it against the official checksum, copy the current file to quarantine as a backup, replace the file, verify the result, and update the baseline. If anything fails, the file is left unchanged or restored from the backup.', 'bee-monitor' );
		} else {
			$steps = __( 'Bee Monitor will copy the file to the protected quarantine folder under a non-executable name, verify the copy, and then remove the original. You can restore it from Tools & Status.', 'bee-monitor' );
		}
		echo '<table class="widefat striped bee-monitor-detail"><tbody>';
		foreach ( $rows as $label => $value ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td><code class="bee-monitor-path">' . esc_html( $value ) . '</code></td></tr>';
		}
		echo '</tbody></table><p>' . esc_html( $steps ) . '</p>';
		if ( $opt['warn'] && 'quarantine' === $fix ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'This file is inside a plugin, theme, must-use plugin, or core folder, or was flagged by a pattern match. Removing it can break the site if it is legitimate. Confirm it is malicious before continuing.', 'bee-monitor' ) . '</p></div>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="bee_monitor_fix"><input type="hidden" name="op" value="' . esc_attr( $fix ) . '"><input type="hidden" name="finding" value="' . (int) $item['id'] . '">';
		wp_nonce_field( 'bee_monitor_fix_' . $fix . '_' . (int) $item['id'] );
		echo '<p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I reviewed this finding and want to continue.', 'bee-monitor' ) . '</label></p>';
		self::button( 'repair' === $fix ? __( 'Repair file', 'bee-monitor' ) : __( 'Quarantine file', 'bee-monitor' ), 'repair' === $fix ? 'wrench' : 'archive', array( 'primary' => true ) );
		echo '</form></div>';
	}

	/**
	 * Quarantine list on Tools & Status.
	 */
	private function quarantine_section() {
		$entries = Repair::entries();
		if ( ! $entries && ! Settings::value( 'allow_repairs' ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only confirmation view; actions are nonce-checked.
		$qid = isset( $_GET['q'] ) ? sanitize_key( wp_unslash( $_GET['q'] ) ) : '';
		$qop = isset( $_GET['qop'] ) ? sanitize_key( wp_unslash( $_GET['qop'] ) ) : '';
		// phpcs:enable
		echo '<h2 id="bee-monitor-quarantine">';
		Icons::render( 'archive' );
		echo esc_html__( 'Quarantine and backups', 'bee-monitor' ) . '</h2>';
		if ( ! $entries ) {
			echo '<p class="description">' . esc_html__( 'No quarantined files or repair backups.', 'bee-monitor' ) . '</p>';
			return;
		}
		if ( isset( $entries[ $qid ] ) && in_array( $qop, array( 'restore', 'delete' ), true ) ) {
			$e = $entries[ $qid ];
			echo '<div class="notice notice-warning inline"><p>' . esc_html( 'restore' === $qop ? __( 'Restore this file to its original location? Restoring a malicious file makes it active again.', 'bee-monitor' ) : __( 'Permanently delete this quarantined copy? It cannot be recovered afterwards.', 'bee-monitor' ) ) . ' <code>' . esc_html( $e['rel'] ) . '</code></p>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="bee_monitor_fix"><input type="hidden" name="op" value="' . esc_attr( $qop ) . '"><input type="hidden" name="entry" value="' . esc_attr( $qid ) . '">';
			wp_nonce_field( 'bee_monitor_fix_' . $qop . '_' . $qid );
			echo '<p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'I understand.', 'bee-monitor' ) . '</label></p>';
			self::button( 'restore' === $qop ? __( 'Restore file', 'bee-monitor' ) : __( 'Delete copy permanently', 'bee-monitor' ), 'restore' === $qop ? 'undo-2' : 'circle-x', array( 'primary' => true ) );
			echo ' <a class="button" href="' . esc_url( self::page_url( 'bee-monitor-tools' ) . '#bee-monitor-quarantine' ) . '">' . esc_html__( 'Cancel', 'bee-monitor' ) . '</a></form></div>';
		}
		echo '<table class="widefat striped"><thead><tr><th scope="col">' . esc_html__( 'Original file', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Type', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Date', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Size', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Actions', 'bee-monitor' ) . '</th></tr></thead><tbody>';
		foreach ( $entries as $id => $e ) {
			echo '<tr><td><code class="bee-monitor-path">' . esc_html( $e['rel'] ) . '</code></td><td>' . esc_html( 'repair-backup' === $e['kind'] ? __( 'Backup before repair', 'bee-monitor' ) : __( 'Quarantined', 'bee-monitor' ) ) . '</td><td>' . esc_html( wp_date( 'Y-m-d H:i', (int) $e['time'] ) ) . '</td><td>' . esc_html( size_format( (int) $e['size'], 1 ) ) . '</td><td>';
			echo '<a href="' . esc_url(
				self::page_url(
					'bee-monitor-tools',
					array(
						'q'   => $id,
						'qop' => 'restore',
					)
				) . '#bee-monitor-quarantine'
			) . '">' . esc_html__( 'Restore', 'bee-monitor' ) . '</a> | ';
			echo '<a href="' . esc_url(
				self::page_url(
					'bee-monitor-tools',
					array(
						'q'   => $id,
						'qop' => 'delete',
					)
				) . '#bee-monitor-quarantine'
			) . '">' . esc_html__( 'Delete', 'bee-monitor' ) . '</a></td></tr>';
		}
		echo '</tbody></table>';
	}

	/**
	 * Repair, quarantine, restore, and delete actions.
	 */
	public function handle_fix() {
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- nonce verified below for the specific operation and object.
		$op      = isset( $_POST['op'] ) ? sanitize_key( wp_unslash( $_POST['op'] ) ) : '';
		$finding = isset( $_POST['finding'] ) ? absint( $_POST['finding'] ) : 0;
		$entry   = isset( $_POST['entry'] ) ? sanitize_key( wp_unslash( $_POST['entry'] ) ) : '';
		$confirm = ! empty( $_POST['confirm'] );
		// phpcs:enable
		if ( ! in_array( $op, array( 'repair', 'quarantine', 'restore', 'delete' ), true ) ) {
			wp_die( esc_html__( 'Unknown Bee Monitor action.', 'bee-monitor' ), '', array( 'response' => 400 ) );
		}
		$object = in_array( $op, array( 'repair', 'quarantine' ), true ) ? (string) $finding : $entry;
		$this->guard( 'bee_monitor_fix_' . $op . '_' . $object );
		$item     = $finding ? Findings::get( $finding ) : null;
		$need_cap = ( $item && 'core' === Paths::area( Paths::to_abs( isset( $item['evidence']['path'] ) ? (string) $item['evidence']['path'] : '' ) ) ) ? 'update_core' : 'update_plugins';
		if ( ! current_user_can( $need_cap ) ) {
			wp_die( esc_html__( 'You do not have permission to change site files.', 'bee-monitor' ), '', array( 'response' => 403 ) );
		}
		$back = in_array( $op, array( 'repair', 'quarantine' ), true ) ? self::page_url( 'bee-monitor', array( 'finding' => $finding ) ) : self::page_url( 'bee-monitor-tools' ) . '#bee-monitor-quarantine';
		if ( ! $confirm ) {
			$this->flash( 'error', __( 'Please confirm the action. Nothing was changed.', 'bee-monitor' ) );
			wp_safe_redirect( $back );
			exit;
		}
		switch ( $op ) {
			case 'repair':
				$result  = Repair::repair( $finding );
				$success = __( 'The file was repaired from the official source and verified. A backup of the previous file is in quarantine.', 'bee-monitor' );
				break;
			case 'quarantine':
				$result  = Repair::quarantine( $finding );
				$success = __( 'The file was moved to quarantine. You can restore it from Tools & Status.', 'bee-monitor' );
				break;
			case 'restore':
				$result  = Repair::restore( $entry );
				$success = __( 'The file was restored to its original location.', 'bee-monitor' );
				break;
			default:
				$result  = Repair::delete_entry( $entry );
				$success = __( 'The quarantined copy was deleted.', 'bee-monitor' );
		}
		$this->flash( is_wp_error( $result ) ? 'error' : 'success', is_wp_error( $result ) ? $result->get_error_message() : $success );
		wp_safe_redirect( $back );
		exit;
	}

	/**
	 * Activity log screen.
	 */
	public function page_activity() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended -- read-only filters.
		$type  = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : '';
		$paged = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		// phpcs:enable
		$types = Activity::types();
		if ( ! isset( $types[ $type ] ) ) {
			$type = '';
		}
		$this->header( __( 'Bee Monitor Activity', 'bee-monitor' ) );
		/* translators: %d: days. */
		echo '<p class="description">' . esc_html( sprintf( __( 'Security-relevant changes on this site. Entries are kept for %d days. The acting user is stored as an ID and shown by name only while the account exists.', 'bee-monitor' ), (int) Settings::value( 'activity_retention_days' ) ) ) . '</p>';
		echo '<form method="get" class="bee-monitor-filter"><input type="hidden" name="page" value="bee-monitor-activity"><label for="bee-monitor-activity-type">' . esc_html__( 'Event type', 'bee-monitor' ) . '</label> <select id="bee-monitor-activity-type" name="type"><option value="">' . esc_html__( 'All events', 'bee-monitor' ) . '</option>';
		foreach ( $types as $key => $label ) {
			printf( '<option value="%1$s" %2$s>%3$s</option>', esc_attr( $key ), selected( $type, $key, false ), esc_html( $label ) );
		}
		echo '</select> ';
		submit_button( __( 'Filter', 'bee-monitor' ), 'secondary', '', false );
		echo '</form>';
		$result = Activity::query( $type, $paged );
		echo '<table class="wp-list-table widefat fixed striped"><caption class="screen-reader-text">' . esc_html__( 'Activity', 'bee-monitor' ) . '</caption><thead><tr>';
		foreach ( array( __( 'Time', 'bee-monitor' ), __( 'Event', 'bee-monitor' ), __( 'Object', 'bee-monitor' ), __( 'Details', 'bee-monitor' ), __( 'User', 'bee-monitor' ), __( 'Via', 'bee-monitor' ) ) as $col ) {
			echo '<th scope="col">' . esc_html( $col ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		if ( ! $result['items'] ) {
			echo '<tr><td class="bee-monitor-empty" colspan="6">';
			Icons::render(
				'list',
				array(
					'size'  => 32,
					'class' => 'bee-monitor-empty-icon',
				)
			);
			echo '<span>' . esc_html__( 'No activity recorded yet.', 'bee-monitor' ) . '</span></td></tr>';
		}
		foreach ( $result['items'] as $row ) {
			$user  = $row['actor'] ? get_userdata( (int) $row['actor'] ) : false;
			$actor = $user ? $user->user_login : ( $row['actor'] ? sprintf( '#%d', (int) $row['actor'] ) : '—' );
			echo '<tr><td>' . esc_html( Notifier::local_time( $row['created_at'] ) ) . '</td><td>' . esc_html( Activity::label( $row['type'] ) ) . '</td><td><code class="bee-monitor-path">' . esc_html( $row['object'] ) . '</code></td><td>' . esc_html( $row['detail'] ) . '</td><td>' . esc_html( $actor ) . '</td><td>' . esc_html( $row['via'] ) . '</td></tr>';
		}
		echo '</tbody></table>';
		$pages = (int) ceil( $result['total'] / Activity::PER_PAGE );
		if ( $pages > 1 ) {
			echo '<div class="tablenav"><div class="tablenav-pages">';
			echo wp_kses_post(
				paginate_links(
					array(
						'base'    => add_query_arg( 'paged', '%#%', self::page_url( 'bee-monitor-activity', array( 'type' => $type ) ) ),
						'format'  => '',
						'current' => $paged,
						'total'   => $pages,
					)
				)
			);
			echo '</div></div>';
		}
		echo '<h2>';
		Icons::render( 'circle-x' );
		echo esc_html__( 'Delete activity log', 'bee-monitor' ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="bee_monitor_activity">';
		wp_nonce_field( 'bee_monitor_activity_delete' );
		echo '<p><label><input type="checkbox" name="confirm" value="1" required> ' . esc_html__( 'Delete every activity entry. This cannot be undone.', 'bee-monitor' ) . '</label></p>';
		self::button( __( 'Delete activity log', 'bee-monitor' ), 'circle-x' );
		echo '</form></div>';
	}

	/**
	 * Delete the activity log.
	 */
	public function handle_activity() {
		$this->guard( 'bee_monitor_activity_delete' );
		if ( empty( $_POST['confirm'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Missing -- verified in guard().
			$this->flash( 'error', __( 'Please tick the confirmation box.', 'bee-monitor' ) );
		} else {
			$count = Activity::delete_all();
			Activity::log( 'activity_cleared', 'activity log', $count . ' entries' );
			/* translators: %d: number of entries. */
			$this->flash( 'success', sprintf( __( '%d activity entries deleted.', 'bee-monitor' ), $count ) );
		}
		wp_safe_redirect( self::page_url( 'bee-monitor-activity' ) );
		exit;
	}

	/**
	 * Tags allowed in Bee Monitor admin fragments.
	 *
	 * @return array
	 */
	private static function allowed_html() {
		return array(
			'span'   => array( 'class' => true ),
			'code'   => array( 'class' => true ),
			'strong' => array(),
			'em'     => array(),
			'br'     => array(),
		) + Icons::allowed();
	}

	/**
	 * Icon for a findings category.
	 *
	 * @param string $category Category key.
	 * @return string Lucide icon name.
	 */
	private static function category_icon( $category ) {
		$map = array(
			'files'   => 'file-code',
			'core'    => 'shield',
			'users'   => 'users',
			'options' => 'settings',
			'cron'    => 'clock',
			'content' => 'file-text',
			'logins'  => 'log-in',
			'monitor' => 'activity',
		);
		return isset( $map[ $category ] ) ? $map[ $category ] : 'file-code';
	}

	/**
	 * Submit or plain button with an icon and a visible label.
	 *
	 * @param string $label   Visible label.
	 * @param string $icon    Lucide icon name.
	 * @param array  $attrs   name, id, type (submit|button), primary (bool), hidden (bool), extra classes.
	 */
	private static function button( $label, $icon, array $attrs = array() ) {
		$attrs = wp_parse_args(
			$attrs,
			array(
				'type'    => 'submit',
				'name'    => '',
				'id'      => '',
				'primary' => false,
				'hidden'  => false,
				'class'   => '',
				'data'    => array(),
			)
		);
		echo '<button type="' . esc_attr( 'button' === $attrs['type'] ? 'button' : 'submit' ) . '" class="' . esc_attr( trim( 'button bee-monitor-btn ' . ( $attrs['primary'] ? 'button-primary ' : '' ) . $attrs['class'] ) ) . '"';
		if ( $attrs['name'] ) {
			echo ' name="' . esc_attr( $attrs['name'] ) . '" value="1"';
		}
		if ( $attrs['id'] ) {
			echo ' id="' . esc_attr( $attrs['id'] ) . '"';
		}
		foreach ( $attrs['data'] as $key => $value ) {
			echo ' data-' . esc_attr( sanitize_key( $key ) ) . '="' . esc_attr( $value ) . '"';
		}
		echo $attrs['hidden'] ? ' hidden>' : '>';
		Icons::render( $icon );
		echo '<span class="bee-monitor-btn-label">' . esc_html( $label ) . '</span></button>';
	}

	/**
	 * Print a severity badge.
	 *
	 * @param int $severity Severity.
	 */
	private function print_badge( $severity ) {
		echo wp_kses( $this->severity_badge( $severity ), self::allowed_html() );
	}

	/**
	 * Severity badge HTML.
	 *
	 * @param int $severity Severity.
	 * @return string
	 */
	private function severity_badge( $severity ) {
		$icons = array( 'info', 'info', 'circle-exclamation-point', 'triangle-exclamation-point', 'octagon-exclamation-point' );
		return '<span class="bee-monitor-sev bee-monitor-sev-' . esc_attr( Findings::severity_key( $severity ) ) . '">' . Icons::svg( $icons[ max( 0, min( 4, (int) $severity ) ) ], array( 'size' => 12 ) ) . esc_html( Findings::severity_label( $severity ) ) . '</span>';
	}
}
