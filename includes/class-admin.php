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

		add_menu_page( __( 'Bee Monitor', 'bee-monitor' ), __( 'Bee Monitor', 'bee-monitor' ) . $badge, $cap, 'bee-monitor', array( $this, 'page_findings' ), 'dashicons-shield-alt', 81 );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Findings', 'bee-monitor' ), __( 'Findings', 'bee-monitor' ), $cap, 'bee-monitor', array( $this, 'page_findings' ) );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Baseline', 'bee-monitor' ), __( 'Baseline', 'bee-monitor' ), $cap, 'bee-monitor-baseline', array( $this, 'page_baseline' ) );
		add_submenu_page( 'bee-monitor', __( 'Bee Monitor Settings', 'bee-monitor' ), __( 'Settings', 'bee-monitor' ), $cap, 'bee-monitor-settings', array( $this, 'page_settings' ) );
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
					'starting' => __( 'Starting scan…', 'bee-monitor' ),
					/* translators: 1: scan phase, 2: files checked, 3: new findings. */
					'running'  => __( 'Scanning: phase %1$s, %2$d files checked, %3$d new findings…', 'bee-monitor' ),
					/* translators: 1: files checked, 2: new findings. */
					'done'     => __( 'Scan complete: %1$d files checked, %2$d new findings.', 'bee-monitor' ),
					'view'     => __( 'View findings', 'bee-monitor' ),
					'error'    => __( 'The scan request failed. Bee Monitor will continue in the background via WP-Cron. Check Tools & Status for errors.', 'bee-monitor' ),
					'confirm'  => __( 'Are you sure? This cannot be undone.', 'bee-monitor' ),
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
		$counts = Findings::open_counts();
		if ( $counts[ Findings::CRITICAL ] || $counts[ Findings::HIGH ] ) {
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
			'bee_monitor_scanning' => array( __( 'Scanning', 'bee-monitor' ), __( 'How often Bee Monitor checks files and how much work each step does.', 'bee-monitor' ) ),
			'bee_monitor_scope'    => array( __( 'Scope and exclusions', 'bee-monitor' ), __( 'Excluded paths are not checked at all. Every exclusion is a place where malware would go unnoticed, so keep this list short.', 'bee-monitor' ) ),
			'bee_monitor_checks'   => array( __( 'Integrity and site checks', 'bee-monitor' ), '' ),
			'bee_monitor_alerts'   => array( __( 'Email alerts', 'bee-monitor' ), __( 'Alerts are sent with wp_mail(). Use an SMTP or transactional email plugin for reliable delivery.', 'bee-monitor' ) ),
			'bee_monitor_advanced' => array( __( 'Tamper detection and data', 'bee-monitor' ), '' ),
		);
		foreach ( $sections as $id => $section ) {
			$desc = $section[1];
			add_settings_section(
				$id,
				$section[0],
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
			array( 'recipients', 'bee_monitor_alerts', 'text', __( 'Alert recipients', 'bee-monitor' ), __( 'Comma-separated. Leave empty to use the site administration email.', 'bee-monitor' ) ),
			array(
				'immediate_severity',
				'bee_monitor_alerts',
				'select',
				__( 'Send immediately at or above', 'bee-monitor' ),
				__( 'Lower-severity findings go into the digest.', 'bee-monitor' ),
				array(
					'critical' => __( 'Critical', 'bee-monitor' ),
					'high'     => __( 'High', 'bee-monitor' ),
					'medium'   => __( 'Medium', 'bee-monitor' ),
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
					'off'    => __( 'Off (lower-severity findings are not emailed)', 'bee-monitor' ),
				),
			),
			array( 'digest_all_clear', 'bee_monitor_alerts', 'checkbox', __( 'Send digest even when there is nothing new', 'bee-monitor' ), __( 'A regular "all clear" email confirms monitoring is still running.', 'bee-monitor' ) ),
			array( 'max_emails_per_hour', 'bee_monitor_alerts', 'number', __( 'Maximum emails per hour', 'bee-monitor' ), __( 'Extra findings are held and included in the next email.', 'bee-monitor' ) ),
			array( 'reminder_days', 'bee_monitor_alerts', 'number', __( 'Remind about open high and critical findings every (days)', 'bee-monitor' ), __( '0 turns reminders off.', 'bee-monitor' ) ),
			array( 'retention_days', 'bee_monitor_advanced', 'number', __( 'Delete closed findings after (days)', 'bee-monitor' ), __( 'Resolved, expected, and auto-verified findings not seen for this many days are deleted. Open findings are never deleted automatically. 0 keeps them forever.', 'bee-monitor' ) ),
			array( 'heartbeat_url', 'bee_monitor_advanced', 'url', __( 'Heartbeat URL', 'bee-monitor' ), __( 'Optional https URL pinged after every completed scan (for example, a Healthchecks.io check). If pings stop, that service alerts you, even when this site is compromised or offline.', 'bee-monitor' ) ),
			array( 'delete_data_on_uninstall', 'bee_monitor_advanced', 'checkbox', __( 'Delete all Bee Monitor data on uninstall', 'bee-monitor' ), __( 'When off (default), findings, baseline, and settings are kept if the plugin is deleted, so history survives a reinstall.', 'bee-monitor' ) ),
		);
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
					'label_for' => 'checkbox' === $field[2] ? null : 'bee-monitor-' . $field[0],
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
		foreach ( array( 'enabled', 'exclusions', 'recipients', 'extra_extensions', 'auto_accept_updates', 'core_checksums', 'heartbeat_url' ) as $key ) {
			if ( (string) $old[ $key ] !== (string) $new[ $key ] ) {
				$changed[] = $key;
			}
		}
		Settings::save( $new );
		Storage::remember_urls();
		Plugin::schedule( true );

		if ( $changed ) {
			$user = wp_get_current_user();
			Findings::record(
				array(
					'rule'        => 'settings_changed',
					'severity'    => array_intersect( $changed, array( 'enabled', 'exclusions', 'recipients' ) ) ? Findings::MEDIUM : Findings::LOW,
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
		// phpcs:enable
		if ( ! in_array( $status, array( 'open', 'expected', 'resolved', 'auto', 'all' ), true ) ) {
			$status = 'open';
		}
		$min_sev = min( Findings::CRITICAL, $min_sev );

		$this->header( __( 'Bee Monitor', 'bee-monitor' ) );
		$this->summary_cards();

		echo '<h2 class="screen-reader-text">' . esc_html__( 'Filter findings', 'bee-monitor' ) . '</h2><ul class="subsubsub">';
		$tabs = array(
			'open'     => Findings::term( 'status', 'open' ),
			'expected' => Findings::term( 'status', 'expected' ),
			'resolved' => Findings::term( 'status', 'resolved' ),
			'auto'     => Findings::term( 'status', 'auto' ),
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
		submit_button( __( 'Filter', 'bee-monitor' ), 'secondary', '', false );
		echo '</form>';

		$result = Findings::query(
			array(
				'status'       => $status,
				'min_severity' => $min_sev,
				'per_page'     => self::PER_PAGE,
				'page'         => $paged,
			)
		);

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
		echo '<input type="hidden" name="action" value="bee_monitor_findings">';
		wp_nonce_field( 'bee_monitor_findings' );
		$this->bulk_controls( 'top' );
		echo '<table class="wp-list-table widefat fixed striped bee-monitor-table"><caption class="screen-reader-text">' . esc_html__( 'Findings', 'bee-monitor' ) . '</caption><thead><tr>';
		echo '<td class="manage-column column-cb check-column"><label class="screen-reader-text" for="bee-monitor-select-all">' . esc_html__( 'Select all', 'bee-monitor' ) . '</label><input type="checkbox" id="bee-monitor-select-all" class="bee-monitor-select-all"></td>';
		foreach ( array( __( 'Severity', 'bee-monitor' ), __( 'Finding', 'bee-monitor' ), __( 'Affected', 'bee-monitor' ), __( 'Confidence', 'bee-monitor' ), __( 'Last seen', 'bee-monitor' ), __( 'Status', 'bee-monitor' ) ) as $col ) {
			echo '<th scope="col">' . esc_html( $col ) . '</th>';
		}
		echo '</tr></thead><tbody>';
		if ( empty( $result['items'] ) ) {
			echo '<tr><td colspan="7">' . esc_html__( 'No findings match this view.', 'bee-monitor' ) . '</td></tr>';
		}
		foreach ( $result['items'] as $item ) {
			$url = self::page_url( 'bee-monitor', array( 'finding' => $item['id'] ) );
			echo '<tr>';
			printf( '<th scope="row" class="check-column"><label class="screen-reader-text" for="bm-f-%1$d">%2$s</label><input type="checkbox" id="bm-f-%1$d" name="ids[]" value="%1$d"></th>', (int) $item['id'], esc_html__( 'Select finding', 'bee-monitor' ) );
			echo '<td>';
			$this->print_badge( $item['severity'] );
			echo '</td>';
			printf( '<td><a href="%1$s"><strong>%2$s</strong></a><br><span class="description">%3$s · %4$s</span></td>', esc_url( $url ), esc_html( Findings::title( $item['rule'] ) ), esc_html( Findings::term( 'basis', $item['basis'] ) ), esc_html( Findings::term( 'change', $item['change_type'] ) ) );
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
		$this->bulk_controls( 'bottom' );
		echo '</form>';

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
		$this->header( __( 'Bee Monitor Finding', 'bee-monitor' ) );
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
			__( 'Affected', 'bee-monitor' )    => '<code class="bee-monitor-path">' . esc_html( $item['subject'] ) . '</code>',
			__( 'Change', 'bee-monitor' )      => esc_html( Findings::term( 'change', $item['change_type'] ) ),
			__( 'Basis', 'bee-monitor' )       => esc_html( Findings::term( 'basis', $item['basis'] ) ) . ( 'heuristic' === $item['basis'] ? ' — ' . esc_html__( 'an indicator for review, not proof of malware', 'bee-monitor' ) : '' ),
			__( 'Confidence', 'bee-monitor' )  => esc_html( Findings::term( 'confidence', $item['confidence'] ) ),
			__( 'Why flagged', 'bee-monitor' ) => esc_html( $item['reason'] ),
			__( 'Next steps', 'bee-monitor' )  => esc_html( Findings::next_steps( $item['rule'] ) ),
			__( 'First seen', 'bee-monitor' )  => esc_html( Notifier::local_time( $item['first_seen'] ) ),
			__( 'Last seen', 'bee-monitor' )   => esc_html( Notifier::local_time( $item['last_seen'] ) ) . ' (' . esc_html( sprintf( /* translators: %d: count. */ __( 'seen %d times', 'bee-monitor' ), (int) $item['occurrences'] ) ) . ')',
			__( 'Emailed', 'bee-monitor' )     => $item['notified_at'] ? esc_html( Notifier::local_time( $item['notified_at'] ) ) : esc_html__( 'Not yet', 'bee-monitor' ),
			__( 'Status', 'bee-monitor' )      => esc_html( Findings::term( 'status', $item['status'] ) ) . ( $item['resolution_note'] ? ' — ' . esc_html( $item['resolution_note'] ) : '' ),
		);
		foreach ( $rows as $label => $html ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . wp_kses( $html, self::allowed_html() ) . '</td></tr>';
		}
		echo '<tr><th scope="row">' . esc_html__( 'Evidence (redacted)', 'bee-monitor' ) . '</th><td>';
		$this->render_evidence( $item['evidence'] );
		echo '</td></tr></tbody></table>';

		echo '<h3>' . esc_html__( 'Update this finding', 'bee-monitor' ) . '</h3>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="bee-monitor-actions">';
		echo '<input type="hidden" name="action" value="bee_monitor_findings"><input type="hidden" name="ids[]" value="' . (int) $item['id'] . '"><input type="hidden" name="return" value="detail">';
		wp_nonce_field( 'bee_monitor_findings' );
		echo '<p><label for="bee-monitor-note">' . esc_html__( 'Note (optional)', 'bee-monitor' ) . '</label><br><input type="text" class="large-text" id="bee-monitor-note" name="note" maxlength="500"></p><p>';
		if ( Findings::is_file_rule( $item['rule'] ) ) {
			echo '<span class="description">' . esc_html__( 'Marking a file change as expected updates the baseline with the file as it is now, only if it still matches the hash in this finding.', 'bee-monitor' ) . '</span><br>';
		}
		submit_button( __( 'Mark expected', 'bee-monitor' ), 'primary', 'single_expected', false );
		echo ' ';
		submit_button( __( 'Mark resolved', 'bee-monitor' ), 'secondary', 'single_resolved', false );
		echo ' ';
		submit_button( __( 'Reopen', 'bee-monitor' ), 'secondary', 'single_open', false );
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
	 * Handle bulk or single finding actions.
	 */
	public function handle_findings() {
		$this->guard( 'bee_monitor_findings' );
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- verified in guard().
		$ids    = isset( $_POST['ids'] ) ? array_map( 'absint', (array) wp_unslash( $_POST['ids'] ) ) : array();
		$note   = isset( $_POST['note'] ) ? sanitize_text_field( wp_unslash( $_POST['note'] ) ) : '';
		$detail = isset( $_POST['return'] ) && 'detail' === sanitize_key( wp_unslash( $_POST['return'] ) );
		$action = '';
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

		echo '<h2>' . esc_html__( 'Accept all open file changes', 'bee-monitor' ) . '</h2>';
		echo '<p>' . esc_html__( 'Use after a deployment you performed. Every open file finding is marked expected and its current file is written to the baseline (only if unchanged since it was flagged). Heuristic findings are accepted too, so review them first.', 'bee-monitor' ) . '</p>';
		$this->baseline_form( 'accept_all', __( 'I reviewed the open file findings and the changes are legitimate.', 'bee-monitor' ), __( 'Accept all open file changes', 'bee-monitor' ) );

		echo '<h2>' . esc_html__( 'Rebuild baseline', 'bee-monitor' ) . '</h2>';
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
		echo '<div class="bee-monitor-card"><h2>' . esc_html__( 'Run a scan now', 'bee-monitor' ) . '</h2>';
		echo '<p>' . esc_html__( 'Runs the scan in short steps from this page. You can leave; WP-Cron will finish an unfinished scan.', 'bee-monitor' ) . '</p>';
		printf( '<p><button type="button" class="button button-primary" id="bee-monitor-run" data-autostart="%1$s">%2$s</button></p>', esc_attr( $autorun ? '1' : '' ), esc_html__( 'Run scan now', 'bee-monitor' ) );
		echo '<p id="bee-monitor-progress" role="status" aria-live="polite"></p></div>';

		echo '<div class="bee-monitor-card"><h2>' . esc_html__( 'Email delivery', 'bee-monitor' ) . '</h2>';
		/* translators: %s: recipients. */
		echo '<p>' . esc_html( sprintf( __( 'Alerts go to: %s', 'bee-monitor' ), implode( ', ', Settings::recipients() ) ) ) . '</p>';
		foreach ( array(
			'test'   => __( 'Send test email', 'bee-monitor' ),
			'sample' => __( 'Send sample alert', 'bee-monitor' ),
		) as $op => $label ) {
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="bee-monitor-inline">';
			echo '<input type="hidden" name="action" value="bee_monitor_email"><input type="hidden" name="op" value="' . esc_attr( $op ) . '">';
			wp_nonce_field( 'bee_monitor_email' );
			submit_button( $label, 'secondary', 'submit', false );
			echo '</form> ';
		}
		echo '<p class="description">' . esc_html__( 'The sample alert uses the real alert format with a clearly labeled fake finding.', 'bee-monitor' ) . '</p></div>';
		echo '</div>';

		echo '<h2>' . esc_html__( 'Status', 'bee-monitor' ) . '</h2><table class="widefat striped bee-monitor-detail"><tbody>';
		foreach ( $this->status_rows() as $label => $value ) {
			echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . esc_html( $value ) . '</td></tr>';
		}
		echo '</tbody></table>';

		echo '<h2>' . esc_html__( 'Email hooks', 'bee-monitor' ) . '</h2><p>' . esc_html__( 'Code hooked into WordPress email can change or suppress Bee Monitor alerts. SMTP plugins legitimately appear here.', 'bee-monitor' ) . '</p><ul class="bee-monitor-list">';
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

		echo '<h2>' . esc_html__( 'Recent Bee Monitor log', 'bee-monitor' ) . '</h2><table class="widefat striped"><thead><tr><th scope="col">' . esc_html__( 'Time', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Level', 'bee-monitor' ) . '</th><th scope="col">' . esc_html__( 'Message', 'bee-monitor' ) . '</th></tr></thead><tbody>';
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
			$scanner->start( 'manual' );
		}
		wp_send_json_success( $scanner->run_step( 'manual' ) );
	}

	// Shared rendering.

	/**
	 * Page header.
	 *
	 * @param string $title Title.
	 */
	private function header( $title ) {
		if ( ! current_user_can( self::capability() ) ) {
			wp_die( esc_html__( 'You do not have permission to manage Bee Monitor.', 'bee-monitor' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap bee-monitor"><h1>' . esc_html( $title ) . '</h1>';
	}

	/**
	 * Summary cards on the findings page.
	 */
	private function summary_cards() {
		$counts = Findings::open_counts();
		$last   = Storage::get( 'last_scan', array() );
		$meta   = Storage::get( 'baseline_meta', array() );
		echo '<div class="bee-monitor-cards">';
		echo '<div class="bee-monitor-card"><h2>' . esc_html__( 'Open findings', 'bee-monitor' ) . '</h2><p>';
		for ( $sev = Findings::CRITICAL; $sev >= Findings::LOW; $sev-- ) {
			$this->print_badge( $sev );
			echo ' <strong>' . esc_html( (string) (int) $counts[ $sev ] ) . '</strong> &nbsp; ';
		}
		echo '</p></div>';
		echo '<div class="bee-monitor-card"><h2>' . esc_html__( 'Last scan', 'bee-monitor' ) . '</h2><p>';
		if ( is_array( $last ) && ! empty( $last['finished'] ) ) {
			/* translators: 1: date, 2: mode, 3: files. */
			echo esc_html( sprintf( __( '%1$s · %2$s · %3$d files', 'bee-monitor' ), wp_date( 'Y-m-d H:i', (int) $last['finished'] ), $last['mode'], (int) $last['stats']['files'] ) );
		} else {
			esc_html_e( 'No scan has completed yet.', 'bee-monitor' );
		}
		echo '</p></div>';
		echo '<div class="bee-monitor-card"><h2>' . esc_html__( 'Baseline', 'bee-monitor' ) . '</h2><p>';
		echo esc_html( is_array( $meta ) && isset( $meta['status'] ) ? $meta['status'] : __( 'not created', 'bee-monitor' ) );
		echo ' · <a href="' . esc_url( self::page_url( 'bee-monitor-tools' ) ) . '">' . esc_html__( 'Run scan', 'bee-monitor' ) . '</a></p></div>';
		$problems = Notifier::health_problems();
		if ( $problems ) {
			echo '<div class="bee-monitor-card bee-monitor-card-warn"><h2>' . esc_html__( 'Monitor health', 'bee-monitor' ) . '</h2><ul>';
			foreach ( $problems as $problem ) {
				echo '<li>' . esc_html( $problem ) . '</li>';
			}
			echo '</ul></div>';
		}
		echo '</div>';
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
		);
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
		return '<span class="bee-monitor-sev bee-monitor-sev-' . esc_attr( Findings::severity_key( $severity ) ) . '">' . esc_html( Findings::severity_label( $severity ) ) . '</span>';
	}
}
