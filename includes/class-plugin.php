<?php
/**
 * Plugin bootstrap, lifecycle, and scheduling.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Main plugin class.
 */
final class Plugin {

	const CRON_SCAN     = 'bee_monitor_scheduled_scan';
	const CRON_CONTINUE = 'bee_monitor_continue_scan';
	const CRON_DIGEST   = 'bee_monitor_digest';

	/**
	 * Instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Get the instance.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Register hooks.
	 */
	private function __construct() {
		if ( is_multisite() && ! self::network_active() ) {
			add_action( 'admin_notices', array( __CLASS__, 'multisite_notice' ) );
			return;
		}

		Storage::maybe_upgrade();
		add_filter( 'cron_schedules', array( __CLASS__, 'cron_schedules' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedules' ), 20 );
		add_action( self::CRON_SCAN, array( __CLASS__, 'cron_scan' ) );
		add_action( self::CRON_CONTINUE, array( __CLASS__, 'cron_continue' ) );
		add_action( self::CRON_DIGEST, array( Notifier::class, 'digest' ) );

		Privacy::register();
		Context::register();
		Login_Monitor::register();
		if ( is_admin() ) {
			new Admin();
		}
	}

	/**
	 * Whether Bee Monitor is network-activated.
	 *
	 * @return bool
	 */
	public static function network_active() {
		if ( ! is_multisite() ) {
			return true;
		}
		$plugins = (array) get_site_option( 'active_sitewide_plugins', array() );
		return isset( $plugins[ plugin_basename( BEE_MONITOR_FILE ) ] );
	}

	/**
	 * Notice shown if a multisite install activates Bee Monitor per site.
	 */
	public static function multisite_notice() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p>' . esc_html__( 'Bee Monitor monitors files shared by the whole network, so it only runs when network-activated. Activate it from Network Admin > Plugins.', 'bee-monitor' ) . '</p></div>';
	}

	/**
	 * Activation.
	 *
	 * @param bool $network_wide Network-wide activation.
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() && ! $network_wide ) {
			wp_die(
				esc_html__( 'Bee Monitor must be network-activated on multisite because it monitors files shared by every site. Activate it from Network Admin > Plugins.', 'bee-monitor' ),
				esc_html__( 'Bee Monitor', 'bee-monitor' ),
				array( 'back_link' => true )
			);
		}
		Storage::install();
		if ( false === Storage::get( 'settings', false ) ) {
			Settings::save( Settings::defaults() );
		}
		Storage::delete( 'lock' );
		Storage::remember_urls();
		self::schedule( true );
		if ( ! wp_next_scheduled( self::CRON_CONTINUE ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, self::CRON_SCAN );
		}
		Storage::log( 'info', 'Bee Monitor activated', array( 'user' => get_current_user_id() ) );
	}

	/**
	 * Deactivation: clear events and send a notice, since disabling the monitor is a tamper signal.
	 */
	public static function deactivate() {
		self::clear_schedules();
		$user = wp_get_current_user();
		$who  = $user && $user->exists() ? $user->user_login : __( 'an unknown process', 'bee-monitor' );
		Storage::log( 'warning', 'Bee Monitor deactivated', array( 'user' => get_current_user_id() ) );
		$to = Settings::recipients();
		if ( $to && Settings::value( 'enabled' ) ) {
			$name = is_multisite() ? get_network()->site_name : get_bloginfo( 'name' );
			wp_mail(
				$to,
				/* translators: %s: site name. */
				sprintf( __( '[Bee Monitor] Monitoring was deactivated on %s', 'bee-monitor' ), wp_specialchars_decode( (string) $name, ENT_QUOTES ) ),
				/* translators: 1: username, 2: date. */
				sprintf( __( "Bee Monitor was deactivated by %1\$s at %2\$s.\n\nIf you did not expect this, check the site for other changes: attackers often disable security plugins first.\n\n--\nSent by Bee Monitor", 'bee-monitor' ), $who, wp_date( 'Y-m-d H:i T' ) )
			);
		}
	}

	/**
	 * Remove all Bee Monitor cron events.
	 */
	public static function clear_schedules() {
		foreach ( array( self::CRON_SCAN, self::CRON_CONTINUE, self::CRON_DIGEST ) as $hook ) {
			wp_clear_scheduled_hook( $hook );
		}
	}

	/**
	 * Custom schedule.
	 *
	 * @param array $schedules Schedules.
	 * @return array
	 */
	public static function cron_schedules( $schedules ) {
		$schedules['bee_monitor_15min'] = array(
			'interval' => 15 * MINUTE_IN_SECONDS,
			'display'  => did_action( 'init' ) ? __( 'Every 15 minutes (Bee Monitor)', 'bee-monitor' ) : 'Every 15 minutes (Bee Monitor)',
		);
		return $schedules;
	}

	/**
	 * Keep recurring events in line with settings (self-healing if removed).
	 */
	public static function ensure_schedules() {
		if ( ! is_main_site() ) {
			return;
		}
		self::schedule( false );
	}

	/**
	 * Schedule or reschedule events.
	 *
	 * @param bool $force Reschedule even when present.
	 */
	public static function schedule( $force ) {
		$enabled = (bool) Settings::value( 'enabled' );
		$jobs    = array(
			self::CRON_SCAN   => $enabled ? (string) Settings::value( 'scan_frequency' ) : '',
			self::CRON_DIGEST => ( $enabled && 'off' !== Settings::value( 'digest_frequency' ) ) ? (string) Settings::value( 'digest_frequency' ) : '',
		);
		foreach ( $jobs as $hook => $recurrence ) {
			$event = wp_get_scheduled_event( $hook );
			if ( '' === $recurrence ) {
				if ( $event ) {
					wp_clear_scheduled_hook( $hook );
				}
				continue;
			}
			if ( $event && ! $force && $event->schedule === $recurrence ) {
				continue;
			}
			wp_clear_scheduled_hook( $hook );
			$offset = self::CRON_DIGEST === $hook ? HOUR_IN_SECONDS : 5 * MINUTE_IN_SECONDS;
			wp_schedule_event( time() + $offset, $recurrence, $hook );
		}
	}

	/**
	 * Scheduled scan.
	 */
	public static function cron_scan() {
		if ( ! Settings::value( 'enabled' ) ) {
			return;
		}
		$scanner = new Scanner();
		$state   = Scanner::state();
		$stale   = ! empty( $state['touched'] ) && time() - (int) $state['touched'] > 30 * MINUTE_IN_SECONDS;
		if ( ! Scanner::is_running() || $stale ) {
			if ( $stale ) {
				Storage::log( 'warning', 'Bee Monitor resumed an interrupted scan', array( 'scan' => isset( $state['id'] ) ? (int) $state['id'] : 0 ) );
			} else {
				$scanner->start( 'cron' );
			}
		}
		$scanner->run_step( 'cron' );
	}

	/**
	 * Continuation step.
	 */
	public static function cron_continue() {
		if ( Settings::value( 'enabled' ) && Scanner::is_running() ) {
			( new Scanner() )->run_step( 'cron' );
		}
	}

	/**
	 * Ping the external heartbeat URL after a completed scan.
	 */
	public static function heartbeat() {
		$url = (string) Settings::value( 'heartbeat_url' );
		if ( '' === $url ) {
			return;
		}
		$response = wp_safe_remote_get(
			$url,
			array(
				'timeout'     => 5,
				'redirection' => 2,
				'user-agent'  => 'Bee Monitor/' . BEE_MONITOR_VERSION,
			)
		);
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
		Storage::set(
			'heartbeat_status',
			array(
				'time'  => time(),
				'code'  => $code,
				'error' => is_wp_error( $response ) ? substr( $response->get_error_message(), 0, 200 ) : '',
			)
		);
		if ( $code < 200 || $code >= 300 ) {
			Storage::log( 'warning', 'Bee Monitor heartbeat ping failed', array( 'code' => $code ) );
		}
	}
}
