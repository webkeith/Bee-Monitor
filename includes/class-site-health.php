<?php
/**
 * Bee Monitor tests in Tools > Site Health.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Site Health integration.
 */
final class Site_Health {

	/**
	 * Register hooks.
	 */
	public static function register() {
		add_filter( 'site_status_tests', array( __CLASS__, 'tests' ) );
	}

	/**
	 * Add direct tests.
	 *
	 * @param array $tests Tests.
	 * @return array
	 */
	public static function tests( $tests ) {
		$tests['direct']['bee_monitor_scans']    = array(
			'label' => __( 'Bee Monitor scans', 'bee-monitor' ),
			'test'  => array( __CLASS__, 'test_scans' ),
		);
		$tests['direct']['bee_monitor_findings'] = array(
			'label' => __( 'Bee Monitor findings', 'bee-monitor' ),
			'test'  => array( __CLASS__, 'test_findings' ),
		);
		$tests['direct']['bee_monitor_email']    = array(
			'label' => __( 'Bee Monitor email delivery', 'bee-monitor' ),
			'test'  => array( __CLASS__, 'test_email' ),
		);
		return $tests;
	}

	/**
	 * Result array.
	 *
	 * @param string $test        Test ID.
	 * @param string $status      good|recommended|critical.
	 * @param string $label       Label.
	 * @param string $description Description.
	 * @param string $page        Bee Monitor page for the action link.
	 * @return array
	 */
	private static function result( $test, $status, $label, $description, $page = 'bee-monitor' ) {
		return array(
			'label'       => $label,
			'status'      => $status,
			'badge'       => array(
				'label' => __( 'Security', 'bee-monitor' ),
				'color' => 'good' === $status ? 'blue' : 'red',
			),
			'description' => '<p>' . esc_html( $description ) . '</p>',
			'actions'     => sprintf( '<p><a href="%1$s">%2$s</a></p>', esc_url( Admin::page_url( $page ) ), esc_html__( 'Open Bee Monitor', 'bee-monitor' ) ),
			'test'        => $test,
		);
	}

	/**
	 * Scans are running and the baseline is valid.
	 *
	 * @return array
	 */
	public static function test_scans() {
		$test = 'bee_monitor_scans';
		if ( ! Settings::value( 'enabled' ) ) {
			return self::result( $test, 'recommended', __( 'Bee Monitor monitoring is disabled', 'bee-monitor' ), __( 'Scheduled scans and alerts are turned off in Bee Monitor settings.', 'bee-monitor' ), 'bee-monitor-settings' );
		}
		$meta = Storage::get( 'baseline_meta', array() );
		if ( ! is_array( $meta ) || ( isset( $meta['status'] ) && 'valid' !== $meta['status'] ) ) {
			return self::result( $test, 'critical', __( 'The Bee Monitor baseline is not valid', 'bee-monitor' ), __( 'File changes cannot be detected reliably until the baseline is created or rebuilt.', 'bee-monitor' ), 'bee-monitor-baseline' );
		}
		$last = Storage::get( 'last_scan', array() );
		if ( ! is_array( $last ) || empty( $last['finished'] ) ) {
			return self::result( $test, 'recommended', __( 'Bee Monitor has not completed a scan yet', 'bee-monitor' ), __( 'Run a scan from Bee Monitor > Tools & Status, or wait for the scheduled scan.', 'bee-monitor' ), 'bee-monitor-tools' );
		}
		if ( time() - (int) $last['finished'] > 3 * Settings::interval_seconds() + HOUR_IN_SECONDS ) {
			return self::result( $test, 'critical', __( 'Bee Monitor scans are overdue', 'bee-monitor' ), __( 'The last completed scan is older than expected, so WP-Cron may not be running. Configure a server cron job or check for errors under Tools & Status.', 'bee-monitor' ), 'bee-monitor-tools' );
		}
		/* translators: %s: date. */
		return self::result( $test, 'good', __( 'Bee Monitor scans are running', 'bee-monitor' ), sprintf( __( 'The last scan completed at %s and the baseline is valid.', 'bee-monitor' ), wp_date( 'Y-m-d H:i', (int) $last['finished'] ) ) );
	}

	/**
	 * No open critical or high findings.
	 *
	 * @return array
	 */
	public static function test_findings() {
		$counts = Findings::open_counts();
		$urgent = $counts[ Findings::CRITICAL ] + $counts[ Findings::HIGH ];
		if ( $urgent ) {
			/* translators: 1: critical count, 2: high count. */
			return self::result( 'bee_monitor_findings', 'critical', __( 'Bee Monitor has open high-severity findings', 'bee-monitor' ), sprintf( __( '%1$d critical and %2$d high-severity findings need review.', 'bee-monitor' ), $counts[ Findings::CRITICAL ], $counts[ Findings::HIGH ] ) );
		}
		return self::result( 'bee_monitor_findings', 'good', __( 'No high-severity Bee Monitor findings are open', 'bee-monitor' ), __( 'There are no open critical or high-severity findings.', 'bee-monitor' ) );
	}

	/**
	 * The last alert email was sent successfully.
	 *
	 * @return array
	 */
	public static function test_email() {
		$mail = Storage::get( 'mail_status', array() );
		if ( is_array( $mail ) && ! empty( $mail['time'] ) && empty( $mail['ok'] ) ) {
			return self::result( 'bee_monitor_email', 'critical', __( 'Bee Monitor alert email failed', 'bee-monitor' ), __( 'The last Bee Monitor email could not be sent, so you may miss alerts. Send a test email and check your SMTP or email plugin.', 'bee-monitor' ), 'bee-monitor-tools' );
		}
		return self::result( 'bee_monitor_email', 'good', __( 'Bee Monitor can send email', 'bee-monitor' ), __( 'No Bee Monitor email delivery failures were recorded.', 'bee-monitor' ), 'bee-monitor-tools' );
	}
}
