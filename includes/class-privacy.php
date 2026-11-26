<?php
/**
 * Privacy policy text and personal data export/erase for Bee Monitor.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * WordPress privacy tools integration.
 */
final class Privacy {

	/**
	 * Register hooks.
	 */
	public static function register() {
		add_action( 'admin_init', array( __CLASS__, 'policy_text' ) );
		add_filter( 'wp_privacy_personal_data_exporters', array( __CLASS__, 'register_exporter' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( __CLASS__, 'register_eraser' ) );
	}

	/**
	 * Suggested privacy policy text.
	 */
	public static function policy_text() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$content  = '<p>' . esc_html__( 'This site uses Bee Monitor to detect unauthorized changes and suspicious activity. For accounts with administrative capabilities, Bee Monitor stores the username, a masked email address, and roles so that changes to those accounts can be reported to site administrators.', 'bee-monitor' ) . '</p>';
		$content .= '<p>' . esc_html__( 'When login monitoring is enabled, Bee Monitor counts failed login attempts and stores only masked network addresses (for example 203.0.113.x) and keyed hashes of attempted usernames. For administrative accounts it stores keyed hashes of the networks they sign in from, to detect sign-ins from new networks.', 'bee-monitor' ) . '</p>';
		$content .= '<p>' . esc_html__( 'Security findings are kept until an administrator resolves them, then deleted after the retention period configured in Bee Monitor. This data is sent only to the site administrators configured to receive alerts, by email.', 'bee-monitor' ) . '</p>';
		wp_add_privacy_policy_content( 'Bee Monitor', wp_kses_post( $content ) );
	}

	/**
	 * Register the exporter.
	 *
	 * @param array $exporters Exporters.
	 * @return array
	 */
	public static function register_exporter( $exporters ) {
		$exporters['bee-monitor'] = array(
			'exporter_friendly_name' => __( 'Bee Monitor', 'bee-monitor' ),
			'callback'               => array( __CLASS__, 'export' ),
		);
		return $exporters;
	}

	/**
	 * Register the eraser.
	 *
	 * @param array $erasers Erasers.
	 * @return array
	 */
	public static function register_eraser( $erasers ) {
		$erasers['bee-monitor'] = array(
			'eraser_friendly_name' => __( 'Bee Monitor', 'bee-monitor' ),
			'callback'             => array( __CLASS__, 'erase' ),
		);
		return $erasers;
	}

	/**
	 * Export Bee Monitor data for a user.
	 *
	 * @param string $email Email address.
	 * @return array
	 */
	public static function export( $email ) {
		$user = get_user_by( 'email', $email );
		$data = array();
		if ( $user ) {
			$known = get_user_meta( $user->ID, Login_Monitor::META_KEY, true );
			if ( is_array( $known ) && $known ) {
				$data[] = array(
					'group_id'    => 'bee-monitor',
					'group_label' => __( 'Bee Monitor', 'bee-monitor' ),
					'item_id'     => 'bee-monitor-networks-' . $user->ID,
					'data'        => array(
						array(
							'name'  => __( 'Known sign-in networks (keyed hashes)', 'bee-monitor' ),
							'value' => implode( ', ', array_map( 'sanitize_text_field', $known ) ),
						),
					),
				);
			}
		}
		return array(
			'data' => $data,
			'done' => true,
		);
	}

	/**
	 * Erase Bee Monitor data for a user.
	 *
	 * @param string $email Email address.
	 * @return array
	 */
	public static function erase( $email ) {
		$user    = get_user_by( 'email', $email );
		$removed = false;
		if ( $user && get_user_meta( $user->ID, Login_Monitor::META_KEY, true ) ) {
			$removed = delete_user_meta( $user->ID, Login_Monitor::META_KEY );
		}
		return array(
			'items_removed'  => $removed,
			'items_retained' => false,
			'messages'       => array(),
			'done'           => true,
		);
	}
}
