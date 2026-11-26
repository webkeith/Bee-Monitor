<?php
/**
 * Login activity monitoring using WordPress authentication hooks.
 *
 * Stores only counts, masked networks, and keyed hashes, never passwords or full IPs.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Login monitor.
 */
final class Login_Monitor {

	const WINDOW   = 15 * MINUTE_IN_SECONDS;
	const META_KEY = 'bee_monitor_known_networks';

	/**
	 * Register hooks.
	 */
	public static function register() {
		if ( ! Settings::value( 'enabled' ) || ! Settings::value( 'monitor_logins' ) ) {
			return;
		}
		add_action( 'wp_login_failed', array( __CLASS__, 'on_failed' ), 10, 1 );
		add_action( 'wp_login', array( __CLASS__, 'on_login' ), 10, 2 );
	}

	/**
	 * Client IP from REMOTE_ADDR. Proxy headers are not trusted because they can be forged.
	 *
	 * @return string
	 */
	private static function ip() {
		$ip = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}

	/**
	 * Count a failed login.
	 *
	 * @param string $username Attempted username.
	 */
	public static function on_failed( $username ) {
		$now    = time();
		$bucket = get_site_transient( 'bee_monitor_login_bucket' );
		if ( ! is_array( $bucket ) || empty( $bucket['start'] ) || $now - (int) $bucket['start'] > self::WINDOW ) {
			$bucket = array(
				'start'    => $now,
				'count'    => 0,
				'nets'     => array(),
				'names'    => array(),
				'existing' => 0,
				'reported' => false,
			);
		}
		++$bucket['count'];
		$net                    = Redactor::ip( self::ip() );
		$bucket['nets'][ $net ] = isset( $bucket['nets'][ $net ] ) ? $bucket['nets'][ $net ] + 1 : 1;
		$name_key               = substr( hash_hmac( 'sha256', strtolower( (string) $username ), Storage::mac_key() ), 0, 12 );
		if ( ! isset( $bucket['names'][ $name_key ] ) && count( $bucket['names'] ) < 200 ) {
			$bucket['names'][ $name_key ] = 1;
			if ( username_exists( $username ) || ( is_email( $username ) && email_exists( $username ) ) ) {
				++$bucket['existing'];
			}
		}
		if ( count( $bucket['nets'] ) > 50 ) {
			arsort( $bucket['nets'] );
			$bucket['nets'] = array_slice( $bucket['nets'], 0, 50, true );
		}

		$threshold = (int) Settings::value( 'failed_login_threshold' );
		if ( ! $bucket['reported'] && $bucket['count'] >= $threshold ) {
			$bucket['reported'] = true;
			arsort( $bucket['nets'] );
			Findings::record(
				array(
					'rule'        => 'failed_login_burst',
					'severity'    => $bucket['existing'] > 0 ? Findings::MEDIUM : Findings::LOW,
					'confidence'  => 'confirmed',
					'basis'       => 'event',
					'change_type' => 'detected',
					'subject'     => __( 'Login form', 'bee-monitor' ),
					/* translators: 1: number of failures, 2: minutes, 3: number of distinct usernames, 4: number targeting real accounts. */
					'reason'      => sprintf( __( '%1$d failed logins within %2$d minutes, using %3$d distinct usernames (%4$d matched existing accounts).', 'bee-monitor' ), $bucket['count'], self::WINDOW / MINUTE_IN_SECONDS, count( $bucket['names'] ), $bucket['existing'] ),
					'evidence'    => array(
						'failures'          => $bucket['count'],
						'top_networks'      => array_slice( $bucket['nets'], 0, 5, true ),
						'distinct_names'    => count( $bucket['names'] ),
						'existing_accounts' => $bucket['existing'],
					),
					'key'         => (string) $bucket['start'],
				)
			);
			set_site_transient( 'bee_monitor_login_bucket', $bucket, self::WINDOW );
			Notifier::dispatch( 'event' );
			return;
		}
		set_site_transient( 'bee_monitor_login_bucket', $bucket, self::WINDOW );
	}

	/**
	 * Check a successful privileged login.
	 *
	 * @param string   $login Username.
	 * @param \WP_User $user  User.
	 */
	public static function on_login( $login, $user ) {
		if ( ! ( $user instanceof \WP_User ) ) {
			return;
		}
		$privileged = false;
		foreach ( Site_Monitor::DANGEROUS_CAPS as $cap ) {
			if ( $user->has_cap( $cap ) ) {
				$privileged = true;
				break;
			}
		}
		if ( ! $privileged ) {
			return;
		}
		$net   = Redactor::ip( self::ip() );
		$key   = substr( hash_hmac( 'sha256', $net, Storage::mac_key() ), 0, 16 );
		$known = get_user_meta( $user->ID, self::META_KEY, true );
		$known = is_array( $known ) ? $known : array();
		if ( in_array( $key, $known, true ) ) {
			return;
		}
		$first   = empty( $known );
		$known[] = $key;
		update_user_meta( $user->ID, self::META_KEY, array_slice( $known, -20 ) );
		if ( $first ) {
			return;
		}
		Findings::record(
			array(
				'rule'        => 'privileged_login_new_net',
				'severity'    => Findings::LOW,
				'confidence'  => 'medium',
				'basis'       => 'event',
				'change_type' => 'detected',
				/* translators: 1: username, 2: user ID. */
				'subject'     => sprintf( __( 'User %1$s (ID %2$d)', 'bee-monitor' ), $user->user_login, $user->ID ),
				/* translators: %s: masked network. */
				'reason'      => sprintf( __( 'A user with powerful capabilities signed in from a network not seen before for this account (%s).', 'bee-monitor' ), $net ),
				'evidence'    => array(
					'user_id' => (int) $user->ID,
					'network' => $net,
				),
				'key'         => $key,
			)
		);
	}
}
