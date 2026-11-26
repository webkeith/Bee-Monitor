<?php
/**
 * Records legitimate change context (updates, activations, admin edits) so
 * Bee Monitor can tell routine maintenance from unexplained changes.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Change context recorder.
 */
final class Context {

	const MAX_EVENTS = 300;
	const WATCHED    = array( 'siteurl', 'home', 'admin_email', 'users_can_register', 'default_role', 'template', 'stylesheet' );

	/**
	 * Register hooks.
	 */
	public static function register() {
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 10, 2 );
		add_action( '_core_updated_successfully', array( __CLASS__, 'on_core_update' ) );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin' ), 10, 1 );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_off' ), 10, 1 );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_plugin_deleted' ), 10, 1 );
		add_action( 'deleted_theme', array( __CLASS__, 'on_theme_deleted' ), 10, 1 );
		add_action( 'switch_theme', array( __CLASS__, 'on_switch_theme' ), 10, 0 );
		add_action( 'user_register', array( __CLASS__, 'on_user_register' ), 10, 1 );
		add_action( 'set_user_role', array( __CLASS__, 'on_set_role' ), 10, 1 );
		add_action( 'profile_update', array( __CLASS__, 'on_profile_update' ), 10, 1 );
		add_action( 'deleted_user', array( __CLASS__, 'on_user_deleted' ), 10, 1 );
		add_action( 'grant_super_admin', array( __CLASS__, 'on_user_register' ), 10, 1 );
		add_action( 'updated_option', array( __CLASS__, 'on_option' ), 10, 1 );
		add_action( 'wp_create_application_password', array( __CLASS__, 'on_app_password' ), 10, 2 );
	}

	/**
	 * Add an event.
	 *
	 * @param string $type   Event type.
	 * @param string $object_id Object identifier.
	 * @param string $detail    Short detail for the activity log.
	 */
	public static function add( $type, $object_id, $detail = '' ) {
		Activity::log( $type, (string) $object_id, $detail );
		$events   = self::events();
		$events[] = array(
			'type'   => $type,
			'object' => (string) $object_id,
			'actor'  => get_current_user_id(),
			'via'    => self::via(),
			'time'   => time(),
		);
		$cutoff   = time() - 7 * DAY_IN_SECONDS;
		$events   = array_values(
			array_filter(
				$events,
				function ( $e ) use ( $cutoff ) {
					return $e['time'] >= $cutoff;
				}
			)
		);
		Storage::set( 'context', array_slice( $events, -self::MAX_EVENTS ) );
	}

	/**
	 * All recorded events.
	 *
	 * @return array
	 */
	public static function events() {
		$events = Storage::get( 'context', array() );
		return is_array( $events ) ? $events : array();
	}

	/**
	 * Most recent event matching type/object since a time.
	 *
	 * @param string[] $types  Event types.
	 * @param string   $object_id Object or '*' for any.
	 * @param int      $since  Unix time.
	 * @return array|null
	 */
	public static function find( array $types, $object_id, $since ) {
		$found = null;
		foreach ( self::events() as $event ) {
			if ( $event['time'] < $since || ! in_array( $event['type'], $types, true ) ) {
				continue;
			}
			if ( '*' !== $object_id && (string) $event['object'] !== (string) $object_id ) {
				continue;
			}
			$found = $event;
		}
		return $found;
	}

	/**
	 * Human description of an event's actor.
	 *
	 * @param array|null $event Event.
	 * @return string
	 */
	public static function describe( $event ) {
		if ( ! $event ) {
			return __( 'No matching admin action, update, or activation was recorded by Bee Monitor.', 'bee-monitor' );
		}
		$user  = $event['actor'] ? get_userdata( $event['actor'] ) : false;
		$actor = $user ? $user->user_login : __( 'an unauthenticated or system process', 'bee-monitor' );
		/* translators: 1: event type, 2: username, 3: channel such as admin or WP-CLI, 4: date. */
		return sprintf( __( 'Recorded %1$s by %2$s via %3$s at %4$s.', 'bee-monitor' ), $event['type'], $actor, $event['via'], wp_date( 'Y-m-d H:i', $event['time'] ) );
	}

	/**
	 * Request channel.
	 *
	 * @return string
	 */
	public static function via() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return 'wp-cli';
		}
		if ( wp_doing_cron() ) {
			return 'cron';
		}
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			return 'rest';
		}
		if ( wp_doing_ajax() ) {
			return 'ajax';
		}
		return is_admin() ? 'admin' : 'front-end';
	}

	/**
	 * Upgrader completed.
	 *
	 * @param object $upgrader Upgrader.
	 * @param array  $extra    Hook extra.
	 */
	public static function on_upgrade( $upgrader, $extra ) {
		$type = isset( $extra['type'] ) ? $extra['type'] : '';
		$objs = array();
		if ( 'plugin' === $type ) {
			if ( ! empty( $extra['plugins'] ) ) {
				$objs = (array) $extra['plugins'];
			} elseif ( ! empty( $extra['plugin'] ) ) {
				$objs = array( $extra['plugin'] );
			}
		} elseif ( 'theme' === $type ) {
			if ( ! empty( $extra['themes'] ) ) {
				$objs = (array) $extra['themes'];
			} elseif ( ! empty( $extra['theme'] ) ) {
				$objs = array( $extra['theme'] );
			}
		} elseif ( 'translation' === $type ) {
			$objs = array( 'translations' );
		} elseif ( 'core' === $type ) {
			$objs = array( 'core' );
		}
		if ( empty( $objs ) && is_object( $upgrader ) && isset( $upgrader->result['destination_name'] ) ) {
			$objs = array( $upgrader->result['destination_name'] );
		}
		foreach ( $objs as $obj ) {
			$slug = strtok( (string) $obj, '/' );
			self::add( 'update_' . sanitize_key( $type ), $slug, isset( $extra['action'] ) ? sanitize_key( $extra['action'] ) : '' );
		}
		if ( $objs && ! wp_next_scheduled( Plugin::CRON_CONTINUE ) && ! Scanner::is_running() ) {
			wp_schedule_single_event( time() + 2 * MINUTE_IN_SECONDS, Plugin::CRON_SCAN );
		}
	}

	/**
	 * Core updated.
	 */
	public static function on_core_update() {
		self::add( 'update_core', 'core' );
	}

	/**
	 * Plugin activated.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public static function on_plugin( $plugin ) {
		self::add( 'activated_plugin', $plugin );
	}

	/**
	 * Plugin deactivated.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public static function on_plugin_off( $plugin ) {
		self::add( 'deactivated_plugin', $plugin );
	}

	/**
	 * Plugin deleted.
	 *
	 * @param string $plugin Plugin basename.
	 */
	public static function on_plugin_deleted( $plugin ) {
		self::add( 'update_plugin', strtok( (string) $plugin, '/' ) );
	}

	/**
	 * Theme deleted.
	 *
	 * @param string $stylesheet Theme folder.
	 */
	public static function on_theme_deleted( $stylesheet ) {
		self::add( 'update_theme', (string) $stylesheet );
	}

	/**
	 * Theme switched.
	 */
	public static function on_switch_theme() {
		self::add( 'switch_theme', get_stylesheet() );
	}

	/**
	 * User registered or granted super admin.
	 *
	 * @param int $user_id User ID.
	 */
	public static function on_user_register( $user_id ) {
		self::add( 'user_change', (int) $user_id );
	}

	/**
	 * Role set.
	 *
	 * @param int $user_id User ID.
	 */
	public static function on_set_role( $user_id ) {
		self::add( 'user_change', (int) $user_id );
	}

	/**
	 * User deleted.
	 *
	 * @param int $user_id User ID.
	 */
	public static function on_user_deleted( $user_id ) {
		self::add( 'user_deleted', (int) $user_id );
	}

	/**
	 * Profile updated.
	 *
	 * @param int $user_id User ID.
	 */
	public static function on_profile_update( $user_id ) {
		self::add( 'profile_update', (int) $user_id );
	}

	/**
	 * Application password created through WordPress, recorded by a keyed hash of its ID.
	 *
	 * @param int   $user_id User ID.
	 * @param array $item    The new application password item.
	 */
	public static function on_app_password( $user_id, $item = array() ) {
		$uuid = is_array( $item ) && ! empty( $item['uuid'] ) ? (string) $item['uuid'] : '';
		self::add( 'app_password', '' !== $uuid ? self::app_password_key( $uuid ) : 'user:' . (int) $user_id );
	}

	/**
	 * Keyed hash identifying an application password without storing its ID.
	 *
	 * @param string $uuid Application password UUID.
	 * @return string
	 */
	public static function app_password_key( $uuid ) {
		return substr( hash_hmac( 'sha256', (string) $uuid, Storage::mac_key() ), 0, 16 );
	}

	/**
	 * Watched option updated through the WordPress API.
	 *
	 * @param string $option Option name.
	 */
	public static function on_option( $option ) {
		if ( in_array( $option, self::WATCHED, true ) ) {
			self::add( 'option_update', $option );
		}
	}
}
