<?php
/**
 * Resumable, time-budgeted file scanner.
 *
 * Modes:
 * - baseline: records hashes of monitored files and reports pre-existing indicators.
 * - scan:     compares against the baseline.
 * - degraded: baseline unavailable; runs location, checksum, and heuristic checks only.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * File scanner.
 */
final class Scanner {

	const BATCH = 150;

	/**
	 * Scan state.
	 *
	 * @var array
	 */
	private $state = array();

	/**
	 * Unix deadline for this step.
	 *
	 * @var float
	 */
	private $deadline = 0.0;

	/**
	 * Core checksums (relative path => md5), or null.
	 *
	 * @var array|null
	 */
	private $checksums = null;

	/**
	 * Exclusion patterns.
	 *
	 * @var string[]
	 */
	private $exclusions = array();

	/**
	 * Extra executable extensions.
	 *
	 * @var string[]
	 */
	private $extra_ext = array();

	/**
	 * Installed plugin versions by folder, or null until loaded.
	 *
	 * @var array|null
	 */
	private $plugin_versions = null;

	/**
	 * Official plugin checksums by folder for this step (array, or null when unavailable).
	 *
	 * @var array
	 */
	private $plugin_sums = array();

	/**
	 * Remote checksum lookups made in this step.
	 *
	 * @var int
	 */
	private $fetches = 0;

	/**
	 * Last time the cancel flag was checked.
	 *
	 * @var float
	 */
	private $cancel_checked = 0.0;

	/**
	 * Whether a cancel request has been seen in this step.
	 *
	 * @var bool
	 */
	private $cancel_seen = false;

	const MAX_FETCHES_PER_STEP = 3;

	/**
	 * Current scan state.
	 *
	 * @return array
	 */
	public static function state() {
		$state = Storage::get( 'scan_state', array() );
		return is_array( $state ) ? $state : array();
	}

	/**
	 * Whether a scan is in progress.
	 *
	 * @return bool
	 */
	public static function is_running() {
		$state = self::state();
		return ! empty( $state['phase'] ) && 'done' !== $state['phase'];
	}

	/**
	 * Start a scan.
	 *
	 * @param string $trigger    cron|manual|activation.
	 * @param bool   $rebuild    Force a new baseline.
	 * @param bool   $full       Re-hash every file and re-verify checksums now (otherwise once a day).
	 * @param bool   $remote     Check public pages in this scan (when remote checks are enabled).
	 * @return bool False if a scan is already running.
	 */
	public function start( $trigger, $rebuild = false, $full = false, $remote = false ) {
		if ( self::is_running() && ! $rebuild ) {
			return false;
		}
		if ( ! Storage::tables_exist() ) {
			Storage::install();
			if ( ! Storage::tables_exist() ) {
				return false;
			}
		}

		$meta = Storage::get( 'baseline_meta', array() );
		$meta = is_array( $meta ) ? $meta : array();
		$rows = Storage::baseline_count();
		$mode = 'scan';
		$note = '';
		$skip = false;

		if ( $rebuild ) {
			$mode = 'baseline';
			Storage::clear_baseline();
			Storage::set(
				'baseline_meta',
				array(
					'status'  => 'building',
					'started' => time(),
				)
			);
		} elseif ( isset( $meta['status'] ) && 'building' === $meta['status'] ) {
			$mode = 'baseline';
			Storage::clear_baseline();
		} elseif ( empty( $meta ) && 0 === $rows ) {
			$mode = 'baseline';
			Storage::set(
				'baseline_meta',
				array(
					'status'  => 'building',
					'started' => time(),
				)
			);
		} elseif ( empty( $meta ) || 0 === $rows ) {
			$mode = 'degraded';
			$note = empty( $meta ) ? 'meta_missing' : 'rows_missing';
			Findings::record(
				array(
					'rule'        => 'baseline_missing',
					'severity'    => Findings::CRITICAL,
					'confidence'  => 'confirmed',
					'basis'       => 'monitor',
					'change_type' => 'detected',
					'subject'     => __( 'Bee Monitor baseline', 'bee-monitor' ),
					'reason'      => empty( $meta )
						? __( 'Baseline records exist but the baseline metadata is missing. It may have been deleted to hide changes.', 'bee-monitor' )
						: __( 'Baseline metadata exists but the baseline table is empty. It may have been emptied to hide changes.', 'bee-monitor' ),
					'evidence'    => array( 'rows' => $rows ),
					'key'         => $note . '|' . gmdate( 'Y-m-d' ),
				)
			);
		} elseif ( isset( $meta['key_fp'] ) && Storage::mac_key_fingerprint() !== $meta['key_fp'] ) {
			$skip = true;
			Findings::record(
				array(
					'rule'        => 'baseline_key_changed',
					'severity'    => Findings::HIGH,
					'confidence'  => 'confirmed',
					'basis'       => 'monitor',
					'change_type' => 'changed',
					'subject'     => __( 'Bee Monitor baseline signing key', 'bee-monitor' ),
					'reason'      => __( 'The key used to sign the baseline changed, so record signatures cannot be verified. File hashes are still compared.', 'bee-monitor' ),
					'key'         => (string) $meta['key_fp'],
				)
			);
		}

		$last_full = isset( $meta['last_full_hash'] ) ? (int) $meta['last_full_hash'] : 0;
		$id        = (int) Storage::get( 'scan_counter', 0 ) + 1;
		Storage::set( 'scan_counter', $id );

		$last = Storage::get( 'last_scan', array() );
		$prev = is_array( $last ) && ! empty( $last['started'] ) ? (int) $last['started'] : 0;

		$roots = Paths::roots( (bool) Settings::value( 'scan_parent_dir' ) );
		$stack = array();
		foreach ( $roots as $i => $root ) {
			$stack[] = array(
				'dir'    => $root['abs'],
				'offset' => 0,
				'root'   => $i,
			);
		}

		Storage::delete( 'cancel_scan' );
		$this->state = array(
			'id'          => $id,
			'estimate'    => 'baseline' === $mode ? 0 : $rows,
			'remote_now'  => (bool) $remote,
			'mode'        => $mode,
			'note'        => $note,
			'skip_mac'    => $skip,
			'full_hash'   => 'scan' === $mode && ( $full || ( time() - $last_full ) > DAY_IN_SECONDS ),
			'phase'       => 'walk',
			'roots'       => $roots,
			'stack'       => $stack,
			'cursor'      => 0,
			'trigger'     => $trigger,
			'actor'       => get_current_user_id(),
			'started'     => time(),
			'touched'     => time(),
			'prev_start'  => $prev,
			'stats'       => array(
				'dirs'       => 0,
				'files'      => 0,
				'hashed'     => 0,
				'inspected'  => 0,
				'added'      => 0,
				'modified'   => 0,
				'deleted'    => 0,
				'unreadable' => 0,
				'too_large'  => 0,
				'symlinks'   => 0,
				'findings'   => 0,
			),
			'unreadable'  => array(),
			'updates'     => array(),
			'errors'      => array(),
			'tamper_hits' => 0,
		);
		$this->save();
		Storage::log(
			'info',
			sprintf( 'Bee Monitor scan #%d started (%s, %s%s)', $id, $mode, $trigger, $full ? ', full' : '' ),
			array( 'full_hash' => $this->state['full_hash'] )
		);
		return true;
	}

	/**
	 * Run one time-budgeted step.
	 *
	 * @param string $trigger cron|manual.
	 * @return array Progress.
	 */
	public function run_step( $trigger ) {
		$token = Storage::acquire_lock();
		if ( false === $token ) {
			return array(
				'done'    => false,
				'locked'  => true,
				'phase'   => '',
				'stats'   => array(),
				'message' => __( 'Another Bee Monitor scan step is running. Waiting…', 'bee-monitor' ),
			);
		}

		$fresh       = Storage::get_fresh( 'scan_state', array() );
		$this->state = is_array( $fresh ) ? $fresh : array();
		if ( empty( $this->state['phase'] ) || 'done' === $this->state['phase'] ) {
			Storage::release_lock( $token );
			return $this->progress();
		}

		wp_raise_memory_limit( 'bee_monitor' );
		$budget = (int) Settings::value( 'time_budget' );
		if ( 'manual' === $trigger ) {
			$budget = min( $budget, 8 );
		}
		$max_exec = (int) ini_get( 'max_execution_time' );
		if ( $max_exec > 0 ) {
			$budget = max( 3, min( $budget, $max_exec - 5 ) );
		}
		$this->deadline   = microtime( true ) + $budget;
		$this->exclusions = Settings::exclusions();
		$this->extra_ext  = array_filter( array_map( 'trim', explode( ',', (string) Settings::value( 'extra_extensions' ) ) ) );
		$this->load_checksums();

		try {
			while ( 'done' !== $this->state['phase'] && ! $this->out_of_time() ) {
				switch ( $this->state['phase'] ) {
					case 'walk':
						$this->walk();
						break;
					case 'deleted':
						$this->deleted();
						break;
					case 'core':
						$this->core_missing();
						break;
					case 'site':
						Site_Monitor::run( $this->state );
						$this->state['phase'] = $this->remote_due() ? 'remote' : 'finalize';
						break;
					case 'remote':
						$this->remote_step();
						break;
					case 'finalize':
						$this->finalize();
						break;
					default:
						$this->state['phase'] = 'done';
				}
			}
		} catch ( \Throwable $e ) {
			$this->state['errors'][] = substr( $e->getMessage(), 0, 200 );
			Storage::log( 'error', 'Bee Monitor scan step failed: ' . substr( $e->getMessage(), 0, 150 ), array( 'phase' => $this->state['phase'] ) );
			if ( count( $this->state['errors'] ) > 5 ) {
				$this->state['phase'] = 'finalize';
			}
		}

		if ( 'done' !== $this->state['phase'] && $this->cancel_requested( true ) ) {
			$this->apply_cancel();
		}
		$this->state['touched'] = time();
		$this->save();
		Storage::release_lock( $token );

		if ( 'done' !== $this->state['phase'] && 'cron' === $trigger && ! wp_next_scheduled( Plugin::CRON_CONTINUE ) ) {
			wp_schedule_single_event( time() + 15, Plugin::CRON_CONTINUE );
		}
		return $this->progress();
	}

	/**
	 * Progress summary.
	 *
	 * @return array
	 */
	public function progress() {
		$s     = $this->state ? $this->state : self::state();
		$phase = isset( $s['phase'] ) ? $s['phase'] : '';
		$stats = isset( $s['stats'] ) ? $s['stats'] : array();
		$map   = array(
			'deleted'  => 88,
			'core'     => 91,
			'site'     => 93,
			'remote'   => 96,
			'finalize' => 98,
			'done'     => 100,
		);
		$pct   = null;
		if ( 'walk' === $phase ) {
			$pct = ! empty( $s['estimate'] ) ? min( 85, (int) floor( ( isset( $stats['files'] ) ? $stats['files'] : 0 ) / max( 1, (int) $s['estimate'] ) * 85 ) ) : null;
		} elseif ( isset( $map[ $phase ] ) ) {
			$pct = $map[ $phase ];
		}
		$labels = array(
			'walk'     => __( 'Checking files', 'bee-monitor' ),
			'deleted'  => __( 'Checking for deleted files', 'bee-monitor' ),
			'core'     => __( 'Verifying WordPress core', 'bee-monitor' ),
			'site'     => __( 'Checking users, settings, and configuration', 'bee-monitor' ),
			'remote'   => __( 'Checking public pages', 'bee-monitor' ),
			'finalize' => __( 'Finishing up', 'bee-monitor' ),
			'done'     => __( 'Done', 'bee-monitor' ),
		);
		return array(
			'done'        => '' === $phase || 'done' === $phase,
			'cancelled'   => ! empty( $s['cancelled'] ),
			'locked'      => false,
			'phase'       => $phase,
			'phase_label' => isset( $labels[ $phase ] ) ? $labels[ $phase ] : '',
			'percent'     => $pct,
			'mode'        => isset( $s['mode'] ) ? $s['mode'] : '',
			'stats'       => $stats,
			'message'     => '',
		);
	}

	/**
	 * Persist state.
	 */
	private function save() {
		Storage::set( 'scan_state', $this->state );
	}

	/**
	 * Whether the step budget is spent.
	 *
	 * @return bool
	 */
	private function out_of_time() {
		return microtime( true ) >= $this->deadline || $this->cancel_requested( false );
	}

	/**
	 * Whether remote page checks should run in this scan.
	 *
	 * @return bool
	 */
	private function remote_due() {
		if ( ! Settings::value( 'remote_checks' ) ) {
			return false;
		}
		return ! empty( $this->state['remote_now'] ) || time() - (int) Storage::get( 'last_remote_check', 0 ) > DAY_IN_SECONDS;
	}

	/**
	 * Check one public page per call, then settle remote findings.
	 */
	private function remote_step() {
		if ( ! isset( $this->state['remote_queue'] ) ) {
			$this->state['remote_queue'] = Remote::queue();
			$this->state['remote_found'] = array();
			$this->state['remote_total'] = count( $this->state['remote_queue'] );
		}
		if ( $this->state['remote_queue'] ) {
			$url                         = array_shift( $this->state['remote_queue'] );
			$home                        = untrailingslashit( $url ) === untrailingslashit( home_url( '/' ) );
			$this->state['remote_found'] = array_merge( $this->state['remote_found'], Remote::check( $url, $home ) );
			if ( ! isset( $this->state['stats']['pages_checked'] ) ) {
				$this->state['stats']['pages_checked'] = 0;
			}
			++$this->state['stats']['pages_checked'];
			return;
		}
		Remote::settle( $this->state['remote_found'] );
		Storage::set( 'last_remote_check', time() );
		$this->state['phase'] = 'finalize';
	}

	/**
	 * Request cancellation of the running scan. Applied immediately when no step is running,
	 * otherwise by the running step within about a second.
	 *
	 * @return bool False when no scan is running.
	 */
	public static function request_cancel() {
		$state = self::state();
		if ( ! self::is_running() ) {
			return false;
		}
		Storage::set( 'cancel_scan', (int) $state['id'] );
		wp_clear_scheduled_hook( Plugin::CRON_CONTINUE );
		$token = Storage::acquire_lock();
		if ( false !== $token ) {
			$scanner        = new self();
			$scanner->state = self::state();
			$scanner->apply_cancel();
			Storage::release_lock( $token );
		}
		return true;
	}

	/**
	 * Whether cancellation was requested for this scan (read from the database, not the request cache).
	 *
	 * @param bool $force Check now instead of at most once per second.
	 * @return bool
	 */
	private function cancel_requested( $force ) {
		if ( $this->cancel_seen || ( ! $force && microtime( true ) - $this->cancel_checked < 1 ) ) {
			return $this->cancel_seen;
		}
		$this->cancel_checked = microtime( true );
		$this->cancel_seen    = ! empty( $this->state['id'] ) && (int) Storage::get_fresh( 'cancel_scan', 0 ) === (int) $this->state['id'];
		return $this->cancel_seen;
	}

	/**
	 * Stop the scan. The baseline and last completed scan summary are left untouched;
	 * an interrupted baseline build restarts on the next scan.
	 */
	private function apply_cancel() {
		$this->state['phase']     = 'done';
		$this->state['cancelled'] = true;
		$this->state['touched']   = time();
		$this->save();
		Storage::delete( 'cancel_scan' );
		Storage::log( 'warning', sprintf( 'Bee Monitor scan #%d cancelled', (int) $this->state['id'] ), array( 'user' => get_current_user_id() ) );
		Activity::log( 'scan_cancelled', sprintf( 'Scan #%d', (int) $this->state['id'] ) );
	}

	/**
	 * Installed plugin versions keyed by folder (single-file plugins are skipped).
	 *
	 * @return array
	 */
	private function plugin_versions() {
		if ( null === $this->plugin_versions ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
			$this->plugin_versions = array();
			foreach ( get_plugins() as $file => $data ) {
				$dir = dirname( $file );
				if ( '.' !== $dir && ! empty( $data['Version'] ) ) {
					$this->plugin_versions[ $dir ] = (string) $data['Version'];
				}
			}
		}
		return $this->plugin_versions;
	}

	/**
	 * Official WordPress.org checksums for an installed plugin (opt-in, cached for a day).
	 *
	 * @param string $slug Plugin folder.
	 * @return array|null file => [ md5 => [], sha256 => [] ], or null when unavailable.
	 */
	private function plugin_checksums( $slug ) {
		if ( array_key_exists( $slug, $this->plugin_sums ) ) {
			return $this->plugin_sums[ $slug ];
		}
		$versions = $this->plugin_versions();
		$version  = isset( $versions[ $slug ] ) ? $versions[ $slug ] : '';
		if ( ! preg_match( '/^[a-z0-9][a-z0-9_-]*$/', $slug ) || ! preg_match( '/^[0-9A-Za-z.+_-]{1,40}$/', $version ) ) {
			$this->plugin_sums[ $slug ] = null;
			return null;
		}
		$key    = 'bee_monitor_pcs_' . md5( $slug . '|' . $version );
		$cached = get_site_transient( $key );
		if ( false !== $cached ) {
			$this->plugin_sums[ $slug ] = is_array( $cached ) ? $cached : null;
			return $this->plugin_sums[ $slug ];
		}
		if ( $this->fetches >= self::MAX_FETCHES_PER_STEP ) {
			$this->plugin_sums[ $slug ] = null;
			return null;
		}
		++$this->fetches;
		$response = wp_safe_remote_get(
			'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json',
			array(
				'timeout'    => 10,
				'user-agent' => 'Bee Monitor/' . BEE_MONITOR_VERSION,
			)
		);
		$code     = is_wp_error( $response ) ? 0 : (int) wp_remote_retrieve_response_code( $response );
		if ( 404 === $code ) {
			set_site_transient( $key, 'none', DAY_IN_SECONDS );
			$this->plugin_sums[ $slug ] = null;
			return null;
		}
		$data  = 200 === $code ? json_decode( (string) wp_remote_retrieve_body( $response ), true ) : null;
		$clean = array();
		if ( is_array( $data ) && ! empty( $data['files'] ) && is_array( $data['files'] ) ) {
			foreach ( $data['files'] as $file => $entry ) {
				$entry          = is_array( $entry ) ? $entry : array( 'md5' => $entry );
				$clean[ $file ] = array(
					'md5'    => array_map( 'strval', (array) ( isset( $entry['md5'] ) ? $entry['md5'] : array() ) ),
					'sha256' => array_map( 'strval', (array) ( isset( $entry['sha256'] ) ? $entry['sha256'] : array() ) ),
				);
			}
		}
		if ( ! $clean ) {
			if ( ! isset( $this->state['stats']['plugin_checksum_errors'] ) ) {
				$this->state['stats']['plugin_checksum_errors'] = 0;
			}
			++$this->state['stats']['plugin_checksum_errors'];
			set_site_transient( $key, 'error', HOUR_IN_SECONDS );
			$this->plugin_sums[ $slug ] = null;
			return null;
		}
		set_site_transient( $key, $clean, DAY_IN_SECONDS );
		$this->plugin_sums[ $slug ] = $clean;
		return $clean;
	}

	/**
	 * Compare a plugin file with the official release.
	 *
	 * @param array $f File (with hash).
	 * @return string|null match|mismatch|unknown, or null when not verifiable.
	 */
	private function plugin_verdict( array $f ) {
		if ( 'plugin' !== $f['area'] || ! Settings::value( 'plugin_checksums' ) ) {
			return null;
		}
		$base  = Paths::dirs()['plugins'];
		$parts = explode( '/', ltrim( substr( $f['abs'], strlen( $base ) ), '/' ), 2 );
		if ( 2 !== count( $parts ) ) {
			return null;
		}
		$sums = $this->plugin_checksums( $parts[0] );
		if ( ! is_array( $sums ) ) {
			return null;
		}
		if ( ! isset( $sums[ $parts[1] ] ) ) {
			return 'unknown';
		}
		$hash = isset( $f['hash'] ) ? $f['hash'] : (string) @hash_file( 'sha256', $f['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( in_array( $hash, $sums[ $parts[1] ]['sha256'], true ) ) {
			return 'match';
		}
		if ( $sums[ $parts[1] ]['md5'] && in_array( (string) @md5_file( $f['abs'] ), $sums[ $parts[1] ]['md5'], true ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return 'match';
		}
		return 'mismatch';
	}

	/**
	 * Load official core checksums for the running version.
	 */
	private function load_checksums() {
		if ( ! Settings::value( 'core_checksums' ) ) {
			return;
		}
		global $wp_version, $wp_local_package;
		$locale    = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
		$cache_key = 'bee_monitor_cs_' . md5( $wp_version . '|' . $locale );
		$cached    = get_site_transient( $cache_key );
		if ( is_array( $cached ) ) {
			$this->checksums = $cached ? $cached : null;
			return;
		}
		require_once ABSPATH . 'wp-admin/includes/update.php';
		$sums = get_core_checksums( $wp_version, $locale );
		if ( ! is_array( $sums ) && 'en_US' !== $locale ) {
			$sums = get_core_checksums( $wp_version, 'en_US' );
		}
		$clean = array();
		if ( is_array( $sums ) ) {
			foreach ( $sums as $file => $md5 ) {
				if ( 0 !== strpos( $file, 'wp-content/' ) ) {
					$clean[ $file ] = $md5;
				}
			}
		}
		set_site_transient( $cache_key, $clean, $clean ? DAY_IN_SECONDS : HOUR_IN_SECONDS );
		$this->checksums = $clean ? $clean : null;
		if ( ! $clean ) {
			Storage::log( 'warning', 'Bee Monitor could not fetch official core checksums; core files are compared against the local baseline only.' );
		}
	}

	/**
	 * Walk directories.
	 */
	private function walk() {
		$s = &$this->state;
		while ( ! empty( $s['stack'] ) ) {
			if ( $this->out_of_time() ) {
				return;
			}
			$item    = array_pop( $s['stack'] );
			$root    = $s['roots'][ $item['root'] ];
			$entries = @scandir( $item['dir'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $entries ) {
				$this->note_unreadable( Paths::to_rel( $item['dir'], $root ) . '/' );
				continue;
			}
			if ( 0 === $item['offset'] ) {
				++$s['stats']['dirs'];
			}
			$pending = array();
			$subdirs = array();
			$count   = count( $entries );
			for ( $i = $item['offset']; $i < $count; $i++ ) {
				$name = $entries[ $i ];
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$abs = $item['dir'] . '/' . $name;
				if ( is_link( $abs ) ) {
					++$s['stats']['symlinks'];
					continue;
				}
				$rel = Paths::to_rel( $abs, $root );
				if ( is_dir( $abs ) ) {
					if ( $root['recursive'] && ! Paths::excluded( $rel, true, $this->exclusions ) ) {
						$subdirs[] = array(
							'dir'    => $abs,
							'offset' => 0,
							'root'   => $item['root'],
						);
					}
					continue;
				}
				if ( Paths::excluded( $rel, false, $this->exclusions ) ) {
					continue;
				}
				$lower = strtolower( $name );
				if ( Paths::is_executable_name( $lower, $this->extra_ext ) || Paths::is_config_name( $lower ) ) {
					$pending[] = array(
						'abs'  => $abs,
						'rel'  => $rel,
						'name' => $lower,
					);
				} elseif ( Settings::value( 'inspect_upload_images' ) ) {
					$this->inspect_media( $abs, $rel, $lower );
				}
				if ( count( $pending ) >= self::BATCH ) {
					$this->flush( $pending );
					$pending = array();
					if ( $this->out_of_time() && $i + 1 < $count ) {
						$s['stack']   = array_merge( $s['stack'], $subdirs );
						$s['stack'][] = array(
							'dir'    => $item['dir'],
							'offset' => $i + 1,
							'root'   => $item['root'],
						);
						return;
					}
				}
			}
			$this->flush( $pending );
			$s['stack'] = array_merge( $s['stack'], $subdirs );
		}
		$s['phase'] = 'scan' === $s['mode'] ? 'deleted' : 'core';
	}

	/**
	 * Process a batch of monitored files.
	 *
	 * @param array $files Files.
	 */
	private function flush( array $files ) {
		if ( empty( $files ) ) {
			return;
		}
		$s    = &$this->state;
		$keys = array();
		foreach ( $files as $f ) {
			$keys[] = md5( $f['rel'] );
		}
		$rows = 'degraded' === $s['mode'] ? array() : Storage::baseline_rows( $keys );
		$seen = array();

		foreach ( $files as $f ) {
			if ( Repair::is_control_file( $f['abs'] ) ) {
				continue;
			}
			++$s['stats']['files'];
			$key       = md5( $f['rel'] );
			$f['area'] = Paths::area( $f['abs'] );
			if ( 'root' === $f['area'] && is_array( $this->checksums ) && isset( $this->checksums[ $f['rel'] ] ) ) {
				$f['area'] = 'core';
			}
			$row = isset( $rows[ $key ] ) ? $rows[ $key ] : null;
			if ( $row ) {
				$seen[] = $key;
			}

			$size  = @filesize( $f['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$mtime = @filemtime( $f['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( false === $size || false === $mtime || ! is_readable( $f['abs'] ) ) {
				$this->note_unreadable( $f['rel'] );
				if ( $row ) {
					$this->record_file( 'file_unverifiable', Findings::MEDIUM, 'confirmed', 'monitor', 'detected', $f, __( 'This monitored file exists but cannot be read, so its integrity cannot be verified.', 'bee-monitor' ), array(), 'unreadable' );
				}
				continue;
			}
			$f['size']  = (int) $size;
			$f['mtime'] = (int) $mtime;
			$volatile   = in_array( $f['area'], array( 'uploads', 'cache' ), true ) && ! Paths::is_config_name( $f['name'] );

			if ( 'scan' === $s['mode'] && $row ) {
				if ( ! $s['skip_mac'] && ! hash_equals( (string) $row['mac'], Storage::row_mac( $key, $row['sha256'], $row['size'] ) ) ) {
					++$s['tamper_hits'];
					$this->record_file( 'baseline_tampered', Findings::CRITICAL, 'confirmed', 'monitor', 'detected', $f, __( 'The stored baseline record for this file does not match its signature. The baseline may have been edited to hide a change.', 'bee-monitor' ), array(), 'mac' );
				}
				$need = $s['full_hash'] || (int) $row['size'] !== $f['size'] || (int) $row['mtime'] !== $f['mtime'];
				if ( ! $need ) {
					continue;
				}
				$hash = $this->hash( $f );
				if ( false === $hash ) {
					continue;
				}
				if ( hash_equals( (string) $row['sha256'], $hash ) ) {
					if ( (int) $row['mtime'] !== $f['mtime'] ) {
						Storage::touch_baseline( $key, $f['mtime'] );
					}
					if ( 'core' === $f['area'] ) {
						$this->check_core( $f, 'present', $row );
					} elseif ( 'plugin' === $f['area'] && $s['full_hash'] ) {
						$f['hash'] = $hash;
						if ( in_array( $this->plugin_verdict( $f ), array( 'mismatch', 'unknown' ), true ) ) {
							$this->evaluate( $f, $hash, 'present', $row );
						}
					}
					continue;
				}
				++$s['stats']['modified'];
				$this->evaluate( $f, $hash, 'modified', $row );
				continue;
			}

			$hash = $this->hash( $f );
			if ( false === $hash ) {
				continue;
			}
			if ( 'baseline' === $s['mode'] ) {
				if ( ! $volatile ) {
					Storage::upsert_baseline( $f['rel'], $f['area'], $hash, $f['size'], $f['mtime'], $s['id'] );
				}
				$this->evaluate( $f, $hash, 'present_at_baseline', null );
			} elseif ( 'degraded' === $s['mode'] ) {
				$this->evaluate( $f, $hash, 'present', null );
			} else {
				if ( ! $volatile ) {
					++$s['stats']['added'];
				}
				$this->evaluate( $f, $hash, 'added', null );
			}
		}
		if ( 'scan' === $s['mode'] ) {
			Storage::mark_seen( $seen, $s['id'] );
		}
	}

	/**
	 * Hash a file.
	 *
	 * @param array $f File.
	 * @return string|false
	 */
	private function hash( array $f ) {
		$hash = @hash_file( 'sha256', $f['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $hash ) {
			$this->note_unreadable( $f['rel'] );
			return false;
		}
		++$this->state['stats']['hashed'];
		return $hash;
	}

	/**
	 * Read a file for inspection within the size limit.
	 *
	 * @param array $f File.
	 * @return string|null
	 */
	private function read( array $f ) {
		$max = (int) Settings::value( 'max_inspect_kb' ) * 1024;
		if ( $f['size'] > $max ) {
			++$this->state['stats']['too_large'];
			return null;
		}
		$content = @file_get_contents( $f['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged,WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
		if ( false === $content ) {
			$this->note_unreadable( $f['rel'] );
			return null;
		}
		++$this->state['stats']['inspected'];
		return $content;
	}

	/**
	 * Decide what a new, changed, or baselined file means.
	 *
	 * @param array      $f      File.
	 * @param string     $hash   SHA-256.
	 * @param string     $change added|modified|present|present_at_baseline.
	 * @param array|null $row    Baseline row.
	 */
	private function evaluate( array $f, $hash, $change, $row ) {
		$f['hash'] = $hash;
		$is_config = Paths::is_config_name( $f['name'] );
		$is_exec   = Paths::is_executable_name( $f['name'], $this->extra_ext );
		$content   = ( $is_exec || $is_config ) ? $this->read( $f ) : null;
		$heur      = ( $is_exec && null !== $content && 'self' !== $f['area'] ) ? Heuristics::inspect_php( $content ) : null;
		$verdict   = $heur ? Heuristics::verdict( $heur ) : null;
		if ( $verdict && 'core' === $f['area'] && $verdict[0] < Findings::HIGH ) {
			$verdict = null;
		}
		$at_baseline = in_array( $change, array( 'present_at_baseline', 'present' ), true );
		$primary     = null;
		$evidence    = array(
			'size'     => $f['size'],
			'sha256'   => $hash,
			'modified' => gmdate( 'c', $f['mtime'] ),
		);
		if ( $row ) {
			$evidence['previous_sha256'] = $row['sha256'];
			$evidence['previous_size']   = (int) $row['size'];
		}

		switch ( $f['area'] ) {
			case 'core':
				if ( $this->check_core( $f, $change, $row ) ) {
					return;
				}
				if ( ! $at_baseline && ! is_array( $this->checksums ) ) {
					$primary = array( 'php_file_changed', Findings::HIGH, 'confirmed', 'integrity', __( 'A WordPress core file changed and official checksums were unavailable to verify it.', 'bee-monitor' ) );
				}
				break;

			case 'uploads':
				if ( $is_config ) {
					$primary = $this->config_primary( $f, $content, $change, true );
					break;
				}
				if ( null !== $content && Heuristics::is_inert_php( $content ) ) {
					$this->record_file( 'inert_php_stub', Findings::INFO, 'high', 'location', $change, $f, __( 'Placeholder PHP file with no executable code (often "Silence is golden"). Recorded for visibility only.', 'bee-monitor' ), $evidence, $hash, Findings::STATUS_AUTO );
					return;
				}
				$primary = array( 'executable_in_uploads', Findings::CRITICAL, 'high', 'location', __( 'An executable PHP file exists in the uploads directory, which should only contain media and documents. Uploaded web shells commonly live here.', 'bee-monitor' ) );
				break;

			case 'cache':
				if ( null !== $content && ( Heuristics::is_inert_php( $content ) || preg_match( '~^\s*<\?php\s+(?:exit|die)\b~i', $content ) ) && ! $verdict ) {
					return;
				}
				$primary = array( 'executable_in_cache', Findings::MEDIUM, 'medium', 'location', __( 'An executable PHP file exists in a cache or temporary directory. Some caching plugins write PHP here; attackers also use these locations.', 'bee-monitor' ) );
				break;

			case 'config':
				$primary = $this->config_primary( $f, $content, $change, Paths::in_uploads( $f['abs'] ) );
				break;

			case 'self':
				if ( $at_baseline ) {
					break;
				}
				if ( $this->update_window( 'plugin', Paths::component( $f['abs'], 'self' ), $f['mtime'] ) ) {
					Storage::upsert_baseline( $f['rel'], 'self', $hash, $f['size'], $f['mtime'], $this->state['id'] );
					$this->note_update( 'self', Paths::component( $f['abs'], 'self' ), $change );
					return;
				}
				$primary = array( 'self_modified', Findings::CRITICAL, 'confirmed', 'integrity', __( 'A Bee Monitor plugin file changed outside a recorded Bee Monitor update. An attacker may be trying to disable monitoring.', 'bee-monitor' ) );
				break;

			case 'mu':
			case 'dropin':
				if ( ! $at_baseline ) {
					$primary = array( 'persistence_file_changed', Findings::HIGH, 'confirmed', 'integrity', __( 'A must-use plugin or drop-in was added or changed. These load automatically on every request and are a common persistence mechanism.', 'bee-monitor' ) );
				}
				break;

			case 'plugin':
			case 'theme':
			case 'languages':
				$official = $this->plugin_verdict( $f );
				if ( 'match' === $official ) {
					if ( ! $at_baseline ) {
						Storage::upsert_baseline( $f['rel'], 'plugin', $hash, $f['size'], $f['mtime'], $this->state['id'] );
						$this->note_update( 'plugin', Paths::component( $f['abs'], 'plugin' ), 'verified' );
					}
					return;
				}
				if ( 'mismatch' === $official ) {
					$primary               = array( 'plugin_checksum_mismatch', Findings::CRITICAL, 'confirmed', 'integrity', __( 'This file differs from the official WordPress.org release of the installed plugin version. Plugin files should not be edited on the server.', 'bee-monitor' ) );
					$evidence['component'] = Paths::component( $f['abs'], 'plugin' );
					break;
				}
				if ( 'unknown' === $official && $is_exec ) {
					$primary               = array( 'plugin_unknown_file', Findings::HIGH, 'medium', 'integrity', __( 'This PHP file is not part of the official WordPress.org release of the installed plugin version.', 'bee-monitor' ) );
					$evidence['component'] = Paths::component( $f['abs'], 'plugin' );
					break;
				}
				if ( $at_baseline ) {
					break;
				}
				$type      = 'languages' === $f['area'] ? 'translation' : $f['area'];
				$component = Paths::component( $f['abs'], $f['area'] );
				if ( $this->update_window( $type, $component, $f['mtime'] ) && ! $verdict && Settings::value( 'auto_accept_updates' ) ) {
					Storage::upsert_baseline( $f['rel'], $f['area'], $hash, $f['size'], $f['mtime'], $this->state['id'] );
					$this->note_update( $f['area'], $component, $change );
					return;
				}
				$primary               = array( 'component_file_changed', 'languages' === $f['area'] ? Findings::LOW : Findings::MEDIUM, 'confirmed', 'integrity', __( 'A plugin, theme, or translation file was added or changed, and no matching update, install, or activation was recorded around that time.', 'bee-monitor' ) );
				$evidence['component'] = $component;
				break;

			default:
				if ( $at_baseline ) {
					break;
				}
				if ( 'added' === $change ) {
					$primary = array( 'unexpected_php_file', Findings::HIGH, 'medium', 'location', __( 'A new PHP file appeared outside WordPress core, plugins, and themes. Attackers often place backdoors with names that look like core files.', 'bee-monitor' ) );
				} else {
					$primary = array( 'php_file_changed', Findings::MEDIUM, 'confirmed', 'integrity', __( 'A PHP file outside plugins and themes changed.', 'bee-monitor' ) );
				}
		}

		if ( $heur && $verdict ) {
			$evidence['indicators'] = $heur['matches'];
			$evidence['score']      = $heur['score'];
		}

		if ( $primary ) {
			list( $rule, $sev, $conf, $basis, $reason ) = $primary;
			if ( $verdict ) {
				$sev = max( $sev, $verdict[0] );
				if ( $heur['shell'] && in_array( $f['area'], array( 'uploads', 'cache', 'root', 'parent', 'other', 'content', 'mu', 'dropin' ), true ) ) {
					$sev = Findings::CRITICAL;
				}
				$reason .= ' ' . __( 'The file also contains suspicious code indicators (see evidence).', 'bee-monitor' );
			}
			$this->record_file( $rule, $sev, $conf, $basis, $change, $f, $reason, $evidence, $hash );
			return;
		}

		if ( $verdict ) {
			list( $sev, $conf ) = $verdict;
			if ( in_array( $f['area'], array( 'root', 'parent', 'other', 'content' ), true ) ) {
				$sev = min( Findings::CRITICAL, $sev + 1 );
			}
			$reason = $heur['shell']
				? __( 'The file matches patterns typical of web shells or backdoors. This is a strong indicator, not proof.', 'bee-monitor' )
				/* translators: %d: indicator score. */
				: sprintf( __( 'The file contains code patterns often used to hide or execute malicious code (indicator score %d). Legitimate libraries sometimes use these patterns too.', 'bee-monitor' ), $heur['score'] );
			$this->record_file( 'suspicious_code', $sev, $conf, 'heuristic', $change, $f, $reason, $evidence, $hash );
		}
	}

	/**
	 * Config file rules.
	 *
	 * @param array       $f          File.
	 * @param string|null $content    Content.
	 * @param string      $change     Change type.
	 * @param bool        $in_uploads Whether inside uploads.
	 * @return array|null Primary finding tuple.
	 */
	private function config_primary( array $f, $content, $change, $in_uploads ) {
		$at_baseline = in_array( $change, array( 'present_at_baseline', 'present' ), true );
		$hits        = null !== $content ? Heuristics::inspect_config( $content, $f['name'] ) : array();
		$is_wpconfig = 'wp-config.php' === $f['name'];
		$evidence    = array(
			'size'   => $f['size'],
			'sha256' => $f['hash'],
		);

		if ( $hits ) {
			$sev = Findings::LOW;
			foreach ( $hits as $hit ) {
				$sev = max( $sev, (int) $hit['severity'] );
			}
			if ( $in_uploads && Findings::HIGH <= $sev ) {
				$sev = Findings::CRITICAL;
			}
			$evidence['indicators'] = $hits;
			$this->record_file(
				$is_wpconfig ? 'config_injection' : 'server_config_risk',
				$sev,
				'medium',
				'heuristic',
				$change,
				$f,
				$is_wpconfig
					? __( 'wp-config.php contains a line that loads code from an unusual source.', 'bee-monitor' )
					: __( 'A server configuration file contains directives that can run PHP, run code on every request, redirect visitors, or cloak content for search engines.', 'bee-monitor' ),
				$evidence,
				$f['hash']
			);
		}

		if ( $at_baseline ) {
			return null;
		}
		if ( $is_wpconfig ) {
			return array( 'config_modified', Findings::HIGH, 'confirmed', 'integrity', __( 'wp-config.php changed. It controls database access and keys and is a common place to inject persistent code.', 'bee-monitor' ) );
		}
		return array( 'server_config_changed', $in_uploads ? Findings::HIGH : Findings::MEDIUM, 'confirmed', 'integrity', __( 'A server configuration file (.htaccess, .user.ini, php.ini, or web.config) was added or changed.', 'bee-monitor' ) );
	}

	/**
	 * Compare a core file with official checksums.
	 *
	 * @param array      $f      File (with hash for changed files).
	 * @param string     $change Change type.
	 * @param array|null $row    Baseline row.
	 * @return bool True when the file was fully handled.
	 */
	private function check_core( array $f, $change, $row ) {
		if ( ! is_array( $this->checksums ) ) {
			return false;
		}
		$is_listed = isset( $this->checksums[ $f['rel'] ] );
		$hash      = isset( $f['hash'] ) ? $f['hash'] : ( $row ? $row['sha256'] : '' );

		if ( ! $is_listed ) {
			if ( 'core' !== Paths::area( $f['abs'] ) ) {
				return false;
			}
			$this->record_file(
				'core_unknown_file',
				Findings::HIGH,
				'high',
				'integrity',
				'present' === $change ? 'present' : $change,
				$f,
				__( 'This file is inside wp-admin or wp-includes but is not part of the official WordPress release for this version.', 'bee-monitor' ),
				array(
					'sha256' => $hash,
					'size'   => $f['size'],
				),
				$hash
			);
			return true;
		}

		$md5 = @md5_file( $f['abs'] ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $md5 ) {
			return false;
		}
		if ( hash_equals( (string) $this->checksums[ $f['rel'] ], $md5 ) ) {
			if ( in_array( $change, array( 'added', 'modified' ), true ) && isset( $f['hash'] ) ) {
				if ( Settings::value( 'auto_accept_verified_core' ) ) {
					Storage::upsert_baseline( $f['rel'], 'core', $f['hash'], $f['size'], $f['mtime'], $this->state['id'] );
					$this->note_update( 'core', 'core', $change );
				} else {
					$this->record_file( 'core_file_updated', Findings::LOW, 'confirmed', 'integrity', $change, $f, __( 'This core file changed and matches the official WordPress checksum, which usually means WordPress was updated.', 'bee-monitor' ), array( 'sha256' => $f['hash'] ), $f['hash'] );
				}
			}
			return true;
		}

		$evidence = array(
			'size'         => $f['size'],
			'md5'          => $md5,
			'official_md5' => $this->checksums[ $f['rel'] ],
		);
		if ( null !== ( $content = $this->read( $f ) ) ) { // phpcs:ignore Generic.CodeAnalysis.AssignmentInCondition.Found,Squiz.PHP.DisallowMultipleAssignments.FoundInControlStructure
			$heur = Heuristics::inspect_php( $content );
			if ( Heuristics::verdict( $heur ) ) {
				$evidence['indicators'] = $heur['matches'];
				$evidence['score']      = $heur['score'];
			}
		}
		$this->record_file(
			'core_checksum_mismatch',
			Findings::CRITICAL,
			'confirmed',
			'integrity',
			'present' === $change ? 'modified' : $change,
			$f,
			__( 'This WordPress core file differs from the official version published on WordPress.org for the installed release. Core files should never be edited.', 'bee-monitor' ),
			$evidence,
			$md5
		);
		return true;
	}

	/**
	 * Baseline rows not seen in this scan.
	 */
	private function deleted() {
		$s = &$this->state;
		while ( ! $this->out_of_time() ) {
			$rows = Storage::unseen_rows( $s['id'], $s['cursor'], 300 );
			if ( empty( $rows ) ) {
				$s['phase'] = 'core';
				return;
			}
			foreach ( $rows as $row ) {
				$s['cursor'] = (int) $row['id'];
				if ( Paths::excluded( $row['path'], false, $this->exclusions ) ) {
					Storage::delete_baseline( $row['path'] );
					continue;
				}
				$abs = Paths::to_abs( $row['path'] );
				$f   = array(
					'abs'  => $abs,
					'rel'  => $row['path'],
					'name' => strtolower( basename( $abs ) ),
					'area' => $row['area'],
					'size' => (int) $row['size'],
				);
				if ( file_exists( $abs ) ) {
					$this->record_file( 'file_unverifiable', Findings::LOW, 'medium', 'monitor', 'detected', $f, __( 'This file is in the baseline but was not reached during the scan (for example, its directory is unreadable or now excluded).', 'bee-monitor' ), array(), 'unreached' );
					continue;
				}
				if ( ! $s['skip_mac'] && ! hash_equals( (string) $row['mac'], Storage::row_mac( $row['path_key'], $row['sha256'], $row['size'] ) ) ) {
					++$s['tamper_hits'];
					$this->record_file( 'baseline_tampered', Findings::CRITICAL, 'confirmed', 'monitor', 'detected', $f, __( 'The stored baseline record for this file does not match its signature.', 'bee-monitor' ), array(), 'mac' );
				}
				++$s['stats']['deleted'];
				$this->evaluate_deleted( $f, $row );
			}
		}
	}

	/**
	 * Decide what a deleted file means.
	 *
	 * @param array $f   File.
	 * @param array $row Baseline row.
	 */
	private function evaluate_deleted( array $f, array $row ) {
		$evidence = array( 'previous_sha256' => $row['sha256'] );
		switch ( $f['area'] ) {
			case 'core':
				if ( $this->update_window( 'core', 'core', 0 ) ) {
					Storage::delete_baseline( $f['rel'] );
					$this->note_update( 'core', 'core', 'deleted' );
					return;
				}
				$this->record_file( 'core_file_missing', Findings::HIGH, 'confirmed', 'integrity', 'deleted', $f, __( 'A WordPress core file that existed in the baseline is missing.', 'bee-monitor' ), $evidence, $row['sha256'] );
				return;
			case 'self':
				if ( $this->update_window( 'plugin', Paths::component( $f['abs'], 'self' ), 0 ) ) {
					Storage::delete_baseline( $f['rel'] );
					$this->note_update( 'self', Paths::component( $f['abs'], 'self' ), 'deleted' );
					return;
				}
				$this->record_file( 'self_modified', Findings::CRITICAL, 'confirmed', 'integrity', 'deleted', $f, __( 'A Bee Monitor plugin file was deleted outside a recorded update.', 'bee-monitor' ), $evidence, $row['sha256'] );
				return;
			case 'config':
				$sev = 'wp-config.php' === $f['name'] ? Findings::HIGH : Findings::MEDIUM;
				$this->record_file( 'file_deleted', $sev, 'confirmed', 'integrity', 'deleted', $f, __( 'A configuration file was deleted.', 'bee-monitor' ), $evidence, $row['sha256'] );
				return;
			case 'mu':
			case 'dropin':
				$this->record_file( 'file_deleted', Findings::MEDIUM, 'confirmed', 'integrity', 'deleted', $f, __( 'A must-use plugin or drop-in was deleted.', 'bee-monitor' ), $evidence, $row['sha256'] );
				return;
			case 'plugin':
			case 'theme':
			case 'languages':
				$type      = 'languages' === $f['area'] ? 'translation' : $f['area'];
				$component = Paths::component( $f['abs'], $f['area'] );
				if ( $this->update_window( $type, $component, 0 ) && Settings::value( 'auto_accept_updates' ) ) {
					Storage::delete_baseline( $f['rel'] );
					$this->note_update( $f['area'], $component, 'deleted' );
					return;
				}
				$this->record_file( 'file_deleted', Findings::LOW, 'confirmed', 'integrity', 'deleted', $f, __( 'A plugin, theme, or translation file was deleted without a recorded update or removal.', 'bee-monitor' ), $evidence, $row['sha256'] );
				return;
			default:
				$this->record_file( 'file_deleted', Findings::LOW, 'confirmed', 'integrity', 'deleted', $f, __( 'A monitored PHP file was deleted.', 'bee-monitor' ), $evidence, $row['sha256'] );
		}
	}

	/**
	 * Report core files missing from disk (baseline and degraded modes).
	 */
	private function core_missing() {
		if ( 'scan' !== $this->state['mode'] && is_array( $this->checksums ) ) {
			$abs = Paths::dirs()['abspath'];
			foreach ( $this->checksums as $rel => $md5 ) {
				if ( Paths::excluded( $rel, false, $this->exclusions ) || file_exists( $abs . '/' . $rel ) ) {
					continue;
				}
				$f = array(
					'abs'  => $abs . '/' . $rel,
					'rel'  => $rel,
					'name' => strtolower( basename( $rel ) ),
					'area' => 'core',
				);
				$this->record_file( 'core_file_missing', Findings::MEDIUM, 'confirmed', 'integrity', 'detected', $f, __( 'A file that is part of the official WordPress release is missing. This can happen after a failed update; it can also indicate tampering.', 'bee-monitor' ), array( 'official_md5' => $md5 ), 'missing' );
			}
		}
		$this->state['phase'] = 'site';
	}

	/**
	 * Final bookkeeping, notifications, and heartbeat.
	 */
	private function finalize() {
		$s    = &$this->state;
		$meta = Storage::get( 'baseline_meta', array() );
		$meta = is_array( $meta ) ? $meta : array();

		if ( 'baseline' === $s['mode'] ) {
			global $wp_version;
			$meta = array(
				'status'         => 'valid',
				'created'        => time(),
				'created_by'     => (int) $s['actor'],
				'trigger'        => $s['trigger'],
				'wp_version'     => $wp_version,
				'files'          => Storage::baseline_count(),
				'key_fp'         => Storage::mac_key_fingerprint(),
				'last_full_hash' => time(),
				'checksums'      => is_array( $this->checksums ),
			);
			Storage::set( 'baseline_meta', $meta );
			Storage::remember_urls();
		} elseif ( 'scan' === $s['mode'] && $s['full_hash'] ) {
			$meta['last_full_hash'] = time();
			Storage::set( 'baseline_meta', $meta );
		}

		foreach ( $s['updates'] as $component => $counts ) {
			$parts = array();
			foreach ( $counts as $type => $n ) {
				$parts[] = $n . ' ' . Findings::term( 'change', $type );
			}
			Findings::record(
				array(
					'rule'        => 'update_changes',
					'severity'    => Findings::INFO,
					'confidence'  => 'high',
					'basis'       => 'event',
					'change_type' => 'updated',
					'subject'     => $component,
					'reason'      => isset( $counts['verified'] ) && 1 === count( $counts )
						/* translators: 1: component, 2: list of change counts. */
						? sprintf( __( 'Files in %1$s changed and match the official WordPress.org release, so they were accepted into the baseline automatically (%2$s).', 'bee-monitor' ), $component, implode( ', ', $parts ) )
						/* translators: 1: component, 2: list of change counts. */
						: sprintf( __( 'Files in %1$s changed during a recorded update and were accepted into the baseline automatically (%2$s). Any file with suspicious code indicators was reported separately.', 'bee-monitor' ), $component, implode( ', ', $parts ) ),
					'evidence'    => $counts,
					'key'         => (string) $s['id'],
					'status'      => Findings::STATUS_AUTO,
				)
			);
		}

		$summary = array(
			'id'         => $s['id'],
			'mode'       => $s['mode'],
			'note'       => $s['note'],
			'trigger'    => $s['trigger'],
			'started'    => $s['started'],
			'finished'   => time(),
			'full_hash'  => $s['full_hash'],
			'stats'      => $s['stats'],
			'unreadable' => array_slice( $s['unreadable'], 0, 20 ),
			'errors'     => $s['errors'],
			'checksums'  => is_array( $this->checksums ),
			'tamper'     => $s['tamper_hits'],
		);
		Storage::set( 'last_scan', $summary );
		$s['phase'] = 'done';
		$this->save();

		Storage::log( 'info', sprintf( 'Bee Monitor scan #%d finished (%s)', $s['id'], $s['mode'] ), $s['stats'] );
		Storage::prune_log();
		Storage::purge_findings( (int) Settings::value( 'retention_days' ) );
		Storage::prune_deliveries();
		Activity::purge( (int) Settings::value( 'activity_retention_days' ) );
		/* translators: 1: files checked, 2: added, 3: modified, 4: deleted, 5: new findings. */
		Activity::log( 'scan_completed', sprintf( 'Scan #%d (%s)', $s['id'], $s['mode'] ), sprintf( __( '%1$d files checked; %2$d added, %3$d modified, %4$d deleted; %5$d new findings', 'bee-monitor' ), $s['stats']['files'], $s['stats']['added'], $s['stats']['modified'], $s['stats']['deleted'], $s['stats']['findings'] ), (int) $s['actor'] );
		Plugin::heartbeat();
		Notifier::dispatch( 'baseline' === $s['mode'] ? 'baseline' : 'scan', $summary );
	}

	/**
	 * Whether a change falls in a recorded update window.
	 *
	 * @param string $type      plugin|theme|translation|core.
	 * @param string $component Folder name.
	 * @param int    $mtime     File modified time, or 0 for deletions.
	 * @return bool
	 */
	private function update_window( $type, $component, $mtime ) {
		$grace = (int) Settings::value( 'update_grace_minutes' ) * MINUTE_IN_SECONDS;
		$since = max( 0, (int) $this->state['prev_start'] - $grace );
		$types = array( 'update_' . $type );
		if ( 'plugin' === $type ) {
			$types[] = 'activated_plugin';
		}
		foreach ( Context::events() as $event ) {
			if ( ! in_array( $event['type'], $types, true ) || $event['time'] < $since ) {
				continue;
			}
			if ( 'core' !== $type && 'translation' !== $type ) {
				$object = strtok( (string) $event['object'], '/' );
				if ( $object !== $component ) {
					continue;
				}
			}
			if ( 0 === $mtime || abs( $mtime - $event['time'] ) <= max( $grace, 5 * MINUTE_IN_SECONDS ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Count an auto-accepted update change.
	 *
	 * @param string $area      Area.
	 * @param string $component Component.
	 * @param string $change    Change type.
	 */
	private function note_update( $area, $component, $change ) {
		$label = $area . ':' . $component;
		if ( ! isset( $this->state['updates'][ $label ][ $change ] ) ) {
			$this->state['updates'][ $label ][ $change ] = 0;
		}
		++$this->state['updates'][ $label ][ $change ];
	}

	/**
	 * Inspect media/text files in uploads for embedded PHP.
	 *
	 * @param string $abs   Absolute path.
	 * @param string $rel   Relative path.
	 * @param string $lower Lowercase name.
	 */
	private function inspect_media( $abs, $rel, $lower ) {
		$ext = strtolower( pathinfo( $lower, PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, Paths::IMAGE_EXTENSIONS, true ) || 'uploads' !== Paths::area( $abs ) ) {
			return;
		}
		$size    = @filesize( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		$f       = array(
			'abs'   => $abs,
			'rel'   => $rel,
			'name'  => $lower,
			'area'  => 'uploads',
			'size'  => (int) $size,
			'mtime' => (int) @filemtime( $abs ), // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		);
		$content = $this->read( $f );
		if ( null === $content ) {
			return;
		}
		$hit = Heuristics::php_in_content( $content );
		if ( $hit ) {
			$hash = hash( 'sha256', $content );
			$this->record_file(
				'php_in_media_file',
				Findings::HIGH,
				'medium',
				'location',
				'detected',
				$f,
				__( 'A media or text file contains PHP code. Attackers hide payloads in images and include them from other files.', 'bee-monitor' ),
				array(
					'indicators' => array( $hit ),
					'sha256'     => $hash,
				),
				$hash
			);
		}
	}

	/**
	 * Record a file finding.
	 *
	 * @param string $rule       Rule.
	 * @param int    $severity   Severity.
	 * @param string $confidence Confidence.
	 * @param string $basis      Basis.
	 * @param string $change     Change type.
	 * @param array  $f          File.
	 * @param string $reason     Reason.
	 * @param array  $evidence   Evidence.
	 * @param string $key        Dedup discriminator.
	 * @param string $status     Status.
	 */
	private function record_file( $rule, $severity, $confidence, $basis, $change, array $f, $reason, array $evidence, $key, $status = Findings::STATUS_OPEN ) {
		$evidence['area'] = isset( $f['area'] ) ? $f['area'] : '';
		$evidence['path'] = $f['rel'];
		if ( ! isset( $evidence['verification'] ) ) {
			$evidence['verification'] = Findings::verification_for( $rule );
		}
		if ( Findings::STATUS_OPEN === $status && Settings::is_ignored( $rule, $f['rel'] ) ) {
			$status = Findings::STATUS_IGNORED;
		}
		Findings::record(
			array(
				'rule'        => $rule,
				'severity'    => $severity,
				'confidence'  => $confidence,
				'basis'       => $basis,
				'change_type' => $change,
				'subject'     => $f['rel'],
				'reason'      => $reason,
				'evidence'    => $evidence,
				'key'         => $key,
				'status'      => $status,
			)
		);
		if ( Findings::STATUS_OPEN === $status ) {
			++$this->state['stats']['findings'];
		}
	}

	/**
	 * Track an unreadable path.
	 *
	 * @param string $rel Relative path.
	 */
	private function note_unreadable( $rel ) {
		++$this->state['stats']['unreadable'];
		if ( count( $this->state['unreadable'] ) < 50 ) {
			$this->state['unreadable'][] = $rel;
		}
	}

	/**
	 * Accept the current state of a file into the baseline after review.
	 *
	 * @param array $finding Finding.
	 * @return string ok|changed|missing|skipped
	 */
	public static function accept_file( array $finding ) {
		$rel = isset( $finding['evidence']['path'] ) ? (string) $finding['evidence']['path'] : '';
		if ( '' === $rel || ! Findings::is_file_rule( $finding['rule'] ) ) {
			return 'skipped';
		}
		$abs  = Paths::to_abs( $rel );
		$area = Paths::area( $abs );
		if ( ! file_exists( $abs ) ) {
			Storage::delete_baseline( $rel );
			return 'missing';
		}
		if ( in_array( $area, array( 'uploads', 'cache' ), true ) && ! Paths::is_config_name( basename( $abs ) ) ) {
			return 'skipped';
		}
		$hash = @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( false === $hash ) {
			return 'skipped';
		}
		$expected = isset( $finding['evidence']['sha256'] ) ? (string) $finding['evidence']['sha256'] : '';
		if ( '' !== $expected && ! hash_equals( $expected, $hash ) ) {
			return 'changed';
		}
		Storage::upsert_baseline( $rel, $area, $hash, (int) filesize( $abs ), (int) filemtime( $abs ), (int) Storage::get( 'scan_counter', 0 ) );
		return 'ok';
	}
}
