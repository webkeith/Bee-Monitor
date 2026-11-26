<?php
/**
 * Administrator-reviewed repair and quarantine.
 *
 * Off by default. Nothing here runs automatically: every action is started by an administrator,
 * confirmed, and recoverable. Repairs use only official WordPress.org sources verified against
 * official checksums. The original file is always copied to quarantine first.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Repair and quarantine.
 */
final class Repair {

	const MAX_BYTES   = 10485760;
	const MAX_ENTRIES = 200;
	const DIR_NAME    = 'bee-monitor-quarantine';

	const CONTROL_FILES = array(
		'.htaccess'  => "Require all denied\nDeny from all\n",
		'index.php'  => "<?php\n// Silence is golden.\n",
		'web.config' => "<configuration><system.webServer><authorization><deny users=\"*\" /></authorization></system.webServer></configuration>\n",
	);

	const REPAIR_RULES     = array( 'core_checksum_mismatch', 'core_file_missing', 'plugin_checksum_mismatch' );
	const QUARANTINE_RULES = array( 'executable_in_uploads', 'executable_in_cache', 'unexpected_php_file', 'core_unknown_file', 'plugin_unknown_file', 'php_in_media_file', 'suspicious_code', 'persistence_file_changed' );

	/**
	 * Whether repairs are allowed on this site.
	 *
	 * @return bool
	 */
	public static function enabled() {
		return (bool) Settings::value( 'allow_repairs' ) && ! ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS );
	}

	/**
	 * Why repairs are unavailable, or '' when available.
	 *
	 * @return string
	 */
	public static function unavailable_reason() {
		if ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) {
			return __( 'File changes are disabled on this site (DISALLOW_FILE_MODS).', 'bee-monitor' );
		}
		if ( ! Settings::value( 'allow_repairs' ) ) {
			return __( 'Administrator-reviewed repairs are turned off in Bee Monitor settings.', 'bee-monitor' );
		}
		require_once ABSPATH . 'wp-admin/includes/file.php';
		if ( 'direct' !== get_filesystem_method() ) {
			return __( 'WordPress cannot write files directly on this server, so repairs must be done manually.', 'bee-monitor' );
		}
		return '';
	}

	/**
	 * Available actions for a finding.
	 *
	 * @param array $finding Finding.
	 * @return array repair (bool), quarantine (bool), warn (bool), rel, abs, area.
	 */
	public static function options( array $finding ) {
		$out = array(
			'repair'     => false,
			'quarantine' => false,
			'warn'       => false,
			'rel'        => '',
			'abs'        => '',
			'area'       => '',
		);
		$rel = isset( $finding['evidence']['path'] ) ? (string) $finding['evidence']['path'] : '';
		if ( '' === $rel || Findings::STATUS_OPEN !== $finding['status'] ) {
			return $out;
		}
		$abs = self::safe_path( $rel );
		if ( '' === $abs ) {
			return $out;
		}
		$area        = Paths::area( $abs );
		$out['rel']  = $rel;
		$out['abs']  = $abs;
		$out['area'] = $area;
		if ( in_array( $area, array( 'config', 'self' ), true ) ) {
			return $out;
		}
		$exists = @is_file( $abs ) && ! @is_link( $abs ) && (int) @filesize( $abs ) <= self::MAX_BYTES; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		if ( in_array( $finding['rule'], self::REPAIR_RULES, true ) && in_array( $area, array( 'core', 'plugin' ), true ) ) {
			$out['repair'] = 'core_file_missing' === $finding['rule'] ? ! @file_exists( $abs ) : $exists; // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		}
		if ( in_array( $finding['rule'], self::QUARANTINE_RULES, true ) && $exists ) {
			$out['quarantine'] = true;
			$out['warn']       = in_array( $finding['rule'], array( 'suspicious_code', 'persistence_file_changed' ), true ) || in_array( $area, array( 'plugin', 'theme', 'mu', 'dropin', 'core' ), true );
		}
		return $out;
	}

	/**
	 * Resolve a relative path to an absolute path inside a scan root, rejecting traversal and symlinks.
	 *
	 * @param string $rel Relative path.
	 * @return string Absolute path or ''.
	 */
	public static function safe_path( $rel ) {
		if ( false !== strpos( $rel, '..' ) || false !== strpos( $rel, "\0" ) ) {
			return '';
		}
		$abs = Paths::to_abs( $rel );
		$dir = Paths::normalize( dirname( $abs ) );
		if ( @is_link( $abs ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return '';
		}
		foreach ( Paths::roots( true ) as $root ) {
			if ( ( $root['recursive'] && Paths::within( $dir, $root['abs'] ) ) || $dir === $root['abs'] ) {
				return $dir . '/' . basename( $abs );
			}
		}
		return '';
	}

	/**
	 * Official source for a repairable file.
	 *
	 * @param array $finding Finding.
	 * @return array|\WP_Error url, md5 (list), sha256 (list).
	 */
	public static function source( array $finding ) {
		global $wp_version, $wp_local_package;
		$opt = self::options( $finding );
		if ( ! $opt['repair'] ) {
			return new \WP_Error( 'not_repairable', __( 'This finding cannot be repaired from an official source.', 'bee-monitor' ) );
		}
		$segments = implode( '/', array_map( 'rawurlencode', explode( '/', $opt['rel'] ) ) );
		if ( 'core' === $opt['area'] ) {
			$locale = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
			$sums   = get_site_transient( 'bee_monitor_cs_' . md5( $wp_version . '|' . $locale ) );
			if ( ! is_array( $sums ) || ! $sums ) {
				require_once ABSPATH . 'wp-admin/includes/update.php';
				$sums = get_core_checksums( $wp_version, $locale );
			}
			if ( ! is_array( $sums ) || empty( $sums[ $opt['rel'] ] ) ) {
				return new \WP_Error( 'no_checksum', __( 'Official checksums for this WordPress version could not be loaded.', 'bee-monitor' ) );
			}
			return array(
				'url'    => 'https://core.svn.wordpress.org/tags/' . rawurlencode( $wp_version ) . '/' . $segments,
				'md5'    => array( (string) $sums[ $opt['rel'] ] ),
				'sha256' => array(),
			);
		}
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$base  = Paths::dirs()['plugins'];
		$parts = explode( '/', ltrim( substr( $opt['abs'], strlen( $base ) ), '/' ), 2 );
		if ( 2 !== count( $parts ) ) {
			return new \WP_Error( 'not_repairable', __( 'Single-file plugins cannot be repaired automatically.', 'bee-monitor' ) );
		}
		$version = '';
		foreach ( get_plugins() as $file => $data ) {
			if ( dirname( $file ) === $parts[0] ) {
				$version = (string) $data['Version'];
			}
		}
		$cached = get_site_transient( 'bee_monitor_pcs_' . md5( $parts[0] . '|' . $version ) );
		if ( ! is_array( $cached ) || empty( $cached[ $parts[1] ] ) ) {
			return new \WP_Error( 'no_checksum', __( 'Official plugin checksums are not available. Run a scan with plugin checksum verification turned on first.', 'bee-monitor' ) );
		}
		return array(
			'url'    => 'https://plugins.svn.wordpress.org/' . rawurlencode( $parts[0] ) . '/tags/' . rawurlencode( $version ) . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', $parts[1] ) ) ),
			'md5'    => $cached[ $parts[1] ]['md5'],
			'sha256' => $cached[ $parts[1] ]['sha256'],
		);
	}

	/**
	 * Replace a file with the verified official version, after backing up the current file.
	 *
	 * @param int $finding_id Finding ID.
	 * @return true|\WP_Error
	 */
	public static function repair( $finding_id ) {
		$fs = self::filesystem();
		if ( is_wp_error( $fs ) ) {
			return $fs;
		}
		$finding = Findings::get( $finding_id );
		if ( ! $finding ) {
			return new \WP_Error( 'missing', __( 'Finding not found.', 'bee-monitor' ) );
		}
		$source = self::source( $finding );
		if ( is_wp_error( $source ) ) {
			return $source;
		}
		$opt      = self::options( $finding );
		$response = wp_safe_remote_get(
			$source['url'],
			array(
				'timeout'             => 20,
				'limit_response_size' => self::MAX_BYTES,
				'user-agent'          => 'Bee Monitor/' . BEE_MONITOR_VERSION,
			)
		);
		if ( is_wp_error( $response ) || 200 !== (int) wp_remote_retrieve_response_code( $response ) ) {
			return new \WP_Error( 'download', __( 'The official file could not be downloaded. Nothing was changed.', 'bee-monitor' ) );
		}
		$body = (string) wp_remote_retrieve_body( $response );
		if ( ! self::matches( $body, $source ) ) {
			return new \WP_Error( 'checksum', __( 'The downloaded file did not match the official checksum. Nothing was changed.', 'bee-monitor' ) );
		}
		$backup = '';
		if ( @file_exists( $opt['abs'] ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			$backup = self::store( $fs, $opt['abs'], $opt['rel'], 'repair-backup', $finding );
			if ( is_wp_error( $backup ) ) {
				return $backup;
			}
		}
		if ( ! $fs->put_contents( $opt['abs'], $body, FS_CHMOD_FILE ) || ! hash_equals( hash( 'sha256', $body ), (string) @hash_file( 'sha256', $opt['abs'] ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			if ( $backup ) {
				self::restore( $backup, true );
			}
			return new \WP_Error( 'write', __( 'The file could not be written. The original was restored from the backup.', 'bee-monitor' ) );
		}
		Storage::upsert_baseline( $opt['rel'], $opt['area'], hash( 'sha256', $body ), strlen( $body ), (int) @filemtime( $opt['abs'] ), (int) Storage::get( 'scan_counter', 0 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		/* translators: %s: quarantine entry ID. */
		Findings::set_status( array( (int) $finding_id ), Findings::STATUS_RESOLVED, $backup ? sprintf( __( 'Repaired from the official source. Backup: %s', 'bee-monitor' ), $backup ) : __( 'Restored from the official source.', 'bee-monitor' ), get_current_user_id() );
		Activity::log( 'file_repaired', $opt['rel'], $backup ? 'backup ' . $backup : 'missing file restored' );
		return true;
	}

	/**
	 * Move a flagged file to quarantine (copy, verify, then delete the original).
	 *
	 * @param int $finding_id Finding ID.
	 * @return string|\WP_Error Quarantine entry ID.
	 */
	public static function quarantine( $finding_id ) {
		$fs = self::filesystem();
		if ( is_wp_error( $fs ) ) {
			return $fs;
		}
		$finding = Findings::get( $finding_id );
		$opt     = $finding ? self::options( $finding ) : array( 'quarantine' => false );
		if ( ! $opt['quarantine'] ) {
			return new \WP_Error( 'not_allowed', __( 'This file cannot be quarantined.', 'bee-monitor' ) );
		}
		$id = self::store( $fs, $opt['abs'], $opt['rel'], 'quarantine', $finding );
		if ( is_wp_error( $id ) ) {
			return $id;
		}
		if ( ! $fs->delete( $opt['abs'] ) ) {
			return new \WP_Error( 'delete', __( 'A copy was quarantined, but the original could not be removed. Remove it manually.', 'bee-monitor' ) );
		}
		Storage::delete_baseline( $opt['rel'] );
		/* translators: %s: quarantine entry ID. */
		Findings::set_status( array( (int) $finding_id ), Findings::STATUS_RESOLVED, sprintf( __( 'Quarantined (entry %s).', 'bee-monitor' ), $id ), get_current_user_id() );
		Activity::log( 'file_quarantined', $opt['rel'], 'entry ' . $id );
		return $id;
	}

	/**
	 * Restore a quarantined or backed-up file to its original path.
	 *
	 * @param string $id        Entry ID.
	 * @param bool   $overwrite Allow replacing an existing file (used for repair rollbacks).
	 * @return true|\WP_Error
	 */
	public static function restore( $id, $overwrite = false ) {
		$fs = self::filesystem();
		if ( is_wp_error( $fs ) ) {
			return $fs;
		}
		$entries = self::entries();
		if ( ! isset( $entries[ $id ] ) ) {
			return new \WP_Error( 'missing', __( 'Quarantine entry not found.', 'bee-monitor' ) );
		}
		$entry = $entries[ $id ];
		$dest  = self::safe_path( $entry['rel'] );
		$copy  = self::dir() . '/' . $entry['file'];
		if ( '' === $dest ) {
			return new \WP_Error( 'path', __( 'The original location is no longer allowed.', 'bee-monitor' ) );
		}
		if ( @file_exists( $dest ) && ! $overwrite && 'repair-backup' !== $entry['kind'] ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return new \WP_Error( 'exists', __( 'A file already exists at the original location. Nothing was changed.', 'bee-monitor' ) );
		}
		$content = $fs->get_contents( $copy );
		if ( false === $content || ! hash_equals( (string) $entry['sha256'], hash( 'sha256', $content ) ) ) {
			return new \WP_Error( 'integrity', __( 'The quarantined copy is missing or was altered. Nothing was restored.', 'bee-monitor' ) );
		}
		if ( ! $fs->put_contents( $dest, $content, FS_CHMOD_FILE ) ) {
			return new \WP_Error( 'write', __( 'The file could not be written.', 'bee-monitor' ) );
		}
		$fs->delete( $copy );
		unset( $entries[ $id ] );
		Storage::set( 'quarantine', $entries );
		Activity::log( 'file_restored', $entry['rel'], 'entry ' . $id );
		return true;
	}

	/**
	 * Permanently delete a quarantined copy.
	 *
	 * @param string $id Entry ID.
	 * @return true|\WP_Error
	 */
	public static function delete_entry( $id ) {
		$fs = self::filesystem();
		if ( is_wp_error( $fs ) ) {
			return $fs;
		}
		$entries = self::entries();
		if ( ! isset( $entries[ $id ] ) ) {
			return new \WP_Error( 'missing', __( 'Quarantine entry not found.', 'bee-monitor' ) );
		}
		$fs->delete( self::dir() . '/' . $entries[ $id ]['file'] );
		$rel = $entries[ $id ]['rel'];
		unset( $entries[ $id ] );
		Storage::set( 'quarantine', $entries );
		Activity::log( 'quarantine_deleted', $rel, 'entry ' . $id );
		return true;
	}

	/**
	 * Quarantine entries, newest first.
	 *
	 * @return array
	 */
	public static function entries() {
		$entries = Storage::get( 'quarantine', array() );
		$entries = is_array( $entries ) ? $entries : array();
		uasort(
			$entries,
			function ( $a, $b ) {
				return (int) $b['time'] - (int) $a['time'];
			}
		);
		return $entries;
	}

	/**
	 * Whether a file is one of Bee Monitor's own quarantine control files with its exact template content.
	 * Anything else in the quarantine folder is scanned normally.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public static function is_control_file( $abs ) {
		$name = basename( $abs );
		if ( dirname( $abs ) !== self::dir() || ! isset( self::CONTROL_FILES[ $name ] ) ) {
			return false;
		}
		return hash( 'sha256', self::CONTROL_FILES[ $name ] ) === (string) @hash_file( 'sha256', $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
	}

	/**
	 * Quarantine folder.
	 *
	 * @return string
	 */
	public static function dir() {
		$uploads = wp_upload_dir( null, false );
		return Paths::normalize( $uploads['basedir'] ) . '/' . self::DIR_NAME;
	}

	/**
	 * Copy a file into quarantine with a non-executable name and record it.
	 *
	 * @param \WP_Filesystem_Base $fs      Filesystem.
	 * @param string              $abs     Source path.
	 * @param string              $rel     Relative path.
	 * @param string              $kind    quarantine|repair-backup.
	 * @param array               $finding Finding.
	 * @return string|\WP_Error Entry ID.
	 */
	private static function store( $fs, $abs, $rel, $kind, array $finding ) {
		$entries = self::entries();
		if ( count( $entries ) >= self::MAX_ENTRIES ) {
			return new \WP_Error( 'full', __( 'The quarantine is full. Delete old entries first. Nothing was changed.', 'bee-monitor' ) );
		}
		$dir = self::dir();
		if ( ! $fs->is_dir( $dir ) && ! $fs->mkdir( $dir, FS_CHMOD_DIR ) ) {
			return new \WP_Error( 'dir', __( 'The quarantine folder could not be created. Nothing was changed.', 'bee-monitor' ) );
		}
		foreach ( self::CONTROL_FILES as $name => $template ) {
			$fs->put_contents( $dir . '/' . $name, $template, FS_CHMOD_FILE );
		}

		$content = $fs->get_contents( $abs );
		if ( false === $content ) {
			return new \WP_Error( 'read', __( 'The file could not be read. Nothing was changed.', 'bee-monitor' ) );
		}
		$id   = strtolower( wp_generate_password( 12, false ) );
		$file = $id . '-' . strtolower( wp_generate_password( 16, false ) ) . '.bmq';
		if ( ! $fs->put_contents( $dir . '/' . $file, $content, 0600 ) || ! hash_equals( hash( 'sha256', $content ), (string) @hash_file( 'sha256', $dir . '/' . $file ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
			return new \WP_Error( 'copy', __( 'The quarantine copy could not be verified. Nothing was changed.', 'bee-monitor' ) );
		}
		$entries[ $id ] = array(
			'kind'    => $kind,
			'rel'     => $rel,
			'file'    => $file,
			'sha256'  => hash( 'sha256', $content ),
			'size'    => strlen( $content ),
			'time'    => time(),
			'actor'   => get_current_user_id(),
			'rule'    => $finding['rule'],
			'finding' => (int) $finding['id'],
		);
		Storage::set( 'quarantine', $entries );
		return $id;
	}

	/**
	 * Whether content matches an official checksum.
	 *
	 * @param string $body   Content.
	 * @param array  $source Source with md5/sha256 lists.
	 * @return bool
	 */
	private static function matches( $body, array $source ) {
		return ( $source['sha256'] && in_array( hash( 'sha256', $body ), $source['sha256'], true ) ) || ( $source['md5'] && in_array( md5( $body ), $source['md5'], true ) );
	}

	/**
	 * Direct filesystem access, or an error explaining why repairs are unavailable.
	 *
	 * @return \WP_Filesystem_Base|\WP_Error
	 */
	private static function filesystem() {
		global $wp_filesystem;
		$reason = self::unavailable_reason();
		if ( '' !== $reason ) {
			return new \WP_Error( 'unavailable', $reason );
		}
		if ( ! WP_Filesystem() || ! $wp_filesystem ) {
			return new \WP_Error( 'filesystem', __( 'The WordPress filesystem could not be initialized.', 'bee-monitor' ) );
		}
		return $wp_filesystem;
	}
}
