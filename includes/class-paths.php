<?php
/**
 * Filesystem locations and classification for Bee Monitor.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Path helpers.
 */
final class Paths {

	const EXECUTABLE_EXTENSIONS = array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phps', 'phar', 'pht', 'phpt', 'inc' );
	const CONFIG_NAMES          = array( 'wp-config.php', '.htaccess', '.user.ini', 'php.ini', 'web.config' );
	const DROPINS               = array( 'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php', 'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php' );
	const IMAGE_EXTENSIONS      = array( 'ico', 'gif', 'jpg', 'jpeg', 'png', 'webp', 'svg', 'bmp', 'txt' );

	/**
	 * Cached directory map.
	 *
	 * @var array|null
	 */
	private static $dirs = null;

	/**
	 * Normalize a path without a trailing slash.
	 *
	 * @param string $path Path.
	 * @return string
	 */
	public static function normalize( $path ) {
		$real = @realpath( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		return untrailingslashit( wp_normalize_path( false !== $real ? $real : $path ) );
	}

	/**
	 * Important directories.
	 *
	 * @return array
	 */
	public static function dirs() {
		if ( null !== self::$dirs ) {
			return self::$dirs;
		}
		global $wp_theme_directories;

		$abs     = self::normalize( ABSPATH );
		$content = self::normalize( WP_CONTENT_DIR );
		$upload  = wp_upload_dir( null, false );
		$uploads = array( ! empty( $upload['basedir'] ) ? self::normalize( $upload['basedir'] ) : $content . '/uploads', $content . '/blogs.dir' );
		$themes  = array();
		foreach ( (array) $wp_theme_directories as $dir ) {
			$themes[] = self::normalize( $dir );
		}
		if ( empty( $themes ) ) {
			$themes[] = self::normalize( get_theme_root() );
		}

		self::$dirs = array(
			'abspath'   => $abs,
			'parent'    => self::normalize( dirname( $abs ) ),
			'content'   => $content,
			'plugins'   => self::normalize( WP_PLUGIN_DIR ),
			'mu'        => self::normalize( WPMU_PLUGIN_DIR ),
			'themes'    => array_values( array_unique( $themes ) ),
			'uploads'   => array_values( array_unique( $uploads ) ),
			'volatile'  => array( $content . '/cache', $content . '/upgrade', $content . '/upgrade-temp-backup' ),
			'languages' => self::normalize( WP_LANG_DIR ),
			'self'      => self::normalize( BEE_MONITOR_DIR ),
		);
		return self::$dirs;
	}

	/**
	 * Scan roots. Each root has abs, label, recursive.
	 *
	 * @param bool $include_parent Whether to include the directory above ABSPATH (files only).
	 * @return array
	 */
	public static function roots( $include_parent ) {
		$d          = self::dirs();
		$candidates = array(
			''            => $d['abspath'],
			'@content'    => $d['content'],
			'@plugins'    => $d['plugins'],
			'@mu-plugins' => $d['mu'],
		);
		foreach ( $d['themes'] as $i => $themes ) {
			$candidates[ '@themes' . ( $i ? $i + 1 : '' ) ] = $themes;
		}
		foreach ( $d['uploads'] as $i => $uploads ) {
			$candidates[ '@uploads' . ( $i ? $i + 1 : '' ) ] = $uploads;
		}
		$roots = array();
		foreach ( $candidates as $label => $dir ) {
			if ( '' !== $label && ! self::readable_dir( $dir ) ) {
				continue;
			}
			$covered = false;
			foreach ( $roots as $root ) {
				if ( self::within( $dir, $root['abs'] ) ) {
					$covered = true;
					break;
				}
			}
			if ( ! $covered ) {
				$roots[] = array(
					'abs'       => $dir,
					'label'     => $label,
					'recursive' => true,
				);
			}
		}
		if ( $include_parent && $d['parent'] !== $d['abspath'] && self::readable_dir( $d['parent'] ) ) {
			$roots[] = array(
				'abs'       => $d['parent'],
				'label'     => '@parent',
				'recursive' => false,
			);
		}
		return $roots;
	}

	/**
	 * Whether a directory is readable, without emitting open_basedir warnings.
	 *
	 * @param string $dir Directory.
	 * @return bool
	 */
	public static function readable_dir( $dir ) {
		$basedir = (string) ini_get( 'open_basedir' );
		if ( '' !== $basedir ) {
			$allowed = false;
			foreach ( explode( PATH_SEPARATOR, $basedir ) as $base ) {
				$base = self::normalize( $base );
				if ( '' !== $base && self::within( $dir, $base ) ) {
					$allowed = true;
					break;
				}
			}
			if ( ! $allowed ) {
				return false;
			}
		}
		return @is_dir( $dir ) && @is_readable( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
	}

	/**
	 * Whether a path is inside (or equal to) a directory.
	 *
	 * @param string $path Path.
	 * @param string $dir  Directory.
	 * @return bool
	 */
	public static function within( $path, $dir ) {
		return 0 === strpos( $path . '/', rtrim( $dir, '/' ) . '/' );
	}

	/**
	 * Display path relative to its root.
	 *
	 * @param string $abs  Absolute normalized path.
	 * @param array  $root Root definition.
	 * @return string
	 */
	public static function to_rel( $abs, array $root ) {
		$sub = ltrim( substr( $abs, strlen( $root['abs'] ) ), '/' );
		return '' === $root['label'] ? $sub : $root['label'] . '/' . $sub;
	}

	/**
	 * Absolute path from a relative display path.
	 *
	 * @param string $rel Relative path.
	 * @return string
	 */
	public static function to_abs( $rel ) {
		if ( 0 === strpos( $rel, '@' ) ) {
			$label = strtok( $rel, '/' );
			foreach ( self::roots( true ) as $root ) {
				if ( $root['label'] === $label ) {
					return $root['abs'] . '/' . substr( $rel, strlen( $label ) + 1 );
				}
			}
		}
		return self::dirs()['abspath'] . '/' . $rel;
	}

	/**
	 * Classify a file by location.
	 *
	 * @param string $abs Absolute normalized path.
	 * @return string
	 */
	public static function area( $abs ) {
		$d    = self::dirs();
		$name = strtolower( basename( $abs ) );
		$dir  = dirname( $abs );

		if ( self::within( $abs, $d['self'] ) ) {
			return 'self';
		}
		if ( in_array( $name, self::CONFIG_NAMES, true ) && ( 'wp-config.php' !== $name || $dir === $d['abspath'] || $dir === $d['parent'] ) ) {
			return 'config';
		}
		foreach ( $d['uploads'] as $uploads ) {
			if ( self::within( $abs, $uploads ) ) {
				return 'uploads';
			}
		}
		foreach ( $d['volatile'] as $volatile ) {
			if ( self::within( $abs, $volatile ) ) {
				return 'cache';
			}
		}
		if ( self::within( $abs, $d['mu'] ) ) {
			return 'mu';
		}
		if ( self::within( $abs, $d['plugins'] ) ) {
			return 'plugin';
		}
		foreach ( $d['themes'] as $themes ) {
			if ( self::within( $abs, $themes ) ) {
				return 'theme';
			}
		}
		if ( self::within( $abs, $d['languages'] ) ) {
			return 'languages';
		}
		if ( $dir === $d['content'] && in_array( $name, self::DROPINS, true ) ) {
			return 'dropin';
		}
		if ( self::within( $abs, $d['content'] ) ) {
			return 'content';
		}
		if ( self::within( $abs, $d['abspath'] . '/wp-admin' ) || self::within( $abs, $d['abspath'] . '/wp-includes' ) ) {
			return 'core';
		}
		if ( $dir === $d['abspath'] ) {
			return 'root';
		}
		if ( $dir === $d['parent'] ) {
			return 'parent';
		}
		return 'other';
	}

	/**
	 * Whether a path is inside an uploads directory.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public static function in_uploads( $abs ) {
		foreach ( self::dirs()['uploads'] as $uploads ) {
			if ( self::within( $abs, $uploads ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Plugin or theme folder name for a path.
	 *
	 * @param string $abs  Absolute path.
	 * @param string $area Area.
	 * @return string
	 */
	public static function component( $abs, $area ) {
		$d    = self::dirs();
		$base = '';
		if ( 'plugin' === $area ) {
			$base = $d['plugins'];
		} elseif ( 'theme' === $area ) {
			foreach ( $d['themes'] as $themes ) {
				if ( self::within( $abs, $themes ) ) {
					$base = $themes;
					break;
				}
			}
		} elseif ( 'languages' === $area ) {
			return 'translations';
		} elseif ( 'self' === $area ) {
			return basename( $d['self'] );
		}
		if ( '' === $base ) {
			return '';
		}
		$sub   = ltrim( substr( $abs, strlen( $base ) ), '/' );
		$parts = explode( '/', $sub );
		return count( $parts ) > 1 ? $parts[0] : preg_replace( '/\.php$/', '', $parts[0] );
	}

	/**
	 * Whether a file name has an executable PHP-like extension.
	 *
	 * @param string   $name  File name.
	 * @param string[] $extra Extra extensions.
	 * @return bool
	 */
	public static function is_executable_name( $name, array $extra = array() ) {
		$name  = strtolower( $name );
		$parts = explode( '.', $name );
		array_shift( $parts );
		$all = array_merge( self::EXECUTABLE_EXTENSIONS, $extra );
		foreach ( $parts as $part ) {
			if ( in_array( $part, $all, true ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Whether a file name is a server or WordPress config file Bee Monitor tracks.
	 *
	 * @param string $name File name.
	 * @return bool
	 */
	public static function is_config_name( $name ) {
		return in_array( strtolower( $name ), self::CONFIG_NAMES, true );
	}

	/**
	 * Glob match for exclusions. "*" also matches "/".
	 *
	 * @param string $pattern Pattern.
	 * @param string $rel     Relative path.
	 * @return bool
	 */
	public static function matches( $pattern, $rel ) {
		$regex = '#^' . str_replace( array( '\*', '\?' ), array( '.*', '.' ), preg_quote( $pattern, '#' ) ) . '$#i';
		return 1 === preg_match( $regex, $rel );
	}

	/**
	 * Whether a relative path is excluded.
	 *
	 * @param string   $rel      Relative path.
	 * @param bool     $is_dir   Whether it is a directory.
	 * @param string[] $patterns Patterns.
	 * @return bool
	 */
	public static function excluded( $rel, $is_dir, array $patterns ) {
		foreach ( $patterns as $pattern ) {
			if ( self::matches( $pattern, $rel ) || ( $is_dir && self::matches( $pattern, $rel . '/' ) ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Source file of a callback, if it can be determined.
	 *
	 * @param mixed $callback Callback.
	 * @return string Normalized absolute path or empty string.
	 */
	public static function callback_file( $callback ) {
		try {
			if ( $callback instanceof \Closure ) {
				$ref = new \ReflectionFunction( $callback );
			} elseif ( is_string( $callback ) && false !== strpos( $callback, '::' ) ) {
				$ref = new \ReflectionMethod( $callback );
			} elseif ( is_string( $callback ) && function_exists( $callback ) ) {
				$ref = new \ReflectionFunction( $callback );
			} elseif ( is_array( $callback ) && 2 === count( $callback ) && is_string( $callback[1] ) ) {
				$ref = new \ReflectionMethod( $callback[0], $callback[1] );
			} elseif ( is_object( $callback ) && method_exists( $callback, '__invoke' ) ) {
				$ref = new \ReflectionMethod( $callback, '__invoke' );
			} else {
				return '';
			}
			$file = $ref->getFileName();
			return $file ? self::normalize( $file ) : '';
		} catch ( \ReflectionException $e ) {
			return '';
		}
	}

	/**
	 * Source files of all callbacks on a hook.
	 *
	 * @param string $hook Hook name.
	 * @return string[]
	 */
	public static function hook_files( $hook ) {
		global $wp_filter;
		$files = array();
		if ( empty( $wp_filter[ $hook ] ) || ! is_object( $wp_filter[ $hook ] ) ) {
			return $files;
		}
		foreach ( (array) $wp_filter[ $hook ]->callbacks as $callbacks ) {
			foreach ( (array) $callbacks as $cb ) {
				if ( isset( $cb['function'] ) ) {
					$file = self::callback_file( $cb['function'] );
					if ( '' !== $file && ! self::is_wp_cli_file( $file ) ) {
						$files[ $file ] = $file;
					}
				}
			}
		}
		return array_values( $files );
	}

	/**
	 * Whether a file belongs to WP-CLI itself (only when running under WP-CLI).
	 *
	 * @param string $file Path.
	 * @return bool
	 */
	private static function is_wp_cli_file( $file ) {
		if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
			return false;
		}
		if ( 0 === strpos( $file, 'phar://' ) ) {
			return true;
		}
		return defined( 'WP_CLI_ROOT' ) && self::within( $file, self::normalize( WP_CLI_ROOT ) );
	}

	/**
	 * Display path for any absolute path.
	 *
	 * @param string $abs Absolute path.
	 * @return string
	 */
	public static function display( $abs ) {
		foreach ( self::roots( true ) as $root ) {
			if ( ( $root['recursive'] && self::within( $abs, $root['abs'] ) ) || dirname( $abs ) === $root['abs'] ) {
				return self::to_rel( $abs, $root );
			}
		}
		return '@external/' . basename( $abs );
	}

	/**
	 * Whether a callback source location is suspicious.
	 *
	 * @param string $abs Absolute path.
	 * @return bool
	 */
	public static function is_suspicious_source( $abs ) {
		return in_array( self::area( $abs ), array( 'uploads', 'cache', 'parent', 'other', 'content', 'root', 'languages' ), true );
	}
}
