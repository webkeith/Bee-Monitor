<?php
/**
 * Removes secrets and personal data from evidence before it is stored or emailed.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Redaction helpers.
 */
final class Redactor {

	/**
	 * Redact one line of source or config text and trim it to a short snippet.
	 *
	 * @param string $line   Text.
	 * @param int    $center Offset to center the snippet on.
	 * @param int    $width  Max characters.
	 * @return string
	 */
	public static function line( $line, $center = 0, $width = 160 ) {
		$line = (string) $line;
		$line = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $line );
		$line = wp_check_invalid_utf8( $line, true );

		if ( function_exists( 'mb_strlen' ) && mb_strlen( $line ) > $width * 3 ) {
			$start = max( 0, $center - $width );
			$line  = ( $start > 0 ? '…' : '' ) . mb_substr( $line, $start, $width * 2 ) . '…';
		}

		$line = preg_replace( "/(define\s*\(\s*['\"][A-Z0-9_]*(?:KEY|SALT|PASSWORD|PASS|SECRET|TOKEN|USER|HOST|NAME|NONCE|AUTH)[A-Z0-9_]*['\"]\s*,\s*)(['\"]).*?\\2/i", '$1\'[redacted]\'', $line );
		$line = preg_replace( "/((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|auth[_-]?key|private[_-]?key|access[_-]?key)['\"]?\s*(?:=>|=|:)\s*)(['\"]).*?\\2/i", '$1\'[redacted]\'', $line );
		$line = preg_replace( '/(:\/\/[^:\/\s]+:)[^@\s]+@/', '$1[redacted]@', $line );
		$line = preg_replace( '/\b((?:SetEnv|SetEnvIf|export)\s+\S*(?:PASS|SECRET|TOKEN|KEY|AUTH)\S*\s+)\S+/i', '$1[redacted]', $line );
		$line = preg_replace_callback(
			'/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i',
			function ( $m ) {
				return self::email( $m[0] );
			},
			$line
		);
		$line = preg_replace_callback(
			'/[A-Za-z0-9+\/=_\\\\x-]{48,}/',
			function ( $m ) {
				return substr( $m[0], 0, 16 ) . '…[+' . ( strlen( $m[0] ) - 16 ) . ' chars]';
			},
			$line
		);

		if ( function_exists( 'mb_strlen' ) && mb_strlen( $line ) > $width ) {
			$line = mb_substr( $line, 0, $width ) . '…';
		} elseif ( strlen( $line ) > $width ) {
			$line = substr( $line, 0, $width ) . '…';
		}
		return trim( $line );
	}

	/**
	 * Server config evidence: directive and first argument only, plus the target host of a redirect.
	 *
	 * @param string $line Config line.
	 * @return string
	 */
	public static function config_line( $line ) {
		$line = trim( (string) $line );
		$host = '';
		if ( preg_match( '#https?://([^/\s"\']+)#i', $line, $m ) ) {
			$host = ' → ' . strtolower( $m[1] );
		}
		$parts = preg_split( '/\s+/', $line, 3 );
		$out   = $parts[0] . ( isset( $parts[1] ) ? ' ' . $parts[1] : '' ) . ( isset( $parts[2] ) ? ' [value hidden]' : '' );
		return self::line( $out . $host );
	}

	/**
	 * Mask an email address: k***@example.com.
	 *
	 * @param string $email Email.
	 * @return string
	 */
	public static function email( $email ) {
		$email = (string) $email;
		$at    = strpos( $email, '@' );
		if ( false === $at ) {
			return '***';
		}
		return substr( $email, 0, 1 ) . '***' . substr( $email, $at );
	}

	/**
	 * Mask an IP address to its network: 203.0.113.x or 2001:db8:1::x.
	 *
	 * @param string $ip IP address.
	 * @return string
	 */
	public static function ip( $ip ) {
		$ip = (string) $ip;
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			$parts = explode( '.', $ip );
			return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.x';
		}
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			$packed = inet_pton( $ip );
			$hex    = bin2hex( substr( $packed, 0, 6 ) );
			return implode( ':', str_split( $hex, 4 ) ) . '::x';
		}
		return 'unknown';
	}

	/**
	 * Short hash prefix for display.
	 *
	 * @param string $hash Hash.
	 * @return string
	 */
	public static function hash( $hash ) {
		$hash = (string) $hash;
		return strlen( $hash ) > 16 ? substr( $hash, 0, 12 ) . '…' . substr( $hash, -4 ) : $hash;
	}
}
