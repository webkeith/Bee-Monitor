<?php
/**
 * Optional checks of the site's own public pages, as visitors and search engines see them.
 *
 * Requests go only to this site's own URLs. Remote checks see rendered output, not server-side
 * files, so they complement file scanning and cannot replace it.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Remote page checks.
 */
final class Remote {

	const MAX_URLS  = 7;
	const TIMEOUT   = 8;
	const MAX_BYTES = 1048576;
	const RULES     = array( 'remote_redirect', 'remote_injected_script', 'remote_obfuscated_script', 'remote_hidden_iframe', 'remote_hidden_links', 'remote_cloaking', 'remote_php_error', 'remote_site_error', 'remote_unreachable' );

	/**
	 * URLs to check: home, login, and recently modified public posts and pages.
	 *
	 * @return string[]
	 */
	public static function queue() {
		$urls = array( home_url( '/' ), wp_login_url() );
		$ids  = get_posts(
			array(
				'post_type'    => array( 'post', 'page' ),
				'post_status'  => 'publish',
				'has_password' => false,
				'orderby'      => 'modified',
				'order'        => 'DESC',
				'numberposts'  => self::MAX_URLS - 2,
				'fields'       => 'ids',
			)
		);
		foreach ( $ids as $id ) {
			$link = get_permalink( $id );
			if ( $link ) {
				$urls[] = $link;
			}
		}
		return array_slice( array_values( array_unique( $urls ) ), 0, self::MAX_URLS );
	}

	/**
	 * Hosts that count as this site.
	 *
	 * @return string[]
	 */
	public static function own_hosts() {
		$hosts = array();
		foreach ( array( home_url(), site_url() ) as $url ) {
			$host = strtolower( (string) wp_parse_url( $url, PHP_URL_HOST ) );
			if ( '' !== $host ) {
				$hosts[] = $host;
				$hosts[] = 0 === strpos( $host, 'www.' ) ? substr( $host, 4 ) : 'www.' . $host;
			}
		}
		return array_values( array_unique( $hosts ) );
	}

	/**
	 * Check one URL. Returns the finding keys found (rule|subject) for auto-resolution.
	 *
	 * @param string $url  URL.
	 * @param bool   $home Whether this is the home page (also checks cloaking).
	 * @return string[]
	 */
	public static function check( $url, $home ) {
		$found   = array();
		$subject = self::subject( $url );
		$visitor = self::fetch( $url, 'Mozilla/5.0 (compatible; Bee Monitor/' . BEE_MONITOR_VERSION . ' remote check)' );

		if ( is_wp_error( $visitor ) ) {
			$found[] = self::record( 'remote_unreachable', Findings::LOW, 'medium', $subject, __( 'Bee Monitor could not load this page from the server itself (a loopback request). Some hosts block these requests; the page may still work for visitors.', 'bee-monitor' ), array( 'url' => $subject ), substr( $visitor->get_error_code(), 0, 40 ) );
			return $found;
		}
		if ( $visitor['code'] >= 300 && $visitor['code'] < 400 && '' !== $visitor['location'] ) {
			$host = strtolower( (string) wp_parse_url( $visitor['location'], PHP_URL_HOST ) );
			if ( '' !== $host && ! in_array( $host, self::own_hosts(), true ) ) {
				$found[] = self::record(
					'remote_redirect',
					Findings::HIGH,
					'high',
					$subject,
					__( 'This page redirects visitors to another website. Malicious redirects are a common sign of compromise; legitimate ones are usually set up deliberately in a redirect plugin or server configuration.', 'bee-monitor' ),
					array(
						'url'           => $subject,
						'http_status'   => $visitor['code'],
						'redirect_host' => $host,
					),
					$host
				);
				return $found;
			}
			$next = self::fetch( $visitor['location'], 'Mozilla/5.0 (compatible; Bee Monitor/' . BEE_MONITOR_VERSION . ' remote check)' );
			if ( is_wp_error( $next ) ) {
				return $found;
			}
			$visitor = $next;
		}
		if ( $visitor['code'] >= 500 ) {
			$found[] = self::record(
				'remote_site_error',
				Findings::MEDIUM,
				'confirmed',
				$subject,
				__( 'This page returns a server error to visitors.', 'bee-monitor' ),
				array(
					'url'         => $subject,
					'http_status' => $visitor['code'],
				),
				(string) $visitor['code']
			);
		}
		$found = array_merge( $found, self::analyze( $visitor['body'], $subject ) );

		if ( $home && $visitor['code'] < 400 ) {
			$bot = self::fetch( $url, 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' );
			if ( ! is_wp_error( $bot ) && $bot['code'] < 300 ) {
				$extra = array_diff( self::link_domains( $bot['body'] ), self::link_domains( $visitor['body'] ) );
				if ( $extra ) {
					$extra   = array_slice( array_values( $extra ), 0, 10 );
					$found[] = self::record(
						'remote_cloaking',
						Findings::HIGH,
						'medium',
						$subject,
						__( 'Search engines are shown links to other websites that normal visitors do not see. This is a typical sign of SEO spam injection (cloaking).', 'bee-monitor' ),
						array(
							'url'     => $subject,
							'domains' => $extra,
						),
						md5( implode( ',', $extra ) )
					);
				}
			}
		}
		return $found;
	}

	/**
	 * Body checks.
	 *
	 * @param string $html    HTML.
	 * @param string $subject Subject.
	 * @return string[]
	 */
	private static function analyze( $html, $subject ) {
		$found = array();
		$own   = self::own_hosts();
		$allow = array_merge( $own, array_filter( array_map( 'trim', explode( "\n", (string) Settings::value( 'content_domain_allowlist' ) ) ) ) );

		if ( preg_match( '~<b>(?:Fatal error|Parse error|Warning|Notice|Deprecated)</b>:|\b(?:Fatal error|Parse error|Uncaught (?:Error|Exception)):[^<]{0,200} in /[^<]{1,200} on line \d+~', $html ) ) {
			$found[] = self::record( 'remote_php_error', Findings::LOW, 'high', $subject, __( 'PHP errors are visible on this page. They reveal file paths and can indicate broken or tampered code.', 'bee-monitor' ), array( 'url' => $subject ), '' );
		}

		$domains = array();
		if ( preg_match_all( '~<script[^>]+src\s*=\s*["\']?\s*(?:https?:)?//([^/"\'\s>:]+)~i', $html, $m ) ) {
			foreach ( $m[1] as $domain ) {
				$domain = strtolower( $domain );
				if ( ! self::allowed( $domain, $allow ) ) {
					$domains[ $domain ] = $domain;
				}
			}
		}
		if ( $domains ) {
			$domains = array_slice( array_values( $domains ), 0, 10 );
			$found[] = self::record(
				'remote_injected_script',
				Findings::MEDIUM,
				'low',
				$subject,
				__( 'The rendered page loads scripts from domains that are not on the trusted list. Confirm each one is a service you use.', 'bee-monitor' ),
				array(
					'url'     => $subject,
					'domains' => $domains,
				),
				md5( implode( ',', $domains ) )
			);
		}

		if ( preg_match_all( '~<script\b[^>]*>(.*?)</script>~is', $html, $blocks ) ) {
			foreach ( $blocks[1] as $code ) {
				$code = substr( $code, 0, 20000 );
				if ( preg_match( '~eval\s*\(\s*(?:atob|unescape|String\.fromCharCode)|document\.write\s*\(\s*unescape|(?:\\\\x[0-9a-fA-F]{2}){40,}~i', $code ) ) {
					$found[] = self::record( 'remote_obfuscated_script', Findings::HIGH, 'medium', $subject, __( 'The page contains an inline script with obfuscation patterns commonly used by injected malware.', 'bee-monitor' ), array( 'url' => $subject ), '' );
					break;
				}
			}
		}

		if ( preg_match_all( '~<iframe\b[^>]*>~i', $html, $frames ) ) {
			foreach ( $frames[0] as $tag ) {
				if ( preg_match( '~(?:width|height)\s*=\s*["\']?0\b|display\s*:\s*none|visibility\s*:\s*hidden~i', $tag ) && preg_match( '~src\s*=\s*["\']?\s*(?:https?:)?//([^/"\'\s>:]+)~i', $tag, $src ) && ! self::allowed( strtolower( $src[1] ), $allow ) ) {
					$found[] = self::record(
						'remote_hidden_iframe',
						Findings::HIGH,
						'medium',
						$subject,
						__( 'The page contains a hidden frame that loads another website.', 'bee-monitor' ),
						array(
							'url'     => $subject,
							'domains' => array( strtolower( $src[1] ) ),
						),
						strtolower( $src[1] )
					);
					break;
				}
			}
		}

		if ( preg_match( '~<meta[^>]+http-equiv\s*=\s*["\']?refresh[^>]+url\s*=\s*["\']?(?:https?:)?//([^/"\'\s>;]+)~i', $html, $meta ) || preg_match( '~(?:window|document|top|self)\.location(?:\.href)?\s*=\s*["\'](?:https?:)?//([^/"\']+)~i', $html, $meta ) ) {
			$host = strtolower( $meta[1] );
			if ( ! in_array( $host, $own, true ) ) {
				$found[] = self::record(
					'remote_redirect',
					Findings::HIGH,
					'medium',
					$subject,
					__( 'The page contains code that sends visitors to another website.', 'bee-monitor' ),
					array(
						'url'           => $subject,
						'redirect_host' => $host,
					),
					$host
				);
			}
		}

		if ( preg_match_all( '~<(?:div|span|p)\b[^>]*style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top)\s*:\s*-\d{3,}px)[^"\']*["\'][^>]*>~i', $html, $boxes, PREG_OFFSET_CAPTURE ) ) {
			foreach ( $boxes[0] as $box ) {
				$region = substr( $html, $box[1] + strlen( $box[0] ), 3000 );
				$close  = stripos( $region, '</div>' );
				$region = false === $close ? $region : substr( $region, 0, $close );
				if ( preg_match( '~<a\s[^>]*href\s*=\s*["\']?(?:https?:)?//([^/"\'\s>]+)~i', $region, $link ) && ! self::allowed( strtolower( $link[1] ), $allow ) ) {
					$found[] = self::record(
						'remote_hidden_links',
						Findings::MEDIUM,
						'medium',
						$subject,
						__( 'The page contains links to another website inside hidden content, a common SEO spam technique.', 'bee-monitor' ),
						array(
							'url'     => $subject,
							'domains' => array( strtolower( $link[1] ) ),
						),
						strtolower( $link[1] )
					);
					break;
				}
			}
		}
		return $found;
	}

	/**
	 * External link domains in HTML.
	 *
	 * @param string $html HTML.
	 * @return string[]
	 */
	private static function link_domains( $html ) {
		$out = array();
		if ( preg_match_all( '~<a\s[^>]*href\s*=\s*["\']?(?:https?:)?//([^/"\'\s>:]+)~i', $html, $m ) ) {
			foreach ( $m[1] as $domain ) {
				$domain = strtolower( $domain );
				if ( ! in_array( $domain, self::own_hosts(), true ) ) {
					$out[ $domain ] = $domain;
				}
			}
		}
		return array_values( $out );
	}

	/**
	 * Whether a domain is trusted (exact or subdomain match).
	 *
	 * @param string   $domain Domain.
	 * @param string[] $allow  Trusted domains.
	 * @return bool
	 */
	private static function allowed( $domain, array $allow ) {
		foreach ( $allow as $trusted ) {
			if ( $domain === $trusted || substr( $domain, -strlen( '.' . $trusted ) ) === '.' . $trusted ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Fetch a page without following redirects.
	 *
	 * @param string $url        URL.
	 * @param string $user_agent User agent.
	 * @return array|\WP_Error code, location, body.
	 */
	private static function fetch( $url, $user_agent ) {
		$response = wp_safe_remote_get(
			$url,
			array(
				'timeout'             => self::TIMEOUT,
				'redirection'         => 0,
				'user-agent'          => $user_agent,
				'limit_response_size' => self::MAX_BYTES,
				'sslverify'           => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core loopback filter.
			)
		);
		if ( is_wp_error( $response ) ) {
			return $response;
		}
		return array(
			'code'     => (int) wp_remote_retrieve_response_code( $response ),
			'location' => (string) wp_remote_retrieve_header( $response, 'location' ),
			'body'     => (string) wp_remote_retrieve_body( $response ),
		);
	}

	/**
	 * Display subject for a URL (path only).
	 *
	 * @param string $url URL.
	 * @return string
	 */
	private static function subject( $url ) {
		$path  = (string) wp_parse_url( $url, PHP_URL_PATH );
		$query = (string) wp_parse_url( $url, PHP_URL_QUERY );
		$path  = ( '' === $path ? '/' : $path ) . ( '' !== $query ? '?' . $query : '' );
		return __( 'Public page', 'bee-monitor' ) . ' ' . substr( $path, 0, 150 );
	}

	/**
	 * Record a remote finding and return its key.
	 *
	 * @param string $rule       Rule.
	 * @param int    $severity   Severity.
	 * @param string $confidence Confidence.
	 * @param string $subject    Subject.
	 * @param string $reason     Reason.
	 * @param array  $evidence   Evidence.
	 * @param string $key        Dedup key.
	 * @return string
	 */
	private static function record( $rule, $severity, $confidence, $subject, $reason, array $evidence, $key ) {
		$evidence['verification'] = 'pattern';
		Findings::record(
			array(
				'rule'        => $rule,
				'severity'    => $severity,
				'confidence'  => $confidence,
				'basis'       => 'heuristic',
				'change_type' => 'detected',
				'subject'     => $subject,
				'reason'      => $reason,
				'evidence'    => $evidence,
				'key'         => $key,
			)
		);
		return $rule . '|' . $subject;
	}

	/**
	 * Resolve remote findings whose condition was not seen in this run.
	 *
	 * @param string[] $found Keys found (rule|subject).
	 */
	public static function settle( array $found ) {
		foreach ( self::RULES as $rule ) {
			$keep = array();
			foreach ( $found as $key ) {
				if ( 0 === strpos( $key, $rule . '|' ) ) {
					$keep[] = substr( $key, strlen( $rule ) + 1 );
				}
			}
			Findings::auto_resolve( $rule, $keep );
		}
	}
}
