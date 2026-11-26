<?php
/**
 * Pattern-based indicators for PHP and server configuration files.
 *
 * Matches are indicators for human review, never proof of malware.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Heuristic inspection.
 */
final class Heuristics {

	const MAX_MATCHES = 8;

	/**
	 * PHP indicator rules.
	 *
	 * @return array
	 */
	private static function php_rules() {
		return array(
			array( 'exec_from_request', 10, 'exec', true, '~\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|create_function)\s*\((?:(?!;).){0,120}\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)\b~is', __( 'Request data reaches a code or command execution function', 'bee-monitor' ) ),
			array( 'request_as_function', 10, 'exec', true, '~\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]{1,64}\]\s*\(~', __( 'Request data is called as a function', 'bee-monitor' ) ),
			array( 'shell_markers', 10, 'shell', true, '~\b(?:FilesMan|c99shell|r57shell|b374k|WSO\s?[0-9.]+|IndoXploit|Alfa-?Shell|p0wny|weevely)\b~i', __( 'Contains strings associated with known web shells', 'bee-monitor' ) ),
			array( 'eval_decode', 8, 'exec', false, '~\b(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|hex2bin|convert_uudecode)\s*\(~i', __( 'Decoded data is executed directly', 'bee-monitor' ) ),
			array( 'var_function_request', 6, 'exec', false, '~\$[A-Za-z_]\w*\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b~', __( 'A variable function is called with request data', 'bee-monitor' ) ),
			array( 'backtick_request', 6, 'exec', false, '~`[^`\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)~', __( 'Request data inside backticks (shell execution or unsafe SQL)', 'bee-monitor' ) ),
			array( 'preg_replace_e', 6, 'exec', false, '~preg_replace\s*\(\s*[\'"]/[^\n]{0,200}?/[a-zA-Z]*e[a-zA-Z]*[\'"]~', __( 'preg_replace with the /e (execute) modifier', 'bee-monitor' ) ),
			array( 'decode_chain', 5, 'decode', false, '~\b(?:gzinflate|gzuncompress|gzdecode)\s*\(\s*@?\s*(?:base64_decode|str_rot13|strrev)\s*\(~i', __( 'Layered decoding of compressed data', 'bee-monitor' ) ),
			array( 'eval_variable', 4, 'exec', false, '~\beval\s*\(\s*\$~i', __( 'eval() of a variable', 'bee-monitor' ) ),
			array( 'assert_variable', 4, 'exec', false, '~\bassert\s*\(\s*\$~i', __( 'assert() of a variable (code execution on older PHP)', 'bee-monitor' ) ),
			array( 'file_write_request', 4, 'write', false, '~\b(?:file_put_contents|fwrite|fputs|move_uploaded_file|copy)\s*\((?:(?!;).){0,160}\$_(?:GET|POST|REQUEST|FILES|COOKIE)\b~is', __( 'Writes files using request data', 'bee-monitor' ) ),
			array( 'create_function', 3, 'exec', false, '~\bcreate_function\s*\(~i', __( 'create_function() builds code from strings', 'bee-monitor' ) ),
			array( 'long_encoded', 3, 'decode', false, '~[\'"][A-Za-z0-9+/=]{1000,}+[\'"]~', __( 'Long encoded string literal', 'bee-monitor' ) ),
			array( 'hex_escapes', 3, 'decode', false, '~(?:\\\\x[0-9a-fA-F]{2}){24,}~', __( 'Dense hex-escaped string', 'bee-monitor' ) ),
			array( 'chr_chain', 3, 'decode', false, '~(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){8,}~i', __( 'String assembled from chr() calls', 'bee-monitor' ) ),
			array( 'globals_call', 3, 'exec', false, '~\$GLOBALS\s*\[\s*[\'"][^\'"]+[\'"]\s*\](?:\s*\[\s*\d+\s*\])?\s*\(~', __( 'Function called through $GLOBALS (common obfuscation)', 'bee-monitor' ) ),
			array( 'silenced_exec', 3, 'exec', false, '~@\s*(?:eval|assert|system|exec|shell_exec|passthru)\s*\(~i', __( 'Execution function with errors silenced', 'bee-monitor' ) ),
			array( 'eval_any', 2, 'exec', false, '~\beval\s*\(~i', __( 'Uses eval()', 'bee-monitor' ) ),
			array( 'str_rot13', 1, 'decode', false, '~\bstr_rot13\s*\(~i', __( 'Uses str_rot13()', 'bee-monitor' ) ),
			array( 'base64_decode', 1, 'decode', false, '~\bbase64_decode\s*\(~i', __( 'Uses base64_decode()', 'bee-monitor' ) ),
		);
	}

	/**
	 * Server/WordPress configuration rules.
	 *
	 * @return array
	 */
	private static function config_rules() {
		return array(
			array( 'php_handler', Findings::HIGH, '~^\s*(?:AddHandler|SetHandler|AddType|Action)\b[^\n]*(?:php|x-httpd)~im', __( 'Maps files to the PHP handler', 'bee-monitor' ) ),
			array( 'auto_prepend', Findings::HIGH, '~\b(?:auto_prepend_file|auto_append_file)\b~i', __( 'Sets auto_prepend_file or auto_append_file (runs code on every request; also used legitimately by some firewalls such as Wordfence)', 'bee-monitor' ) ),
			array( 'seo_cloaking', Findings::HIGH, '~RewriteCond\s+%\{HTTP_(?:USER_AGENT|REFERER)\}[^\n]*(?:google|bing|yahoo|yandex|baidu)~i', __( 'Rewrites requests based on search engine user agents or referrers (SEO spam cloaking)', 'bee-monitor' ) ),
			array( 'php_value', Findings::MEDIUM, '~^\s*php_(?:value|flag|admin_value|admin_flag)\s+\S+~im', __( 'Changes PHP settings', 'bee-monitor' ) ),
			array( 'external_redirect', Findings::MEDIUM, '~^\s*(?:RewriteRule\s+\S+\s+https?://|Redirect(?:Match|Permanent)?\s+(?:\d{3}\s+)?\S+\s+https?://|ErrorDocument\s+\d{3}\s+https?://)~im', __( 'Redirects visitors to an external address', 'bee-monitor' ) ),
		);
	}

	/**
	 * Inspect PHP source.
	 *
	 * @param string $content Source.
	 * @return array score, shell, matches, kinds.
	 */
	public static function inspect_php( $content ) {
		$result = array(
			'score'   => 0,
			'shell'   => false,
			'matches' => array(),
		);
		$kinds  = array();

		foreach ( self::php_rules() as $rule ) {
			list( $id, $weight, $kind, $shell, $regex, $label ) = $rule;
			if ( ! preg_match( $regex, $content, $m, PREG_OFFSET_CAPTURE ) ) {
				continue;
			}
			if ( 'eval_any' === $id && isset( $result['matches']['eval_variable'] ) ) {
				continue;
			}
			$result['score']         += $weight;
			$kinds[ $kind ]           = true;
			$result['shell']          = $result['shell'] || $shell;
			$result['matches'][ $id ] = self::match_evidence( $content, $m[0][1], $label, $id );
		}

		if ( preg_match_all( '~\bgoto\s+\w+\s*;~', $content ) >= 15 ) {
			$result['score']              += 3;
			$kinds['decode']               = true;
			$result['matches']['goto_obf'] = array(
				'rule'  => 'goto_obf',
				'label' => __( 'Heavy use of goto (typical of obfuscators)', 'bee-monitor' ),
				'line'  => 0,
				'text'  => '',
			);
		}

		$longest = 0;
		foreach ( explode( "\n", $content ) as $line ) {
			$longest = max( $longest, strlen( $line ) );
			if ( $longest > 5000 ) {
				break;
			}
		}
		if ( $longest > 5000 ) {
			++$result['score'];
			$result['matches']['long_line'] = array(
				'rule'  => 'long_line',
				'label' => __( 'Very long line (minified or obfuscated code)', 'bee-monitor' ),
				'line'  => 0,
				'text'  => '',
			);
		}

		if ( ! empty( $kinds['decode'] ) && ! empty( $kinds['exec'] ) ) {
			$result['score'] += 3;
			$result['combo']  = true;
		}

		$result['matches'] = array_slice( array_values( $result['matches'] ), 0, self::MAX_MATCHES );
		return $result;
	}

	/**
	 * Severity and confidence for a PHP inspection result.
	 *
	 * @param array $result Result from inspect_php().
	 * @return array|null severity, confidence or null when below the reporting threshold.
	 */
	public static function verdict( array $result ) {
		if ( $result['shell'] ) {
			return array( Findings::HIGH, 'high' );
		}
		if ( $result['score'] >= 10 ) {
			return array( Findings::HIGH, 'medium' );
		}
		if ( $result['score'] >= 6 ) {
			return array( Findings::MEDIUM, 'low' );
		}
		if ( $result['score'] >= 3 ) {
			return array( Findings::LOW, 'low' );
		}
		return null;
	}

	/**
	 * Inspect a server config file or wp-config.php for injection indicators.
	 *
	 * @param string $content Content.
	 * @param string $name    Lowercase file name.
	 * @return array List of hits: rule, severity, label, line, text.
	 */
	public static function inspect_config( $content, $name ) {
		$hits = array();
		if ( 'wp-config.php' === $name ) {
			$rules = array(
				array( 'config_include_nonphp', Findings::CRITICAL, '~\b(?:include|require)(?:_once)?\s*\(?\s*[\'"][^\'"]+\.(?:ico|png|jpe?g|gif|txt|log|css|js|svg|zip|bak)[\'"]~i', __( 'Includes a non-PHP file as code', 'bee-monitor' ) ),
				array( 'config_include_uploads', Findings::CRITICAL, '~\b(?:include|require)(?:_once)?\s*\(?[^;]*uploads/~i', __( 'Includes code from the uploads directory', 'bee-monitor' ) ),
				array( 'auto_prepend', Findings::HIGH, '~\bini_set\s*\(\s*[\'"]auto_(?:prepend|append)_file~i', __( 'Sets auto_prepend_file at runtime', 'bee-monitor' ) ),
			);
		} else {
			$rules = self::config_rules();
		}
		foreach ( $rules as $rule ) {
			list( $id, $severity, $regex, $label ) = $rule;
			if ( preg_match( $regex, $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$evidence             = self::match_evidence( $content, $m[0][1], $label, $id );
				$evidence['severity'] = $severity;
				if ( 'wp-config.php' !== $name ) {
					$evidence['text'] = Redactor::config_line( self::line_at( $content, $m[0][1] ) );
				}
				$hits[] = $evidence;
			}
		}
		return $hits;
	}

	/**
	 * Whether PHP source is an inert stub (comments, whitespace, exit/die only).
	 *
	 * @param string $content Source.
	 * @return bool
	 */
	public static function is_inert_php( $content ) {
		if ( strlen( $content ) > 4096 ) {
			return false;
		}
		if ( function_exists( 'token_get_all' ) ) {
			$code = '';
			foreach ( token_get_all( $content ) as $token ) {
				if ( is_array( $token ) ) {
					if ( in_array( $token[0], array( T_OPEN_TAG, T_CLOSE_TAG, T_COMMENT, T_DOC_COMMENT, T_WHITESPACE ), true ) ) {
						continue;
					}
					$code .= $token[1];
				} else {
					$code .= $token;
				}
			}
		} else {
			$code = preg_replace( array( '~<\?php|\?>~i', '~/\*.*?\*/~s', '~(?://|#)[^\n]*~', '~\s+~' ), '', $content );
		}
		$code = strtolower( preg_replace( '~\s+~', '', $code ) );
		return in_array( $code, array( '', 'exit;', 'die;', 'exit();', 'die();', 'exit', 'die' ), true );
	}

	/**
	 * Whether non-PHP content contains PHP open tags.
	 *
	 * @param string $content Content.
	 * @return array|null Evidence when found.
	 */
	public static function php_in_content( $content ) {
		if ( preg_match( '~<\?(?:php|=)~i', $content, $m, PREG_OFFSET_CAPTURE ) ) {
			return self::match_evidence( $content, $m[0][1], __( 'Contains a PHP open tag', 'bee-monitor' ), 'php_tag' );
		}
		return null;
	}

	/**
	 * Raw line containing an offset.
	 *
	 * @param string $content Content.
	 * @param int    $offset  Byte offset.
	 * @return string
	 */
	private static function line_at( $content, $offset ) {
		$start = strrpos( substr( $content, 0, $offset ), "\n" );
		$start = false === $start ? 0 : $start + 1;
		$end   = strpos( $content, "\n", $offset );
		$end   = false === $end ? strlen( $content ) : $end;
		return substr( $content, $start, min( $end - $start, 2000 ) );
	}

	/**
	 * Build redacted evidence around an offset.
	 *
	 * @param string $content Content.
	 * @param int    $offset  Byte offset.
	 * @param string $label   Label.
	 * @param string $rule    Rule ID.
	 * @return array
	 */
	private static function match_evidence( $content, $offset, $label, $rule ) {
		$line_no    = substr_count( $content, "\n", 0, $offset ) + 1;
		$line_start = strrpos( substr( $content, 0, $offset ), "\n" );
		$line_start = false === $line_start ? 0 : $line_start + 1;
		$line_end   = strpos( $content, "\n", $offset );
		$line_end   = false === $line_end ? strlen( $content ) : $line_end;
		$line       = substr( $content, $line_start, min( $line_end - $line_start, 2000 ) );
		return array(
			'rule'  => $rule,
			'label' => $label,
			'line'  => $line_no,
			'text'  => Redactor::line( $line, $offset - $line_start ),
		);
	}
}
