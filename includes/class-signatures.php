<?php
/**
 * Local signature set for publicly documented WordPress backdoor and injector techniques.
 *
 * Signatures are patterns, not file hashes. A match is a lead for review, never proof of infection.
 * The set ships with the plugin and is updated only by plugin releases (no remote feeds).
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Signature definitions and matcher.
 */
final class Signatures {

	const VERSION = '2026.11.1';

	/**
	 * Signatures: id, severity, confidence, scope (php|any), regex, label.
	 *
	 * @return array
	 */
	private static function all() {
		return array(
			array( 'BM-SIG-001', Findings::CRITICAL, 'high', 'php', '~\b(?:eval|assert)\s*\([^;]{0,80}file_get_contents\s*\(\s*[\'"]php://input~i', __( 'Executes code read from the raw request body (php://input)', 'bee-monitor' ) ),
			array( 'BM-SIG-002', Findings::HIGH, 'high', 'php', '~\$_COOKIE\s*\[[^\]]{1,64}\]\s*\(|\b(?:eval|assert|create_function|system|passthru|shell_exec)\s*\([^;]{0,80}\$_COOKIE\b~i', __( 'Cookie-controlled code execution (cookie backdoor)', 'bee-monitor' ) ),
			array( 'BM-SIG-003', Findings::HIGH, 'high', 'php', '~\b(?:include|require)(?:_once)?\s*\(?\s*[\'"](?:\\\\x[0-9a-fA-F]{2}|\\\\[0-7]{3}){6,}~', __( 'Includes a file whose path is hidden with hex or octal escapes', 'bee-monitor' ) ),
			array( 'BM-SIG-004', Findings::HIGH, 'high', 'any', '~\AGIF8[79]a.{0,512}<\?(?:php|=)~is', __( 'Image header followed by PHP code (GIF/PHP polyglot)', 'bee-monitor' ) ),
			array( 'BM-SIG-005', Findings::CRITICAL, 'high', 'php', '~\b(?:eval|assert)\s*\(\s*(?:@?\s*(?:base64_decode|gzinflate|str_rot13)\s*\(\s*)?@?\s*(?:file_get_contents|wp_remote_retrieve_body|curl_exec)\s*\(\s*[\'"]?(?:https?:)?//~i', __( 'Downloads code from a remote URL and executes it', 'bee-monitor' ) ),
			array( 'BM-SIG-006', Findings::HIGH, 'medium', 'php', '~\b(?:echo|print)\b[^;]{0,200}<script[^;]{0,400}(?:String\.fromCharCode|eval\s*\(\s*atob|document\.write\s*\(\s*unescape)~is', __( 'PHP prints an obfuscated script into pages (script injector)', 'bee-monitor' ) ),
			array( 'BM-SIG-007', Findings::MEDIUM, 'low', 'php', '~\bwp_(?:insert|create)_user\b[^;]{0,300}[\'"]administrator[\'"]~is', __( 'Creates an administrator account in code', 'bee-monitor' ) ),
			array( 'BM-SIG-008', Findings::MEDIUM, 'medium', 'php', '~\berror_reporting\s*\(\s*0\s*\)[\s\S]{0,400}\bset_time_limit\s*\(\s*0\s*\)[\s\S]{0,400}\bignore_user_abort\s*\(~i', __( 'Silences errors and removes time limits together (typical of shells and spam mailers)', 'bee-monitor' ) ),
			array( 'BM-SIG-009', Findings::HIGH, 'medium', 'php', '~\b(?:echo|print|print_r|var_dump|var_export)\s*\(?\s*(?:DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY)\b~', __( 'Outputs database credentials or secret keys', 'bee-monitor' ) ),
			array( 'BM-SIG-010', Findings::HIGH, 'high', 'php', '~pre_user_query[\s\S]{0,400}user_login\s*(?:<>|!=|NOT\s+IN)~i', __( 'Hides user accounts from the WordPress user list', 'bee-monitor' ) ),
			array( 'BM-SIG-011', Findings::MEDIUM, 'medium', 'php', '~\bwp_schedule_(?:single_)?event\b[\s\S]{0,600}\bfile_put_contents\s*\([\s\S]{0,200}\bbase64_decode\b~i', __( 'Scheduled task that writes decoded data to files (reinfection)', 'bee-monitor' ) ),
			array( 'BM-SIG-012', Findings::HIGH, 'medium', 'php', '~\$_FILES\b[\s\S]{0,400}\bmove_uploaded_file\b[\s\S]{0,800}<form[^>]+enctype=[\'"]multipart/form-data~i', __( 'Standalone file uploader with its own form (uploader shell)', 'bee-monitor' ) ),
			array( 'BM-SIG-013', Findings::HIGH, 'medium', 'php', '~\$\w+\s*=\s*[\'"][a-z_]{2,8}[\'"]\s*\.\s*[\'"][a-z_]{2,8}[\'"][\s\S]{0,120}\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)~i', __( 'Builds a function name from string pieces and calls it with request data', 'bee-monitor' ) ),
			array( 'BM-SIG-014', Findings::MEDIUM, 'medium', 'php', '~add_action\s*\(\s*[\'"](?:wp_head|wp_footer)[\'"][\s\S]{0,300}(?:base64_decode|gzinflate|str_rot13)\s*\(~i', __( 'Outputs decoded content into every page header or footer', 'bee-monitor' ) ),
		);
	}

	/**
	 * Match content against signatures.
	 *
	 * @param string $content Content.
	 * @param string $scope   php or any.
	 * @return array List of [ id, severity, confidence, label, offset ].
	 */
	public static function match( $content, $scope ) {
		$hits = array();
		foreach ( self::all() as $sig ) {
			list( $id, $severity, $confidence, $sig_scope, $regex, $label ) = $sig;
			if ( 'php' === $sig_scope && 'php' !== $scope ) {
				continue;
			}
			if ( preg_match( $regex, $content, $m, PREG_OFFSET_CAPTURE ) ) {
				$hits[] = array( $id, $severity, $confidence, $label, $m[0][1] );
			}
		}
		return $hits;
	}

	/**
	 * Number of signatures.
	 *
	 * @return int
	 */
	public static function count() {
		return count( self::all() );
	}
}
