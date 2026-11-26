<?php
/**
 * Exportable findings reports (JSON and CSV).
 *
 * Personal data and the site address are excluded unless explicitly requested.
 * Evidence is exported through an allowlist; it is already redacted when stored.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Report builder.
 */
final class Report {

	const SAFE_EVIDENCE = array( 'path', 'area', 'component', 'size', 'modified', 'sha256', 'previous_sha256', 'previous_size', 'md5', 'official_md5', 'indicators', 'score', 'sources', 'domains', 'hook', 'option', 'role', 'roles', 'previous_roles', 'gained', 'mode', 'file', 'failures', 'distinct_names', 'existing_accounts', 'post_id', 'length', 'changed', 'enabled', 'exclusions', 'ignore_rule', 'official', 'app_name', 'created', 'verification', 'url', 'http_status', 'redirect_host', 'signature' );

	const PERSONAL_EVIDENCE = array( 'user_id', 'login', 'email', 'registered', 'network', 'top_networks', 'context', 'recipients', 'old', 'new' );

	const PERSONAL_CATEGORIES = array( 'users', 'logins' );

	/**
	 * Build the report data.
	 *
	 * @param array $args status (open|all|...), include_personal (bool), include_site (bool).
	 * @return array
	 */
	public static function build( array $args ) {
		global $wp_version;
		$args     = wp_parse_args(
			$args,
			array(
				'status'           => 'open',
				'include_personal' => false,
				'include_site'     => false,
			)
		);
		$personal = (bool) $args['include_personal'];
		$result   = Findings::query(
			array(
				'status'       => $args['status'],
				'min_severity' => 0,
				'per_page'     => 5000,
			)
		);
		$meta     = Storage::get( 'baseline_meta', array() );
		$last     = Storage::get( 'last_scan', array() );
		$findings = array();
		foreach ( $result['items'] as $item ) {
			$findings[] = self::finding( $item, $personal );
		}
		$report = array(
			'generator'     => 'Bee Monitor ' . BEE_MONITOR_VERSION,
			'generated_at'  => gmdate( 'c' ),
			'redaction'     => array(
				'personal_data' => $personal ? 'included' : 'excluded',
				'site_address'  => $args['include_site'] ? 'included' : 'excluded',
				'secrets'       => 'excluded (evidence is redacted when stored; file contents are never stored)',
			),
			'environment'   => array(
				'wordpress' => $wp_version,
				'php'       => PHP_VERSION,
				'multisite' => is_multisite(),
			),
			'baseline'      => array(
				'status'     => is_array( $meta ) && isset( $meta['status'] ) ? $meta['status'] : 'missing',
				'created'    => is_array( $meta ) && ! empty( $meta['created'] ) ? gmdate( 'c', (int) $meta['created'] ) : null,
				'files'      => Storage::baseline_count(),
				'checksums'  => is_array( $meta ) && ! empty( $meta['checksums'] ),
				'wp_version' => is_array( $meta ) && isset( $meta['wp_version'] ) ? $meta['wp_version'] : null,
			),
			'last_scan'     => is_array( $last ) && ! empty( $last['finished'] ) ? array(
				'id'       => (int) $last['id'],
				'mode'     => $last['mode'],
				'finished' => gmdate( 'c', (int) $last['finished'] ),
				'stats'    => $last['stats'],
			) : null,
			'status_filter' => $args['status'],
			'counts'        => self::counts( $findings ),
			'findings'      => $findings,
		);
		if ( $args['include_site'] ) {
			$report['site'] = array(
				'name' => Notifier::label(),
				'url'  => Storage::trusted_urls()['home'],
			);
		}
		return $report;
	}

	/**
	 * One finding for export.
	 *
	 * @param array $item     Finding.
	 * @param bool  $personal Include personal data.
	 * @return array
	 */
	private static function finding( array $item, $personal ) {
		$category = Findings::category( $item['rule'] );
		$allowed  = $personal ? array_merge( self::SAFE_EVIDENCE, self::PERSONAL_EVIDENCE ) : self::SAFE_EVIDENCE;
		$evidence = array_intersect_key( (array) $item['evidence'], array_flip( $allowed ) );
		$subject  = $item['subject'];
		$reason   = $item['reason'];
		if ( ! $personal ) {
			if ( in_array( $category, self::PERSONAL_CATEGORIES, true ) && preg_match( '/^User /', $subject ) ) {
				$subject = 'User [redacted ' . substr( hash_hmac( 'sha256', $subject, Storage::mac_key() ), 0, 8 ) . ']';
			}
			$reason = self::scrub( $reason );
		}
		return array(
			'id'          => (int) $item['id'],
			'severity'    => Findings::severity_key( $item['severity'] ),
			'title'       => Findings::title( $item['rule'] ),
			'rule'        => $item['rule'],
			'category'    => $category,
			'confidence'  => $item['confidence'],
			'basis'       => $item['basis'],
			'change'      => $item['change_type'],
			'status'      => $item['status'],
			'subject'     => $subject,
			'reason'      => $reason,
			'remediation' => Findings::next_steps( $item['rule'] ),
			'first_seen'  => gmdate( 'c', (int) strtotime( $item['first_seen'] . ' UTC' ) ),
			'last_seen'   => gmdate( 'c', (int) strtotime( $item['last_seen'] . ' UTC' ) ),
			'occurrences' => (int) $item['occurrences'],
			'evidence'    => $evidence,
		);
	}

	/**
	 * Remove email addresses, masked networks, and recorded actor details from free text.
	 *
	 * @param string $text Text.
	 * @return string
	 */
	private static function scrub( $text ) {
		$text = preg_replace( '/[A-Z0-9._%+*-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i', '[email redacted]', (string) $text );
		$text = preg_replace( '/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.x\b|\b[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){2}::x\b/i', '[network redacted]', $text );
		return preg_replace( '/Recorded \S+ by .+? via \S+ at [0-9: -]+\./', 'Recorded admin action (actor redacted).', $text );
	}

	/**
	 * Counts by severity.
	 *
	 * @param array $findings Exported findings.
	 * @return array
	 */
	private static function counts( array $findings ) {
		$counts = array_fill_keys( array( 'critical', 'high', 'medium', 'low', 'info' ), 0 );
		foreach ( $findings as $f ) {
			++$counts[ $f['severity'] ];
		}
		return $counts;
	}

	/**
	 * JSON text.
	 *
	 * @param array $report Report.
	 * @return string
	 */
	public static function to_json( array $report ) {
		return (string) wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	/**
	 * CSV text, one row per finding. Cells that a spreadsheet could treat as a formula are prefixed with an apostrophe.
	 *
	 * @param array $report Report.
	 * @return string
	 */
	public static function to_csv( array $report ) {
		$columns = array( 'id', 'severity', 'title', 'rule', 'category', 'confidence', 'basis', 'change', 'status', 'subject', 'reason', 'remediation', 'first_seen', 'last_seen', 'occurrences', 'evidence' );
		$lines   = array( self::csv_line( $columns ) );
		foreach ( $report['findings'] as $f ) {
			$row = array();
			foreach ( $columns as $col ) {
				$row[] = 'evidence' === $col ? wp_json_encode( $f['evidence'], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ) : (string) $f[ $col ];
			}
			$lines[] = self::csv_line( $row );
		}
		return implode( "\r\n", $lines ) . "\r\n";
	}

	/**
	 * One CSV line (RFC 4180 quoting, formula-injection safe).
	 *
	 * @param array $cells Cells.
	 * @return string
	 */
	private static function csv_line( array $cells ) {
		$out = array();
		foreach ( $cells as $cell ) {
			$cell = (string) $cell;
			if ( '' !== $cell && in_array( $cell[0], array( '=', '+', '-', '@', "\t", "\r" ), true ) ) {
				$cell = "'" . $cell;
			}
			$out[] = '"' . str_replace( '"', '""', $cell ) . '"';
		}
		return implode( ',', $out );
	}

	/**
	 * Download file name.
	 *
	 * @param string $format json|csv.
	 * @return string
	 */
	public static function filename( $format ) {
		return 'bee-monitor-report-' . gmdate( 'Ymd-His' ) . '.' . ( 'csv' === $format ? 'csv' : 'json' );
	}
}
