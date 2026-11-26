<?php
/**
 * WP-CLI commands: wp bee-monitor <command>.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'WP_CLI' ) || ! WP_CLI ) {
	return;
}

// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter -- WP-CLI passes $args and $assoc_args to every command method.

/**
 * Manage Bee Monitor scans, findings, and alerts.
 */
final class CLI {

	/**
	 * Run a scan to completion.
	 *
	 * ## OPTIONS
	 *
	 * [--rebuild]
	 * : Replace the baseline with the files as they are now. Only use this on a verified clean site.
	 *
	 * [--remote]
	 * : Also check this site's public pages in this scan (requires remote checks to be enabled).
	 *
	 * [--full]
	 * : Re-hash every monitored file and re-verify core and plugin checksums now, instead of waiting for the daily full pass.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bee-monitor scan
	 *     wp bee-monitor scan --full
	 *     wp bee-monitor scan --rebuild
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function scan( $args, $assoc_args ) {
		$scanner = new Scanner();
		$rebuild = ! empty( $assoc_args['rebuild'] );
		if ( $rebuild ) {
			Storage::delete( 'lock' );
			Storage::delete( 'scan_state' );
			$scanner->start( 'cli', true );
		} elseif ( ! Scanner::is_running() ) {
			$scanner->start( 'cli', false, ! empty( $assoc_args['full'] ), ! empty( $assoc_args['remote'] ) );
		}
		$steps = 0;
		do {
			$progress = $scanner->run_step( 'cli' );
			++$steps;
			if ( ! empty( $progress['locked'] ) ) {
				sleep( 2 );
			}
		} while ( empty( $progress['done'] ) && $steps < 1000 );
		$last = Storage::get( 'last_scan', array() );
		if ( empty( $progress['done'] ) || ! is_array( $last ) ) {
			\WP_CLI::error( 'The scan did not finish. Check wp bee-monitor status.' );
		}
		$st = $last['stats'];
		\WP_CLI::success( sprintf( 'Scan #%d (%s) finished: %d files checked, %d added, %d modified, %d deleted, %d new findings.', $last['id'], $last['mode'], $st['files'], $st['added'], $st['modified'], $st['deleted'], $st['findings'] ) );
	}

	/**
	 * Show monitor status.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bee-monitor status
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function status( $args, $assoc_args ) {
		$meta   = Storage::get( 'baseline_meta', array() );
		$last   = Storage::get( 'last_scan', array() );
		$counts = Findings::open_counts();
		$deploy = (int) Storage::get( 'deploy_until', 0 );
		$rows   = array(
			array(
				'item'  => 'Monitoring',
				'value' => Settings::value( 'enabled' ) ? 'enabled' : 'disabled',
			),
			array(
				'item'  => 'Baseline',
				'value' => is_array( $meta ) && isset( $meta['status'] ) ? $meta['status'] . ' (' . Storage::baseline_count() . ' files)' : 'not created',
			),
			array(
				'item'  => 'Last scan',
				'value' => is_array( $last ) && ! empty( $last['finished'] ) ? wp_date( 'Y-m-d H:i', (int) $last['finished'] ) . ' (' . $last['mode'] . ')' : 'never',
			),
			array(
				'item'  => 'Scan running',
				'value' => Scanner::is_running() ? 'yes' : 'no',
			),
			array(
				'item'  => 'Open findings',
				'value' => sprintf( '%d critical, %d high, %d medium, %d low', $counts[4], $counts[3], $counts[2], $counts[1] ),
			),
			array(
				'item'  => 'Deploy window',
				'value' => $deploy > time() ? 'open until ' . wp_date( 'Y-m-d H:i', $deploy ) : 'closed',
			),
			array(
				'item'  => 'Recipients',
				'value' => implode( ', ', Settings::recipients() ),
			),
		);
		\WP_CLI\Utils\format_items( 'table', $rows, array( 'item', 'value' ) );
	}

	/**
	 * List findings.
	 *
	 * ## OPTIONS
	 *
	 * [--status=<status>]
	 * : open, expected, resolved, auto, ignored, or all.
	 * ---
	 * default: open
	 * ---
	 *
	 * [--min-severity=<severity>]
	 * : info, low, medium, high, or critical.
	 * ---
	 * default: low
	 * ---
	 *
	 * [--format=<format>]
	 * : table, csv, json, or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * ## EXAMPLES
	 *
	 *     wp bee-monitor findings --min-severity=high
	 *     wp bee-monitor findings --status=all --format=csv > findings.csv
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function findings( $args, $assoc_args ) {
		$status = isset( $assoc_args['status'] ) ? sanitize_key( $assoc_args['status'] ) : 'open';
		if ( ! in_array( $status, array( 'open', 'expected', 'resolved', 'auto', 'ignored', 'all' ), true ) ) {
			\WP_CLI::error( 'Unknown status.' );
		}
		$result = Findings::query(
			array(
				'status'       => $status,
				'min_severity' => Findings::severity_from_key( isset( $assoc_args['min-severity'] ) ? sanitize_key( $assoc_args['min-severity'] ) : 'low' ),
				'per_page'     => 1000,
			)
		);
		$items  = array();
		foreach ( $result['items'] as $item ) {
			$items[] = array(
				'id'         => $item['id'],
				'severity'   => Findings::severity_key( $item['severity'] ),
				'rule'       => $item['rule'],
				'subject'    => $item['subject'],
				'change'     => $item['change_type'],
				'confidence' => $item['confidence'],
				'status'     => $item['status'],
				'last_seen'  => $item['last_seen'],
			);
		}
		\WP_CLI\Utils\format_items( isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table', $items, array( 'id', 'severity', 'rule', 'subject', 'change', 'confidence', 'status', 'last_seen' ) );
	}

	/**
	 * Mark findings expected. File changes are accepted into the baseline only if the file still matches the finding.
	 *
	 * ## OPTIONS
	 *
	 * <id>...
	 * : Finding IDs.
	 *
	 * [--note=<note>]
	 * : Note stored with the finding.
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function accept( $args, $assoc_args ) {
		$ok      = array();
		$changed = 0;
		foreach ( array_map( 'absint', $args ) as $id ) {
			$item = Findings::get( $id );
			if ( ! $item ) {
				\WP_CLI::warning( "Finding {$id} not found." );
				continue;
			}
			if ( 'changed' === Scanner::accept_file( $item ) ) {
				\WP_CLI::warning( "Finding {$id}: the file changed again after it was flagged. Run a new scan first." );
				++$changed;
				continue;
			}
			$ok[] = $id;
		}
		$count = Findings::set_status( $ok, Findings::STATUS_EXPECTED, isset( $assoc_args['note'] ) ? sanitize_text_field( $assoc_args['note'] ) : 'Accepted via WP-CLI', 0 );
		Storage::log( 'info', 'Bee Monitor findings marked expected via WP-CLI', array( 'count' => $count ) );
		\WP_CLI::success( "{$count} findings marked expected." );
	}

	/**
	 * Mark findings resolved (fixed). If the same problem reappears, it alerts again once.
	 *
	 * ## OPTIONS
	 *
	 * <id>...
	 * : Finding IDs.
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function resolve( $args, $assoc_args ) {
		$count = Findings::set_status( array_map( 'absint', $args ), Findings::STATUS_RESOLVED, 'Resolved via WP-CLI', 0 );
		\WP_CLI::success( "{$count} findings marked resolved." );
	}

	/**
	 * Accept every open file finding into the baseline, for use right after a deployment you performed.
	 *
	 * ## OPTIONS
	 *
	 * [--yes]
	 * : Skip the confirmation prompt.
	 *
	 * @subcommand accept-all
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function accept_all( $args, $assoc_args ) {
		\WP_CLI::confirm( 'Accept every open file finding into the baseline? Review heuristic findings first.', $assoc_args );
		$result  = Findings::query(
			array(
				'status'       => Findings::STATUS_OPEN,
				'min_severity' => 0,
				'per_page'     => 1000,
			)
		);
		$ids     = array();
		$changed = 0;
		foreach ( $result['items'] as $item ) {
			if ( ! Findings::is_file_rule( $item['rule'] ) ) {
				continue;
			}
			if ( 'changed' === Scanner::accept_file( $item ) ) {
				++$changed;
				continue;
			}
			$ids[] = $item['id'];
		}
		$count = Findings::set_status( $ids, Findings::STATUS_EXPECTED, 'Accepted in bulk via WP-CLI', 0 );
		Storage::log( 'warning', 'Bee Monitor accepted all open file changes via WP-CLI', array( 'count' => $count ) );
		\WP_CLI::success( "{$count} file findings accepted. {$changed} skipped because the file changed again." );
	}

	/**
	 * Open a deployment window: during it, only critical findings are emailed immediately; the rest go to the digest.
	 *
	 * ## OPTIONS
	 *
	 * <minutes>
	 * : Window length in minutes (1-240). Use 0 to close the window.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bee-monitor deploy-window 30 && ./deploy.sh && wp bee-monitor scan
	 *
	 * @subcommand deploy-window
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function deploy_window( $args, $assoc_args ) {
		$minutes = max( 0, min( 240, (int) $args[0] ) );
		Storage::set( 'deploy_until', $minutes ? time() + $minutes * MINUTE_IN_SECONDS : 0 );
		Storage::log( 'info', $minutes ? sprintf( 'Bee Monitor deploy window opened for %d minutes', $minutes ) : 'Bee Monitor deploy window closed' );
		\WP_CLI::success( $minutes ? "Deploy window open for {$minutes} minutes." : 'Deploy window closed.' );
	}

	/**
	 * Send the test email to all recipients.
	 *
	 * @subcommand test-email
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function test_email( $args, $assoc_args ) {
		$result = Notifier::send_test();
		if ( ! $result['ok'] ) {
			\WP_CLI::error( 'Test email failed: ' . $result['error'] );
		}
		\WP_CLI::success( 'Test email sent to ' . implode( ', ', Settings::recipients() ) . '.' );
	}

	/**
	 * Export a findings report to stdout. Personal data and the site address are excluded unless requested.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : json or csv.
	 * ---
	 * default: json
	 * ---
	 *
	 * [--status=<status>]
	 * : open, expected, resolved, auto, ignored, or all.
	 * ---
	 * default: open
	 * ---
	 *
	 * [--include-personal]
	 * : Include usernames, user IDs, masked emails, and masked networks.
	 *
	 * [--include-site]
	 * : Include the site name and address.
	 *
	 * ## EXAMPLES
	 *
	 *     wp bee-monitor export > report.json
	 *     wp bee-monitor export --format=csv --status=all > findings.csv
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function export( $args, $assoc_args ) {
		$status = isset( $assoc_args['status'] ) ? sanitize_key( $assoc_args['status'] ) : 'open';
		if ( ! in_array( $status, array( 'open', 'expected', 'resolved', 'auto', 'ignored', 'all' ), true ) ) {
			\WP_CLI::error( 'Unknown status.' );
		}
		$report = Report::build(
			array(
				'status'           => $status,
				'include_personal' => ! empty( $assoc_args['include-personal'] ),
				'include_site'     => ! empty( $assoc_args['include-site'] ),
			)
		);
		\WP_CLI::line( isset( $assoc_args['format'] ) && 'csv' === $assoc_args['format'] ? Report::to_csv( $report ) : Report::to_json( $report ) );
	}

	/**
	 * List recent activity.
	 *
	 * ## OPTIONS
	 *
	 * [--type=<type>]
	 * : Event type, for example update_plugin or user_change.
	 *
	 * [--format=<format>]
	 * : table, csv, json, or yaml.
	 * ---
	 * default: table
	 * ---
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function activity( $args, $assoc_args ) {
		$result = Activity::query( isset( $assoc_args['type'] ) ? sanitize_key( $assoc_args['type'] ) : '', 1 );
		$rows   = array();
		foreach ( $result['items'] as $row ) {
			$rows[] = array(
				'time'   => $row['created_at'],
				'event'  => $row['type'],
				'object' => $row['object'],
				'detail' => $row['detail'],
				'actor'  => (int) $row['actor'],
				'via'    => $row['via'],
			);
		}
		\WP_CLI\Utils\format_items( isset( $assoc_args['format'] ) ? $assoc_args['format'] : 'table', $rows, array( 'time', 'event', 'object', 'detail', 'actor', 'via' ) );
	}

	/**
	 * Cancel the running scan.
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function cancel( $args, $assoc_args ) {
		if ( ! Scanner::request_cancel() ) {
			\WP_CLI::warning( 'No scan is running.' );
			return;
		}
		\WP_CLI::success( 'Cancellation requested.' );
	}

	/**
	 * Send the digest now.
	 *
	 * @param array $args       Positional arguments.
	 * @param array $assoc_args Options.
	 */
	public function digest( $args, $assoc_args ) {
		Notifier::digest();
		\WP_CLI::success( 'Digest processed.' );
	}
}
