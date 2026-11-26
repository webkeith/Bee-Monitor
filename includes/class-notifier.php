<?php
/**
 * Email alerts: grouping, rate limits, digests, and the test email.
 *
 * @package BeeMonitor
 */

namespace BeeMonitor;

defined( 'ABSPATH' ) || exit;

/**
 * Notifier.
 */
final class Notifier {

	const MAX_DETAILED = 25;

	/**
	 * Last wp_mail error captured during our send.
	 *
	 * @var string
	 */
	private static $last_error = '';

	/**
	 * Send immediate alerts for pending findings at or above the configured severity.
	 *
	 * @param string $trigger scan|baseline|event.
	 * @param array  $summary Scan summary.
	 */
	public static function dispatch( $trigger, array $summary = array() ) {
		if ( ! Settings::value( 'enabled' ) ) {
			return;
		}
		$threshold = Findings::severity_from_key( (string) Settings::value( 'immediate_severity' ) );

		if ( 'baseline' === $trigger ) {
			$items = Findings::pending( Findings::LOW );
			if ( self::send( 'baseline', $items, array(), $summary ) ) {
				Findings::mark_sent( wp_list_pluck( $items, 'id' ) );
			}
			return;
		}

		$items = Findings::pending( $threshold );
		if ( empty( $items ) ) {
			return;
		}
		if ( self::send( 'alert', $items, array(), $summary ) ) {
			Findings::mark_sent( wp_list_pluck( $items, 'id' ) );
		}
	}

	/**
	 * Scheduled digest of lower-severity findings and reminders.
	 */
	public static function digest() {
		if ( ! Settings::value( 'enabled' ) ) {
			return;
		}
		$items     = Findings::pending( Findings::LOW );
		$reminders = Findings::due_reminders( (int) Settings::value( 'reminder_days' ) );
		$last      = Storage::get( 'last_scan', array() );
		$healthy   = self::health_problems();

		if ( empty( $items ) && empty( $reminders ) && empty( $healthy ) && ! Settings::value( 'digest_all_clear' ) ) {
			return;
		}
		if ( self::send( 'digest', $items, $reminders, is_array( $last ) ? $last : array() ) ) {
			Findings::mark_sent( wp_list_pluck( $items, 'id' ) );
			Findings::mark_sent( wp_list_pluck( $reminders, 'id' ), 'reminded_at' );
		}
	}

	/**
	 * Monitor health problems worth mentioning in a digest.
	 *
	 * @return string[]
	 */
	public static function health_problems() {
		$problems = array();
		$last     = Storage::get( 'last_scan', array() );
		if ( ! is_array( $last ) || empty( $last['finished'] ) ) {
			$problems[] = __( 'No completed scan has been recorded yet.', 'bee-monitor' );
		} elseif ( time() - (int) $last['finished'] > 3 * Settings::interval_seconds() + HOUR_IN_SECONDS ) {
			$problems[] = __( 'The last completed scan is older than expected. WP-Cron may not be running.', 'bee-monitor' );
		}
		if ( is_array( $last ) && ! empty( $last['stats']['unreadable'] ) ) {
			/* translators: %d: number of paths. */
			$problems[] = sprintf( __( '%d paths could not be read during the last scan.', 'bee-monitor' ), (int) $last['stats']['unreadable'] );
		}
		if ( is_array( $last ) && isset( $last['checksums'] ) && ! $last['checksums'] && Settings::value( 'core_checksums' ) ) {
			$problems[] = __( 'Official WordPress checksums could not be fetched; core files were compared with the local baseline only.', 'bee-monitor' );
		}
		$mail = Storage::get( 'mail_status', array() );
		if ( is_array( $mail ) && empty( $mail['ok'] ) && ! empty( $mail['time'] ) ) {
			$problems[] = __( 'The previous Bee Monitor email failed to send.', 'bee-monitor' );
		}
		return $problems;
	}

	/**
	 * Build and send an email, respecting the hourly cap.
	 *
	 * @param string $kind      alert|digest|baseline|test.
	 * @param array  $items     Findings.
	 * @param array  $reminders Reminder findings.
	 * @param array  $summary   Scan summary.
	 * @return bool
	 */
	private static function send( $kind, array $items, array $reminders, array $summary ) {
		$recipients = Settings::recipients();
		if ( empty( $recipients ) ) {
			Storage::log( 'error', 'Bee Monitor has no valid alert recipient.' );
			return false;
		}
		if ( 'test' !== $kind && ! self::within_rate_limit() ) {
			Storage::log( 'warning', 'Bee Monitor email held back by the hourly limit; it will be included in the next send.' );
			return false;
		}

		$site = self::site_name();
		$top  = Findings::INFO;
		$open = 0;
		foreach ( $items as $item ) {
			$top = max( $top, (int) $item['severity'] );
		}
		foreach ( $items as $item ) {
			if ( $item['severity'] >= Findings::LOW ) {
				++$open;
			}
		}

		switch ( $kind ) {
			case 'baseline':
				/* translators: 1: site name, 2: number of findings. */
				$subject = sprintf( __( '[Bee Monitor] Baseline created for %1$s — %2$d items to review', 'bee-monitor' ), $site, $open );
				if ( $top >= Findings::HIGH ) {
					/* translators: 1: severity, 2: site name, 3: number of findings. */
					$subject = sprintf( __( '[Bee Monitor] [%1$s] Baseline created for %2$s — %3$d items to review', 'bee-monitor' ), strtoupper( Findings::severity_label( $top ) ), $site, $open );
				}
				break;
			case 'digest':
				/* translators: 1: site name, 2: number of findings. */
				$subject = sprintf( __( '[Bee Monitor] Digest for %1$s — %2$d new findings', 'bee-monitor' ), $site, count( $items ) );
				break;
			default:
				/* translators: 1: severity, 2: site name, 3: number of findings. */
				$subject = sprintf( _n( '[Bee Monitor] [%1$s] %2$s — %3$d finding', '[Bee Monitor] [%1$s] %2$s — %3$d findings', count( $items ), 'bee-monitor' ), strtoupper( Findings::severity_label( $top ) ), $site, count( $items ) );
		}

		$body = self::body( $kind, $items, $reminders, $summary );
		return self::mail( $recipients, $subject, $body, $kind );
	}

	/**
	 * Send the test email.
	 *
	 * @return array ok, error.
	 */
	public static function send_test() {
		$recipients = Settings::recipients();
		if ( empty( $recipients ) ) {
			return array(
				'ok'    => false,
				'error' => __( 'No valid recipient is configured.', 'bee-monitor' ),
			);
		}
		$lines   = array();
		$lines[] = __( 'This is a Bee Monitor test email. No security issue was detected by this test.', 'bee-monitor' );
		$lines[] = '';
		/* translators: %s: site name and URL. */
		$lines[] = sprintf( __( 'Site: %s', 'bee-monitor' ), self::site_name() . ' (' . Storage::trusted_urls()['home'] . ')' );
		/* translators: %s: date and time. */
		$lines[] = sprintf( __( 'Sent: %s', 'bee-monitor' ), wp_date( 'Y-m-d H:i T' ) );
		/* translators: %s: list of recipients. */
		$lines[] = sprintf( __( 'Recipients: %s', 'bee-monitor' ), implode( ', ', $recipients ) );
		$lines[] = '';
		$lines[] = __( 'If you received this, WordPress can deliver Bee Monitor alerts to this address. Check that it did not land in spam, and consider an SMTP or transactional email plugin for reliable delivery.', 'bee-monitor' );
		$lines[] = '';
		$lines[] = self::footer();
		/* translators: %s: site name. */
		$ok = self::mail( $recipients, sprintf( __( '[Bee Monitor] Test email from %s', 'bee-monitor' ), self::site_name() ), implode( "\n", $lines ), 'test' );
		return array(
			'ok'    => $ok,
			'error' => $ok ? '' : ( self::$last_error ? self::$last_error : __( 'wp_mail() returned false.', 'bee-monitor' ) ),
		);
	}

	/**
	 * Send a sample alert showing the real format, using a clearly labeled fake finding.
	 *
	 * @return bool
	 */
	public static function send_sample() {
		$sample     = array(
			'id'          => 0,
			'rule'        => 'executable_in_uploads',
			'severity'    => Findings::CRITICAL,
			'confidence'  => 'high',
			'basis'       => 'location',
			'change_type' => 'added',
			'subject'     => 'wp-content/uploads/2026/01/bee-monitor-sample.php',
			'reason'      => __( 'SAMPLE ONLY: this finding is not real. It shows how Bee Monitor alerts look.', 'bee-monitor' ),
			'evidence'    => array(
				'path'       => 'wp-content/uploads/2026/01/bee-monitor-sample.php',
				'size'       => 128,
				'sha256'     => str_repeat( 'ab', 32 ),
				'indicators' => array(
					array(
						'rule'  => 'exec_from_request',
						'label' => __( 'Request data reaches a code or command execution function', 'bee-monitor' ),
						'line'  => 1,
						'text'  => '[sample indicator text]',
					),
				),
			),
			'first_seen'  => current_time( 'mysql', true ),
			'occurrences' => 1,
		);
		$recipients = Settings::recipients();
		/* translators: %s: site name. */
		$subject = sprintf( __( '[Bee Monitor] [SAMPLE] %s — sample alert (not a real finding)', 'bee-monitor' ), self::site_name() );
		return $recipients ? self::mail( $recipients, $subject, self::body( 'sample', array( $sample ), array(), array() ), 'test' ) : false;
	}

	/**
	 * Plain-text email body.
	 *
	 * @param string $kind      Kind.
	 * @param array  $items     Findings.
	 * @param array  $reminders Reminders.
	 * @param array  $summary   Scan summary.
	 * @return string
	 */
	private static function body( $kind, array $items, array $reminders, array $summary ) {
		$l       = array();
		$trusted = Storage::trusted_urls();
		$site    = self::site_name() . ' (' . $trusted['home'] . ')';

		if ( 'baseline' === $kind ) {
			/* translators: %s: site name and URL. */
			$l[] = sprintf( __( 'Bee Monitor created its baseline for %s.', 'bee-monitor' ), $site );
			$l[] = __( 'From now on, changes are compared with this baseline. The items below already existed when the baseline was created; review them, because a baseline taken from an infected site treats the infection as normal.', 'bee-monitor' );
		} elseif ( 'digest' === $kind ) {
			/* translators: %s: site name and URL. */
			$l[] = sprintf( __( 'Bee Monitor digest for %s.', 'bee-monitor' ), $site );
		} else {
			/* translators: 1: number of findings, 2: site name and URL. */
			$l[] = sprintf( _n( 'Bee Monitor detected %1$d finding on %2$s.', 'Bee Monitor detected %1$d findings on %2$s.', count( $items ), 'bee-monitor' ), count( $items ), $site );
		}
		if ( untrailingslashit( network_home_url( '/' ) ) !== untrailingslashit( $trusted['home'] ) ) {
			$l[] = '';
			/* translators: 1: current address, 2: recorded address. */
			$l[] = sprintf( __( 'WARNING: WordPress currently reports the site address as %1$s, which differs from the address Bee Monitor recorded (%2$s). Links in this email use the recorded address. Do not follow links to an address you do not recognize.', 'bee-monitor' ), network_home_url( '/' ), $trusted['home'] );
		}
		$meta = Storage::get( 'baseline_meta', array() );
		$l[]  = '';
		/* translators: 1: date, 2: scan number, 3: baseline status. */
		$l[] = sprintf( __( 'Time: %1$s   Scan: #%2$s   Baseline: %3$s', 'bee-monitor' ), wp_date( 'Y-m-d H:i T' ), isset( $summary['id'] ) ? (int) $summary['id'] : '-', is_array( $meta ) && isset( $meta['status'] ) ? $meta['status'] : __( 'missing', 'bee-monitor' ) );
		if ( ! empty( $summary['stats'] ) ) {
			$st = $summary['stats'];
			/* translators: 1: files checked, 2: added, 3: modified, 4: deleted, 5: unreadable. */
			$l[] = sprintf( __( 'Files checked: %1$d   Added: %2$d   Modified: %3$d   Deleted: %4$d   Unreadable: %5$d', 'bee-monitor' ), $st['files'], $st['added'], $st['modified'], $st['deleted'], $st['unreadable'] );
		}
		if ( ! empty( $summary['mode'] ) && 'degraded' === $summary['mode'] ) {
			$l[] = __( 'WARNING: The baseline was unavailable, so this scan ran in limited mode (checksums, locations, and code indicators only).', 'bee-monitor' );
		}
		$l[] = '';

		$counts = array_fill( 0, 5, 0 );
		foreach ( $items as $item ) {
			++$counts[ (int) $item['severity'] ];
		}
		$parts = array();
		for ( $sev = Findings::CRITICAL; $sev >= Findings::LOW; $sev-- ) {
			if ( $counts[ $sev ] ) {
				$parts[] = $counts[ $sev ] . ' ' . strtolower( Findings::severity_label( $sev ) );
			}
		}
		if ( $parts ) {
			/* translators: %s: counts by severity. */
			$l[] = sprintf( __( 'Summary: %s', 'bee-monitor' ), implode( ', ', $parts ) );
			$l[] = '';
		}

		$groups = array();
		foreach ( $items as $item ) {
			$groups[ $item['rule'] . '|' . $item['severity'] ][] = $item;
		}
		$n       = 0;
		$skipped = 0;
		foreach ( $groups as $group ) {
			foreach ( $group as $idx => $item ) {
				if ( $item['severity'] < Findings::LOW ) {
					continue;
				}
				if ( $n >= self::MAX_DETAILED || ( $idx >= 5 && count( $group ) > 6 ) ) {
					++$skipped;
					continue;
				}
				++$n;
				$l = array_merge( $l, self::finding_lines( $n, $item ) );
			}
		}
		if ( $skipped ) {
			/* translators: %d: number of findings. */
			$l[] = sprintf( __( '…and %d more related findings. See the Bee Monitor findings screen for the full list.', 'bee-monitor' ), $skipped );
			$l[] = '';
		}

		if ( $reminders ) {
			$l[] = __( 'Still open (reminder):', 'bee-monitor' );
			foreach ( $reminders as $item ) {
				/* translators: 1: severity, 2: title, 3: subject, 4: date first seen. */
				$l[] = sprintf( __( '- [%1$s] %2$s: %3$s (first seen %4$s)', 'bee-monitor' ), Findings::severity_label( $item['severity'] ), Findings::title( $item['rule'] ), $item['subject'], self::local_time( $item['first_seen'] ) );
			}
			$l[] = '';
		}

		if ( 'digest' === $kind ) {
			$problems = self::health_problems();
			if ( $problems ) {
				$l[] = __( 'Monitor health:', 'bee-monitor' );
				foreach ( $problems as $problem ) {
					$l[] = '- ' . $problem;
				}
				$l[] = '';
			}
			if ( ! $items && ! $reminders && ! $problems ) {
				$l[] = __( 'No new findings since the last digest.', 'bee-monitor' );
				$l[] = '';
			}
		}

		if ( $items ) {
			$l[] = __( 'General next steps:', 'bee-monitor' );
			$l[] = __( '1. Review each finding in Bee Monitor > Findings. Mark legitimate changes as Expected.', 'bee-monitor' );
			$l[] = __( '2. For suspected compromise: take a full backup for evidence before changing anything, then restore or clean files manually.', 'bee-monitor' );
			$l[] = __( '3. After cleanup, reset administrator passwords, rotate the keys and salts in wp-config.php, and rebuild the Bee Monitor baseline.', 'bee-monitor' );
			$l[] = '';
		}
		$l[] = self::footer();
		return implode( "\n", $l );
	}

	/**
	 * Lines for one finding.
	 *
	 * @param int   $n    Number.
	 * @param array $item Finding.
	 * @return string[]
	 */
	private static function finding_lines( $n, array $item ) {
		$l   = array();
		$ev  = $item['evidence'];
		$l[] = sprintf( '%d. %s · %s · %s', $n, strtoupper( Findings::severity_label( $item['severity'] ) ), Findings::term( 'confidence', $item['confidence'] ), Findings::term( 'basis', $item['basis'] ) );
		$l[] = '   ' . Findings::title( $item['rule'] );
		/* translators: 1: subject, 2: change type. */
		$l[] = '   ' . sprintf( __( 'Affected: %1$s (%2$s)', 'bee-monitor' ), $item['subject'], Findings::term( 'change', $item['change_type'] ) );
		$l[] = '   ' . sprintf( /* translators: %s: reason. */ __( 'Why: %s', 'bee-monitor' ), $item['reason'] );
		if ( ! empty( $ev['indicators'] ) && is_array( $ev['indicators'] ) ) {
			$l[] = '   ' . __( 'Evidence (redacted):', 'bee-monitor' );
			foreach ( array_slice( $ev['indicators'], 0, 3 ) as $ind ) {
				$where = ! empty( $ind['line'] ) ? 'L' . (int) $ind['line'] . ': ' : '';
				$l[]   = '     - ' . $ind['label'] . ( '' !== $ind['text'] ? ' — ' . $where . $ind['text'] : '' );
			}
		}
		foreach ( array( 'sources', 'domains' ) as $list ) {
			if ( ! empty( $ev[ $list ] ) && is_array( $ev[ $list ] ) ) {
				$l[] = '   ' . ucfirst( $list ) . ': ' . implode( ', ', array_slice( $ev[ $list ], 0, 5 ) );
			}
		}
		if ( ! empty( $ev['sha256'] ) ) {
			$hash = 'SHA-256: ' . Redactor::hash( $ev['sha256'] );
			if ( ! empty( $ev['previous_sha256'] ) ) {
				$hash .= '  (was ' . Redactor::hash( $ev['previous_sha256'] ) . ')';
			}
			$l[] = '   ' . $hash;
		}
		if ( ! empty( $ev['official_md5'] ) && ! empty( $ev['md5'] ) ) {
			$l[] = '   MD5: ' . Redactor::hash( $ev['md5'] ) . '  (official ' . Redactor::hash( $ev['official_md5'] ) . ')';
		}
		if ( ! empty( $ev['context'] ) ) {
			$l[] = '   ' . __( 'Context:', 'bee-monitor' ) . ' ' . $ev['context'];
		}
		$l[] = '   ' . sprintf( /* translators: %s: next steps. */ __( 'Next: %s', 'bee-monitor' ), Findings::next_steps( $item['rule'] ) );
		if ( ! empty( $item['id'] ) ) {
			$l[] = '   ' . sprintf( /* translators: %s: URL. */ __( 'Review: %s', 'bee-monitor' ), self::link( 'bee-monitor', array( 'finding' => (int) $item['id'] ) ) );
		}
		$l[] = '';
		return $l;
	}

	/**
	 * Common footer.
	 *
	 * @return string
	 */
	private static function footer() {
		return "--\n" . sprintf(
			/* translators: 1: version, 2: settings URL. */
			__( "Sent by Bee Monitor %1\$s. Bee Monitor reports indicators for review; it never deletes, quarantines, or changes files.\nManage alerts: %2\$s", 'bee-monitor' ),
			BEE_MONITOR_VERSION,
			self::link( 'bee-monitor-settings' )
		);
	}

	/**
	 * Admin link built from the trusted admin URL, not the current (possibly altered) one.
	 *
	 * @param string $page Page slug.
	 * @param array  $args Query args.
	 * @return string
	 */
	private static function link( $page, array $args = array() ) {
		$urls = Storage::trusted_urls();
		return add_query_arg( array_merge( array( 'page' => $page ), $args ), $urls['admin'] );
	}

	/**
	 * Send via wp_mail with the Bee Monitor From name.
	 *
	 * @param string[] $to      Recipients.
	 * @param string   $subject Subject.
	 * @param string   $body    Body.
	 * @param string   $kind    Kind.
	 * @return bool
	 */
	private static function mail( array $to, $subject, $body, $kind ) {
		self::$last_error = '';
		$from_name        = function () {
			return 'Bee Monitor';
		};
		$capture          = function ( $error ) {
			if ( is_wp_error( $error ) ) {
				self::$last_error = substr( wp_strip_all_tags( $error->get_error_message() ), 0, 200 );
			}
		};
		add_filter( 'wp_mail_from_name', $from_name, 99 );
		add_action( 'wp_mail_failed', $capture );
		$ok = wp_mail( $to, $subject, $body, array( 'Content-Type: text/plain; charset=UTF-8' ) );
		remove_filter( 'wp_mail_from_name', $from_name, 99 );
		remove_action( 'wp_mail_failed', $capture );

		Storage::set(
			'mail_status',
			array(
				'ok'    => (bool) $ok,
				'time'  => time(),
				'kind'  => $kind,
				'error' => self::$last_error,
			)
		);
		Storage::log( $ok ? 'info' : 'error', $ok ? sprintf( 'Bee Monitor %s email sent', $kind ) : sprintf( 'Bee Monitor %s email failed', $kind ), $ok ? array() : array( 'error' => self::$last_error ) );
		if ( $ok && 'test' !== $kind ) {
			self::count_sent();
		}
		return (bool) $ok;
	}

	/**
	 * Whether another email fits within the hourly cap.
	 *
	 * @return bool
	 */
	private static function within_rate_limit() {
		$window = Storage::get( 'mail_window', array() );
		if ( ! is_array( $window ) || empty( $window['start'] ) || time() - (int) $window['start'] >= HOUR_IN_SECONDS ) {
			return true;
		}
		return (int) $window['count'] < (int) Settings::value( 'max_emails_per_hour' );
	}

	/**
	 * Count a sent email in the hourly window.
	 */
	private static function count_sent() {
		$window = Storage::get( 'mail_window', array() );
		if ( ! is_array( $window ) || empty( $window['start'] ) || time() - (int) $window['start'] >= HOUR_IN_SECONDS ) {
			$window = array(
				'start' => time(),
				'count' => 0,
			);
		}
		++$window['count'];
		Storage::set( 'mail_window', $window );
	}

	/**
	 * Site name for subjects.
	 *
	 * @return string
	 */
	private static function site_name() {
		$name = is_multisite() ? get_network()->site_name : get_bloginfo( 'name' );
		$name = wp_specialchars_decode( (string) $name, ENT_QUOTES );
		return '' !== $name ? $name : (string) wp_parse_url( network_home_url(), PHP_URL_HOST );
	}

	/**
	 * GMT MySQL date to local display.
	 *
	 * @param string $gmt GMT datetime.
	 * @return string
	 */
	public static function local_time( $gmt ) {
		$ts = strtotime( $gmt . ' UTC' );
		return $ts ? wp_date( 'Y-m-d H:i', $ts ) : '';
	}
}
