<?php
/**
 * Email alerts: per-recipient routing, digests, rate limits, HTML and text formats.
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

	const COLORS = array( '#646970', '#2c3338', '#996800', '#b32d2e', '#8a1f11' );

	/**
	 * Last wp_mail error captured during our send.
	 *
	 * @var string
	 */
	private static $last_error = '';

	/**
	 * Send immediate alerts. Each recipient gets one email with the pending findings
	 * that match their categories and severity threshold.
	 *
	 * @param string $trigger scan|baseline|event.
	 * @param array  $summary Scan summary.
	 */
	public static function dispatch( $trigger, array $summary = array() ) {
		if ( ! Settings::value( 'enabled' ) ) {
			return;
		}
		$rows    = Settings::recipient_rows();
		$pending = Findings::pending( Findings::LOW );
		if ( empty( $rows ) || empty( $pending ) ) {
			return;
		}
		$baseline  = 'baseline' === $trigger;
		$deploying = ! $baseline && self::in_deploy_window();
		$delivered = Storage::delivered_map( wp_list_pluck( $pending, 'id' ) );

		foreach ( $rows as $row ) {
			$min = $baseline ? Findings::LOW : Findings::severity_from_key( $row['min_severity'] );
			if ( $deploying ) {
				$min = Findings::CRITICAL;
			}
			$items = self::eligible( $pending, $row, $min, $delivered );
			if ( empty( $items ) ) {
				continue;
			}
			if ( self::send( $baseline ? 'baseline' : 'alert', $row, $items, array(), $summary ) ) {
				Storage::record_deliveries( wp_list_pluck( $items, 'id' ), $row['email'], 'immediate' );
			}
		}
		self::settle( $pending, $rows );
	}

	/**
	 * Scheduled digest: findings not yet delivered to each digest recipient, reminders, and monitor health.
	 */
	public static function digest() {
		if ( ! Settings::value( 'enabled' ) ) {
			return;
		}
		$rows      = Settings::recipient_rows();
		$pending   = Findings::pending( Findings::LOW );
		$reminders = Findings::due_reminders( (int) Settings::value( 'reminder_days' ) );
		$problems  = self::health_problems();
		$last      = Storage::get( 'last_scan', array() );
		$delivered = Storage::delivered_map( wp_list_pluck( $pending, 'id' ) );
		$reminded  = array();

		foreach ( $rows as $row ) {
			if ( empty( $row['digest'] ) ) {
				continue;
			}
			$items = self::eligible( $pending, $row, Findings::LOW, $delivered );
			$rem   = array();
			foreach ( $reminders as $item ) {
				if ( in_array( Findings::category( $item['rule'] ), (array) $row['categories'], true ) && $item['severity'] >= Findings::severity_from_key( $row['min_severity'] ) ) {
					$rem[] = $item;
				}
			}
			if ( empty( $items ) && empty( $rem ) && empty( $problems ) && ! Settings::value( 'digest_all_clear' ) ) {
				continue;
			}
			if ( self::send( 'digest', $row, $items, $rem, is_array( $last ) ? $last : array() ) ) {
				Storage::record_deliveries( wp_list_pluck( $items, 'id' ), $row['email'], 'digest' );
				$reminded = array_merge( $reminded, wp_list_pluck( $rem, 'id' ) );
			}
		}
		Findings::mark_sent( array_unique( $reminded ), 'reminded_at' );
		self::settle( $pending, $rows );
	}

	/**
	 * Findings a recipient should receive now.
	 *
	 * @param array $pending   Pending findings.
	 * @param array $row       Recipient row.
	 * @param int   $min       Minimum severity.
	 * @param array $delivered Delivered map.
	 * @return array
	 */
	private static function eligible( array $pending, array $row, $min, array $delivered ) {
		$key = Storage::recipient_key( $row['email'] );
		$out = array();
		foreach ( $pending as $item ) {
			if ( $item['severity'] < $min || isset( $delivered[ $item['id'] ][ $key ] ) ) {
				continue;
			}
			if ( in_array( Findings::category( $item['rule'] ), (array) $row['categories'], true ) ) {
				$out[] = $item;
			}
		}
		return $out;
	}

	/**
	 * Mark findings notified once no recipient still has to receive them.
	 *
	 * @param array $pending Pending findings.
	 * @param array $rows    Recipient rows.
	 */
	private static function settle( array $pending, array $rows ) {
		$delivered = Storage::delivered_map( wp_list_pluck( $pending, 'id' ) );
		$done      = array();
		foreach ( $pending as $item ) {
			$waiting = false;
			foreach ( $rows as $row ) {
				if ( ! in_array( Findings::category( $item['rule'] ), (array) $row['categories'], true ) ) {
					continue;
				}
				if ( isset( $delivered[ $item['id'] ][ Storage::recipient_key( $row['email'] ) ] ) ) {
					continue;
				}
				if ( $item['severity'] >= Findings::severity_from_key( $row['min_severity'] ) || ! empty( $row['digest'] ) ) {
					$waiting = true;
					break;
				}
			}
			if ( ! $waiting ) {
				$done[] = $item['id'];
			}
		}
		Findings::mark_sent( $done );
	}

	/**
	 * Whether a deployment window is open (only critical findings are emailed immediately).
	 *
	 * @return bool
	 */
	public static function in_deploy_window() {
		return (int) Storage::get( 'deploy_until', 0 ) > time();
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
	 * Build and send an email to one recipient, respecting their hourly cap.
	 *
	 * @param string $kind      alert|digest|baseline.
	 * @param array  $row       Recipient row.
	 * @param array  $items     Findings.
	 * @param array  $reminders Reminder findings.
	 * @param array  $summary   Scan summary.
	 * @return bool
	 */
	private static function send( $kind, array $row, array $items, array $reminders, array $summary ) {
		if ( ! self::within_rate_limit( $row['email'] ) ) {
			Storage::log( 'warning', 'Bee Monitor email held back by the hourly limit; it will be included in the next send.', array( 'recipient' => Redactor::email( $row['email'] ) ) );
			return false;
		}
		$subject = self::subject( $kind, $items );
		$ok      = self::mail(
			array( $row['email'] ),
			$subject,
			self::text_body( $kind, $items, $reminders, $summary ),
			'html' === Settings::value( 'email_format' ) ? self::html_body( $kind, $items, $reminders, $summary ) : null,
			$kind
		);
		if ( $ok ) {
			self::count_sent( $row['email'] );
		}
		return $ok;
	}

	/**
	 * Subject line.
	 *
	 * @param string $kind  Kind.
	 * @param array  $items Findings.
	 * @return string
	 */
	private static function subject( $kind, array $items ) {
		$label = self::label();
		$top   = Findings::INFO;
		$count = 0;
		foreach ( $items as $item ) {
			$top = max( $top, (int) $item['severity'] );
			if ( $item['severity'] >= Findings::LOW ) {
				++$count;
			}
		}
		if ( 'baseline' === $kind ) {
			if ( $top >= Findings::HIGH ) {
				/* translators: 1: severity, 2: site label, 3: number of findings. */
				return sprintf( __( '[Bee Monitor] [%1$s] Baseline created for %2$s — %3$d items to review', 'bee-monitor' ), strtoupper( Findings::severity_label( $top ) ), $label, $count );
			}
			/* translators: 1: site label, 2: number of findings. */
			return sprintf( __( '[Bee Monitor] Baseline created for %1$s — %2$d items to review', 'bee-monitor' ), $label, $count );
		}
		if ( 'digest' === $kind ) {
			/* translators: 1: site label, 2: number of findings. */
			return sprintf( __( '[Bee Monitor] Digest for %1$s — %2$d new findings', 'bee-monitor' ), $label, count( $items ) );
		}
		/* translators: 1: severity, 2: site label, 3: number of findings. */
		return sprintf( _n( '[Bee Monitor] [%1$s] %2$s — %3$d finding', '[Bee Monitor] [%1$s] %2$s — %3$d findings', count( $items ), 'bee-monitor' ), strtoupper( Findings::severity_label( $top ) ), $label, count( $items ) );
	}

	/**
	 * Send the test email to all recipients or one.
	 *
	 * @param string $only Optional single recipient.
	 * @return array ok, error.
	 */
	public static function send_test( $only = '' ) {
		$recipients = $only ? array( $only ) : Settings::recipients();
		if ( empty( $recipients ) ) {
			return array(
				'ok'    => false,
				'error' => __( 'No valid recipient is configured.', 'bee-monitor' ),
			);
		}
		$trusted = Storage::trusted_urls();
		$lines   = array(
			__( 'This is a Bee Monitor test email. No security issue was detected by this test.', 'bee-monitor' ),
			'',
			/* translators: %s: site name and URL. */
			sprintf( __( 'Site: %s', 'bee-monitor' ), self::label() . ' (' . $trusted['home'] . ')' ),
			/* translators: %s: date and time. */
			sprintf( __( 'Sent: %s', 'bee-monitor' ), wp_date( 'Y-m-d H:i T' ) ),
			/* translators: %s: format. */
			sprintf( __( 'Format: %s', 'bee-monitor' ), 'html' === Settings::value( 'email_format' ) ? __( 'HTML with plain-text version', 'bee-monitor' ) : __( 'plain text', 'bee-monitor' ) ),
			'',
			__( 'If you received this, WordPress can deliver Bee Monitor alerts to this address. Check that it did not land in spam, and consider an SMTP or transactional email plugin for reliable delivery.', 'bee-monitor' ),
			'',
			self::footer(),
		);
		$text    = implode( "\n", $lines );
		$html    = null;
		if ( 'html' === Settings::value( 'email_format' ) ) {
			$html = self::html_wrap( '<p style="margin:0 0 12px;">' . esc_html( $lines[0] ) . '</p><p style="margin:0 0 12px;color:#50575e;">' . esc_html( $lines[2] ) . '<br>' . esc_html( $lines[3] ) . '<br>' . esc_html( $lines[4] ) . '</p><p style="margin:0;">' . esc_html( $lines[6] ) . '</p>' );
		}
		/* translators: %s: site label. */
		$ok = self::mail( $recipients, sprintf( __( '[Bee Monitor] Test email from %s', 'bee-monitor' ), self::label() ), $text, $html, 'test' );
		return array(
			'ok'    => $ok,
			'error' => $ok ? '' : ( self::$last_error ? self::$last_error : __( 'wp_mail() returned false.', 'bee-monitor' ) ),
		);
	}

	/**
	 * A clearly labeled fake finding used for samples and previews.
	 *
	 * @return array
	 */
	private static function sample_finding() {
		return array(
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
	}

	/**
	 * Send a sample alert in the real format.
	 *
	 * @return bool
	 */
	public static function send_sample() {
		$recipients = Settings::recipients();
		$items      = array( self::sample_finding() );
		/* translators: %s: site label. */
		$subject = sprintf( __( '[Bee Monitor] [SAMPLE] %s — sample alert (not a real finding)', 'bee-monitor' ), self::label() );
		$html    = 'html' === Settings::value( 'email_format' ) ? self::html_body( 'sample', $items, array(), array() ) : null;
		return $recipients ? self::mail( $recipients, $subject, self::text_body( 'sample', $items, array(), array() ), $html, 'test' ) : false;
	}

	/**
	 * HTML preview of the sample alert for the admin screen.
	 *
	 * @return string
	 */
	public static function preview_html() {
		return self::html_body( 'sample', array( self::sample_finding() ), array(), array() );
	}

	/**
	 * Tags and attributes allowed when showing the preview in wp-admin.
	 *
	 * @return array
	 */
	public static function allowed_email_html() {
		$basic = array( 'style' => true );
		return array(
			'div'    => $basic,
			'p'      => $basic,
			'span'   => $basic,
			'strong' => $basic,
			'code'   => $basic,
			'br'     => array(),
			'ul'     => $basic,
			'ol'     => $basic,
			'li'     => $basic,
			'h1'     => $basic,
			'h2'     => $basic,
			'a'      => array(
				'href'  => true,
				'style' => true,
			),
			'table'  => $basic,
			'tr'     => $basic,
			'td'     => $basic,
		);
	}

	/**
	 * Plain-text body.
	 *
	 * @param string $kind      Kind.
	 * @param array  $items     Findings.
	 * @param array  $reminders Reminders.
	 * @param array  $summary   Scan summary.
	 * @return string
	 */
	private static function text_body( $kind, array $items, array $reminders, array $summary ) {
		$l     = array();
		$intro = self::intro( $kind, $items );
		$l     = array_merge( $l, $intro );
		$warn  = self::url_warning();
		if ( $warn ) {
			$l[] = '';
			$l[] = $warn;
		}
		$l[] = '';
		$l[] = self::meta_line( $summary );
		if ( ! empty( $summary['stats'] ) ) {
			$l[] = self::stats_line( $summary['stats'] );
		}
		if ( ! empty( $summary['mode'] ) && 'degraded' === $summary['mode'] ) {
			$l[] = __( 'WARNING: The baseline was unavailable, so this scan ran in limited mode (checksums, locations, and code indicators only).', 'bee-monitor' );
		}
		if ( self::in_deploy_window() && 'digest' !== $kind ) {
			$l[] = __( 'A deployment window is open: only critical findings are sent immediately; the rest follow in the digest.', 'bee-monitor' );
		}
		$l[]   = '';
		$parts = self::severity_counts( $items );
		if ( $parts ) {
			/* translators: %s: counts by severity. */
			$l[] = sprintf( __( 'Summary: %s', 'bee-monitor' ), implode( ', ', $parts ) );
			$l[] = '';
		}
		list( $shown, $skipped ) = self::shown_items( $items );
		foreach ( $shown as $n => $item ) {
			$l = array_merge( $l, self::finding_lines( $n + 1, $item ) );
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
			foreach ( self::general_steps() as $step ) {
				$l[] = $step;
			}
			$l[] = '';
		}
		$l[] = self::footer();
		return implode( "\n", $l );
	}

	/**
	 * Lines for one finding in the text body.
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
		/* translators: %s: reason. */
		$l[] = '   ' . sprintf( __( 'Why: %s', 'bee-monitor' ), $item['reason'] );
		foreach ( self::evidence_lines( $ev ) as $line ) {
			$l[] = '   ' . $line;
		}
		/* translators: %s: next steps. */
		$l[] = '   ' . sprintf( __( 'Next: %s', 'bee-monitor' ), Findings::next_steps( $item['rule'] ) );
		if ( ! empty( $item['id'] ) ) {
			/* translators: %s: URL. */
			$l[] = '   ' . sprintf( __( 'Review: %s', 'bee-monitor' ), self::link( 'bee-monitor', array( 'finding' => (int) $item['id'] ) ) );
		}
		$l[] = '';
		return $l;
	}

	/**
	 * Evidence lines, respecting the evidence detail setting.
	 *
	 * @param array $ev Evidence.
	 * @return string[]
	 */
	private static function evidence_lines( array $ev ) {
		$l = array();
		if ( ! empty( $ev['verification'] ) ) {
			$l[] = __( 'Verification:', 'bee-monitor' ) . ' ' . Findings::term( 'verification', $ev['verification'] );
		}
		if ( ! empty( $ev['context'] ) ) {
			$l[] = __( 'Context:', 'bee-monitor' ) . ' ' . $ev['context'];
		}
		if ( 'full' !== Settings::value( 'evidence_detail' ) ) {
			return $l;
		}
		if ( ! empty( $ev['indicators'] ) && is_array( $ev['indicators'] ) ) {
			$l[] = __( 'Evidence (redacted):', 'bee-monitor' );
			foreach ( array_slice( $ev['indicators'], 0, 3 ) as $ind ) {
				$where = ! empty( $ind['line'] ) ? 'L' . (int) $ind['line'] . ': ' : '';
				$l[]   = '  - ' . $ind['label'] . ( '' !== $ind['text'] ? ' — ' . $where . $ind['text'] : '' );
			}
		}
		foreach ( array( 'sources', 'domains' ) as $list ) {
			if ( ! empty( $ev[ $list ] ) && is_array( $ev[ $list ] ) ) {
				$l[] = ucfirst( $list ) . ': ' . implode( ', ', array_slice( $ev[ $list ], 0, 5 ) );
			}
		}
		if ( ! empty( $ev['sha256'] ) ) {
			$hash = 'SHA-256: ' . Redactor::hash( $ev['sha256'] );
			if ( ! empty( $ev['previous_sha256'] ) ) {
				$hash .= '  (was ' . Redactor::hash( $ev['previous_sha256'] ) . ')';
			}
			$l[] = $hash;
		}
		if ( ! empty( $ev['official_md5'] ) && ! empty( $ev['md5'] ) ) {
			$l[] = 'MD5: ' . Redactor::hash( $ev['md5'] ) . '  (official ' . Redactor::hash( $ev['official_md5'] ) . ')';
		}
		return $l;
	}

	/**
	 * HTML body. Every dynamic value is escaped because evidence can contain attacker-controlled text.
	 *
	 * @param string $kind      Kind.
	 * @param array  $items     Findings.
	 * @param array  $reminders Reminders.
	 * @param array  $summary   Scan summary.
	 * @return string
	 */
	private static function html_body( $kind, array $items, array $reminders, array $summary ) {
		$muted = 'color:#50575e;';
		$h     = '';
		foreach ( self::intro( $kind, $items ) as $line ) {
			$h .= '<p style="margin:0 0 10px;font-size:15px;">' . esc_html( $line ) . '</p>';
		}
		$warn = self::url_warning();
		if ( $warn ) {
			$h .= '<div style="background:#fcf9e8;border:1px solid #dba617;border-radius:4px;padding:10px 12px;margin:12px 0;">' . esc_html( $warn ) . '</div>';
		}
		$h .= '<p style="margin:0 0 4px;font-size:13px;' . $muted . '">' . esc_html( self::meta_line( $summary ) ) . '</p>';
		if ( ! empty( $summary['stats'] ) ) {
			$h .= '<p style="margin:0 0 4px;font-size:13px;' . $muted . '">' . esc_html( self::stats_line( $summary['stats'] ) ) . '</p>';
		}
		if ( ! empty( $summary['mode'] ) && 'degraded' === $summary['mode'] ) {
			$h .= '<p style="margin:8px 0;color:#b32d2e;">' . esc_html__( 'WARNING: The baseline was unavailable, so this scan ran in limited mode (checksums, locations, and code indicators only).', 'bee-monitor' ) . '</p>';
		}
		if ( self::in_deploy_window() && 'digest' !== $kind ) {
			$h .= '<p style="margin:8px 0;' . $muted . '">' . esc_html__( 'A deployment window is open: only critical findings are sent immediately; the rest follow in the digest.', 'bee-monitor' ) . '</p>';
		}
		$counts = array_fill( 0, 5, 0 );
		foreach ( $items as $item ) {
			++$counts[ (int) $item['severity'] ];
		}
		$pills = '';
		for ( $sev = Findings::CRITICAL; $sev >= Findings::LOW; $sev-- ) {
			if ( $counts[ $sev ] ) {
				$pills .= '<span style="display:inline-block;margin:0 6px 6px 0;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600;color:#fff;background:' . esc_attr( self::COLORS[ $sev ] ) . ';">' . esc_html( $counts[ $sev ] . ' ' . strtolower( Findings::severity_label( $sev ) ) ) . '</span>';
			}
		}
		if ( $pills ) {
			$h .= '<div style="margin:14px 0 6px;">' . $pills . '</div>';
		}

		list( $shown, $skipped ) = self::shown_items( $items );
		foreach ( $shown as $item ) {
			$sev = (int) $item['severity'];
			$h  .= '<div style="border:1px solid #dcdcde;border-left:4px solid ' . esc_attr( self::COLORS[ $sev ] ) . ';border-radius:4px;padding:12px 14px;margin:12px 0;">';
			$h  .= '<p style="margin:0 0 4px;font-size:12px;font-weight:600;letter-spacing:.03em;color:' . esc_attr( self::COLORS[ $sev ] ) . ';">' . esc_html( strtoupper( Findings::severity_label( $sev ) ) . ' · ' . Findings::term( 'confidence', $item['confidence'] ) . ' · ' . Findings::term( 'basis', $item['basis'] ) ) . '</p>';
			$h  .= '<p style="margin:0 0 6px;font-size:16px;font-weight:600;">' . esc_html( Findings::title( $item['rule'] ) ) . '</p>';
			$h  .= '<p style="margin:0 0 8px;"><code style="font-family:Menlo,Consolas,monospace;font-size:13px;background:#f6f7f7;padding:2px 4px;word-break:break-all;">' . esc_html( $item['subject'] ) . '</code> <span style="' . $muted . 'font-size:13px;">(' . esc_html( Findings::term( 'change', $item['change_type'] ) ) . ')</span></p>';
			$h  .= '<p style="margin:0 0 8px;">' . esc_html( $item['reason'] ) . '</p>';
			$ev  = self::evidence_lines( $item['evidence'] );
			if ( $ev ) {
				$h .= '<div style="background:#f6f7f7;border-radius:4px;padding:8px 10px;margin:0 0 8px;font-family:Menlo,Consolas,monospace;font-size:12px;line-height:1.5;word-break:break-all;">';
				foreach ( $ev as $line ) {
					$h .= esc_html( $line ) . '<br>';
				}
				$h .= '</div>';
			}
			$h .= '<p style="margin:0 0 8px;"><strong>' . esc_html__( 'Next:', 'bee-monitor' ) . '</strong> ' . esc_html( Findings::next_steps( $item['rule'] ) ) . '</p>';
			if ( ! empty( $item['id'] ) ) {
				$h .= '<p style="margin:0;"><a href="' . esc_url( self::link( 'bee-monitor', array( 'finding' => (int) $item['id'] ) ) ) . '" style="display:inline-block;background:#2271b1;color:#fff;text-decoration:none;padding:6px 12px;border-radius:3px;font-size:13px;">' . esc_html__( 'Review finding', 'bee-monitor' ) . '</a></p>';
			}
			$h .= '</div>';
		}
		if ( $skipped ) {
			/* translators: %d: number of findings. */
			$h .= '<p style="' . $muted . '">' . esc_html( sprintf( __( '…and %d more related findings. See the Bee Monitor findings screen for the full list.', 'bee-monitor' ), $skipped ) ) . '</p>';
		}
		if ( $reminders ) {
			$h .= '<h2 style="font-size:15px;margin:18px 0 6px;">' . esc_html__( 'Still open (reminder)', 'bee-monitor' ) . '</h2><ul style="margin:0 0 0 18px;padding:0;">';
			foreach ( $reminders as $item ) {
				/* translators: 1: severity, 2: title, 3: subject, 4: date first seen. */
				$h .= '<li>' . esc_html( sprintf( __( '[%1$s] %2$s: %3$s (first seen %4$s)', 'bee-monitor' ), Findings::severity_label( $item['severity'] ), Findings::title( $item['rule'] ), $item['subject'], self::local_time( $item['first_seen'] ) ) ) . '</li>';
			}
			$h .= '</ul>';
		}
		if ( 'digest' === $kind ) {
			$problems = self::health_problems();
			if ( $problems ) {
				$h .= '<h2 style="font-size:15px;margin:18px 0 6px;">' . esc_html__( 'Monitor health', 'bee-monitor' ) . '</h2><ul style="margin:0 0 0 18px;padding:0;">';
				foreach ( $problems as $problem ) {
					$h .= '<li>' . esc_html( $problem ) . '</li>';
				}
				$h .= '</ul>';
			}
			if ( ! $items && ! $reminders && ! $problems ) {
				$h .= '<p>' . esc_html__( 'No new findings since the last digest.', 'bee-monitor' ) . '</p>';
			}
		}
		if ( $items ) {
			$h .= '<div style="margin:18px 0 0;padding:10px 12px;background:#f0f6fc;border-radius:4px;font-size:13px;">';
			foreach ( self::general_steps() as $step ) {
				$h .= esc_html( $step ) . '<br>';
			}
			$h .= '</div>';
		}
		return self::html_wrap( $h );
	}

	/**
	 * Outer HTML layout with header and footer.
	 *
	 * @param string $inner Escaped inner HTML.
	 * @return string
	 */
	private static function html_wrap( $inner ) {
		$footer = '';
		foreach ( explode( "\n", self::footer() ) as $line ) {
			$footer .= esc_html( $line ) . '<br>';
		}
		return '<div style="background:#f0f0f1;padding:20px 10px;">'
			. '<div style="max-width:680px;margin:0 auto;background:#fff;border-radius:6px;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1d2327;line-height:1.5;">'
			. '<div style="background:#1d2327;color:#fff;padding:14px 20px;"><span style="font-size:16px;font-weight:600;">Bee Monitor</span> <span style="color:#c3c4c7;font-size:13px;">· ' . esc_html( self::label() ) . '</span></div>'
			. '<div style="padding:18px 20px;">' . $inner . '</div>'
			. '<div style="padding:12px 20px;border-top:1px solid #dcdcde;font-size:12px;color:#646970;">' . $footer . '</div>'
			. '</div></div>';
	}

	/**
	 * Opening lines.
	 *
	 * @param string $kind  Kind.
	 * @param array  $items Findings.
	 * @return string[]
	 */
	private static function intro( $kind, array $items ) {
		$trusted = Storage::trusted_urls();
		$site    = self::label() . ' (' . $trusted['home'] . ')';
		if ( 'baseline' === $kind ) {
			return array(
				/* translators: %s: site label and URL. */
				sprintf( __( 'Bee Monitor created its baseline for %s.', 'bee-monitor' ), $site ),
				__( 'From now on, changes are compared with this baseline. The items below already existed when the baseline was created; review them, because a baseline taken from an infected site treats the infection as normal.', 'bee-monitor' ),
			);
		}
		if ( 'digest' === $kind ) {
			/* translators: %s: site label and URL. */
			return array( sprintf( __( 'Bee Monitor digest for %s.', 'bee-monitor' ), $site ) );
		}
		/* translators: 1: number of findings, 2: site label and URL. */
		return array( sprintf( _n( 'Bee Monitor detected %1$d finding on %2$s.', 'Bee Monitor detected %1$d findings on %2$s.', count( $items ), 'bee-monitor' ), count( $items ), $site ) );
	}

	/**
	 * Warning when WordPress reports a different site address than the recorded one.
	 *
	 * @return string
	 */
	private static function url_warning() {
		$trusted = Storage::trusted_urls();
		if ( untrailingslashit( network_home_url( '/' ) ) === untrailingslashit( $trusted['home'] ) ) {
			return '';
		}
		/* translators: 1: current address, 2: recorded address. */
		return sprintf( __( 'WARNING: WordPress currently reports the site address as %1$s, which differs from the address Bee Monitor recorded (%2$s). Links in this email use the recorded address. Do not follow links to an address you do not recognize.', 'bee-monitor' ), network_home_url( '/' ), $trusted['home'] );
	}

	/**
	 * Time, scan number, and baseline status.
	 *
	 * @param array $summary Scan summary.
	 * @return string
	 */
	private static function meta_line( array $summary ) {
		$meta = Storage::get( 'baseline_meta', array() );
		/* translators: 1: date, 2: scan number, 3: baseline status. */
		return sprintf( __( 'Time: %1$s   Scan: #%2$s   Baseline: %3$s', 'bee-monitor' ), wp_date( 'Y-m-d H:i T' ), isset( $summary['id'] ) ? (int) $summary['id'] : '-', is_array( $meta ) && isset( $meta['status'] ) ? $meta['status'] : __( 'missing', 'bee-monitor' ) );
	}

	/**
	 * Scan statistics line.
	 *
	 * @param array $st Stats.
	 * @return string
	 */
	private static function stats_line( array $st ) {
		/* translators: 1: files checked, 2: added, 3: modified, 4: deleted, 5: unreadable. */
		return sprintf( __( 'Files checked: %1$d   Added: %2$d   Modified: %3$d   Deleted: %4$d   Unreadable: %5$d', 'bee-monitor' ), $st['files'], $st['added'], $st['modified'], $st['deleted'], $st['unreadable'] );
	}

	/**
	 * Counts per severity, e.g. "2 critical".
	 *
	 * @param array $items Findings.
	 * @return string[]
	 */
	private static function severity_counts( array $items ) {
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
		return $parts;
	}

	/**
	 * Findings to detail (grouped, capped) and the number left out.
	 *
	 * @param array $items Findings.
	 * @return array [ shown[], skipped ].
	 */
	private static function shown_items( array $items ) {
		$groups = array();
		foreach ( $items as $item ) {
			if ( $item['severity'] >= Findings::LOW ) {
				$groups[ $item['rule'] . '|' . $item['severity'] ][] = $item;
			}
		}
		$shown   = array();
		$skipped = 0;
		foreach ( $groups as $group ) {
			foreach ( $group as $idx => $item ) {
				if ( count( $shown ) >= self::MAX_DETAILED || ( $idx >= 5 && count( $group ) > 6 ) ) {
					++$skipped;
					continue;
				}
				$shown[] = $item;
			}
		}
		return array( $shown, $skipped );
	}

	/**
	 * General next steps.
	 *
	 * @return string[]
	 */
	private static function general_steps() {
		return array(
			__( 'General next steps:', 'bee-monitor' ),
			__( '1. Review each finding in Bee Monitor > Findings. Mark legitimate changes as Expected.', 'bee-monitor' ),
			__( '2. For suspected compromise: take a full backup for evidence before changing anything, then restore or clean files manually.', 'bee-monitor' ),
			__( '3. After cleanup, reset administrator passwords, rotate the keys and salts in wp-config.php, and rebuild the Bee Monitor baseline.', 'bee-monitor' ),
		);
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
	 * Send via wp_mail with Bee Monitor sender settings. In HTML mode, the plain-text
	 * version is attached as the alternative body for this message only.
	 *
	 * @param string[]    $to      Recipients.
	 * @param string      $subject Subject.
	 * @param string      $text    Plain-text body.
	 * @param string|null $html    HTML body or null.
	 * @param string      $kind    Kind.
	 * @return bool
	 */
	private static function mail( array $to, $subject, $text, $html, $kind ) {
		self::$last_error = '';
		$name             = (string) Settings::value( 'from_name' );
		$from             = (string) Settings::value( 'from_email' );
		$reply            = (string) Settings::value( 'reply_to' );
		$filters          = array(
			'wp_mail_from_name' => function () use ( $name ) {
				return '' !== $name ? $name : 'Bee Monitor';
			},
		);
		if ( '' !== $from && is_email( $from ) ) {
			$filters['wp_mail_from'] = function () use ( $from ) {
				return $from;
			};
		}
		$alt     = function ( $phpmailer ) use ( $text ) {
			$phpmailer->AltBody = $text; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- PHPMailer property.
		};
		$capture = function ( $error ) {
			if ( is_wp_error( $error ) ) {
				self::$last_error = substr( wp_strip_all_tags( $error->get_error_message() ), 0, 200 );
			}
		};
		foreach ( $filters as $hook => $cb ) {
			add_filter( $hook, $cb, 99 );
		}
		if ( null !== $html ) {
			add_action( 'phpmailer_init', $alt, 99 );
		}
		add_action( 'wp_mail_failed', $capture );

		$headers = array( 'Content-Type: ' . ( null !== $html ? 'text/html' : 'text/plain' ) . '; charset=UTF-8' );
		if ( '' !== $reply && is_email( $reply ) ) {
			$headers[] = 'Reply-To: ' . $reply;
		}
		$ok = wp_mail( $to, wp_strip_all_tags( $subject ), null !== $html ? $html : $text, $headers );

		foreach ( $filters as $hook => $cb ) {
			remove_filter( $hook, $cb, 99 );
		}
		remove_action( 'phpmailer_init', $alt, 99 );
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
		Storage::log( $ok ? 'info' : 'error', $ok ? sprintf( 'Bee Monitor %s email sent', $kind ) : sprintf( 'Bee Monitor %s email failed', $kind ), $ok ? array( 'recipients' => count( $to ) ) : array( 'error' => self::$last_error ) );
		return (bool) $ok;
	}

	/**
	 * Whether another email to this recipient fits within the hourly cap.
	 *
	 * @param string $email Recipient.
	 * @return bool
	 */
	private static function within_rate_limit( $email ) {
		$windows = Storage::get( 'mail_window', array() );
		$key     = Storage::recipient_key( $email );
		if ( ! is_array( $windows ) || empty( $windows[ $key ]['start'] ) || time() - (int) $windows[ $key ]['start'] >= HOUR_IN_SECONDS ) {
			return true;
		}
		return (int) $windows[ $key ]['count'] < (int) Settings::value( 'max_emails_per_hour' );
	}

	/**
	 * Count a sent email in the recipient's hourly window.
	 *
	 * @param string $email Recipient.
	 */
	private static function count_sent( $email ) {
		$windows = Storage::get( 'mail_window', array() );
		$windows = is_array( $windows ) && ! isset( $windows['start'] ) ? $windows : array();
		$key     = Storage::recipient_key( $email );
		if ( empty( $windows[ $key ]['start'] ) || time() - (int) $windows[ $key ]['start'] >= HOUR_IN_SECONDS ) {
			$windows[ $key ] = array(
				'start' => time(),
				'count' => 0,
			);
		}
		++$windows[ $key ]['count'];
		foreach ( $windows as $k => $w ) {
			if ( time() - (int) $w['start'] >= HOUR_IN_SECONDS && $k !== $key ) {
				unset( $windows[ $k ] );
			}
		}
		Storage::set( 'mail_window', $windows );
	}

	/**
	 * Label used in subjects and headers: the configured subject label or the site name.
	 *
	 * @return string
	 */
	public static function label() {
		$label = (string) Settings::value( 'subject_label' );
		if ( '' !== $label ) {
			return $label;
		}
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
