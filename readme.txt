=== Bee Monitor ===
Contributors: keithquinones
Tags: security, malware, file integrity, monitoring, audit log
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.5.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Detects suspicious PHP file changes, core tampering, and risky admin or settings changes, then emails clear, deduplicated alerts.

== Description ==

Bee Monitor builds a signed baseline of your site's PHP and server configuration files, verifies WordPress core (and optionally WordPress.org plugins) against official checksums, scans for documented backdoor signatures and suspicious patterns, watches users, roles, settings, and scheduled tasks, and emails grouped alerts with redacted evidence and a recommended next step.

Bee Monitor never changes files on its own. If you turn on administrator-reviewed repairs, an administrator can repair core or WordPress.org plugin files from official, checksum-verified sources, or quarantine flagged files. Each action needs confirmation, keeps a recoverable copy, and is logged.

= Features =

* **File integrity:** added, modified, and missing files in core, plugins, themes, must-use plugins, drop-ins, uploads, and the root. Each result says whether it was verified against official WordPress.org checksums or compared with the local baseline only (unverified).
* **Malware signatures and patterns:** a versioned local signature set (BM-SIG-###) plus heuristics, with file, line, redacted evidence, severity, and confidence. Matches are leads for review, not proof of infection.
* **Persistence and configuration checks:** hidden administrators, admin application passwords, runtime prepend files, the file editor, debug exposure, world-writable files, unsupported PHP.
* **Public page checks (optional):** injected or obfuscated scripts, hidden frames and links, external redirects, search-engine cloaking, and visible errors on your own public pages.
* **Activity log:** updates, activations, user and role changes, key settings, scans, and Bee Monitor actions, with configurable retention and deletion.
* **Alerts and reports:** per-recipient routing, digests, JSON/CSV reports that exclude personal data by default, WP-CLI, and Site Health tests.

= Limitations =

No tool detects every attack. Signatures and heuristics find known techniques and suspicious patterns; new or heavily disguised malware can be missed, and legitimate code can match. Bee Monitor runs inside WordPress, so code with full access can disable it; deactivation emails, signed baseline records, and the optional heartbeat make that visible. Public page checks see only rendered output, not server files. Bee Monitor does not check blocklist status (that needs third-party services with their own terms); use Google Search Console for that. Theme files and non-WordPress.org plugins are compared with the local baseline only.

== Installation ==

1. Install and activate (network-activate on multisite).
2. In Bee Monitor > Tools & Status, send a test email and run a scan to create the baseline. Review the "Baseline created" email.
3. Optional: set `BEE_MONITOR_HMAC_KEY` in wp-config.php, a heartbeat URL, and a server cron job.

== External services ==

* **WordPress.org core checksums** (api.wordpress.org), on by default: sends your WordPress version and locale, at most daily.
* **WordPress.org plugin checksums** (downloads.wordpress.org), off by default: sends a plugin's folder name and version when one of its files changes, at most daily per version.
* **Official file sources** (core.svn.wordpress.org, plugins.svn.wordpress.org): only when an administrator confirms a repair; requests the one file being repaired.
* **Heartbeat URL**, off by default: an HTTPS GET to the address you choose after each scan, with no site data.

WordPress.org privacy policy: https://wordpress.org/about/privacy/

Public page checks request only this site's own pages. Alerts use your site's wp_mail() setup.

== Data stored ==

File paths and hashes; findings with redacted evidence (secrets and file contents are never stored); usernames, masked emails, and roles of privileged accounts; masked networks and keyed hashes for login monitoring; alert recipient addresses; the activity log (user IDs, not names; kept 30 days by default); and, only after a confirmed repair or quarantine, the affected file in a protected quarantine folder. Bee Monitor supports WordPress personal data export and erase, and suggests privacy policy text. Data is kept on uninstall unless you choose to delete it.

== Frequently Asked Questions ==

= Will Bee Monitor delete or change files? =

Not by itself. Repairs and quarantine are off by default, available only for specific findings, and always need an administrator's confirmation. Repairs use official files verified against official checksums, back up the current file first, and roll back on failure. Quarantined files can be restored.

= What does "unverified" mean? =

The file was compared with Bee Monitor's own baseline, not an official source, because none exists (themes, premium and custom plugins). A change is real, but whether it is legitimate needs your review.

= How does it avoid alert floods? =

Each finding is emailed once; lower severities go to a digest; there is an hourly cap; verified core and plugin updates are accepted automatically.

= Can I use WP-CLI? =

Yes: `scan` (`--full`, `--remote`), `cancel`, `status`, `findings`, `accept`, `resolve`, `accept-all`, `deploy-window`, `export`, `activity`, `test-email`, and `digest`.

= How do I test alerts? =

On staging, create `wp-content/uploads/bee-monitor-canary.php` containing `<?php echo 'canary';` and run a scan. Expect a critical email.

== Credits ==

Icons: Lucide (https://lucide.dev), ISC License; see assets/icons/LICENSE-lucide.txt. The bee logo is original artwork made for Bee Monitor and is licensed GPLv2 or later with the plugin.

== Changelog ==

= 1.5.0 =
* Redesigned dashboard: security status, scan controls on the dashboard, key figures, top priorities with verification labels, severity breakdown, and recent activity. New bee logo and admin menu icon, consistent section navigation, and improved empty, running, and error states.

= 1.4.0 =
* Verification labels on file findings, a versioned signature set, optional public page checks, an activity log with retention, and optional administrator-reviewed repair and quarantine with backups.

= 1.3.0 =
* Icons, full integrity scan, copy buttons, accessibility improvements.

= 1.2.0 =
* Overview dashboard, investigation panel, scan cancel, posture checks, plugin checksums, reports.

= 1.1.0 =
* Alert routing, HTML email, ignore rules, read-only access, Site Health, WP-CLI.

= 1.0.0 =
* Initial release.
