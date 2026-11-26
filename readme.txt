=== Bee Monitor ===
Contributors: keithquinones
Tags: security, malware, file integrity, monitoring, alerts
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Detects suspicious PHP file changes, core tampering, and risky admin or settings changes, then emails clear, deduplicated alerts. Read-only.

== Description ==

Bee Monitor builds a signed baseline of your site's PHP and server configuration files and checks for changes on a schedule. It verifies WordPress core against official checksums, watches privileged accounts, roles, key options, and scheduled tasks, and emails grouped alerts with redacted evidence and next steps.

Bee Monitor never deletes, quarantines, or modifies files. Every finding is for you to review.

= What it detects =

* **Confirmed changes:** core files that differ from official WordPress.org checksums, unknown or missing core files, PHP and server config files added, changed, or deleted since the baseline (core, plugins, themes, must-use plugins, drop-ins, uploads, the WordPress root), wp-config.php and .htaccess changes, new or changed privileged accounts (including ones inserted directly into the database), role and key option changes, and tampering with Bee Monitor itself.
* **Location rules:** executable PHP in uploads, cache, and temporary folders, and new PHP files in unusual places.
* **Heuristic indicators (for review, not proof):** web shell and obfuscation patterns, risky server directives, unusual includes in wp-config.php, scheduled tasks or email hooks defined outside plugins and themes, injected scripts in options and posts, failed-login bursts, and privileged logins from new networks.

Each finding shows its basis, severity, and confidence. Legitimate code sometimes matches heuristic patterns.

= Alerts your way =

* Route alerts per recipient: choose categories and the severity that triggers an immediate email; everything else goes to an hourly, daily, or weekly digest at the time you choose.
* HTML or plain-text emails, a custom From name, From and Reply-To address, a subject label for each site, and a summary mode that leaves code out of emails.
* Ignore rules for known-noisy paths, read-only access for clients, WordPress Site Health checks, and WP-CLI commands.

= Limitations =

No monitoring tool detects every attack. Bee Monitor runs inside WordPress, so an attacker with code execution can disable it or suppress email. Deactivation emails, signed baseline records, scan-gap detection, and an optional external heartbeat make this visible, but cannot prevent it. Requests to standalone PHP files bypass WordPress and need server logs or a firewall. A baseline created on an infected site treats unchanged infected files as normal, so review the first "Baseline created" email carefully. Excluded paths are not checked.

== Installation ==

1. Install and activate. On multisite, network-activate it (per-site activation is refused because files are shared).
2. Go to Bee Monitor > Tools & Status and click **Send test email**.
3. Click **Run scan now** to create the baseline, then review the "Baseline created" email.
4. Recommended: add `define( 'BEE_MONITOR_HMAC_KEY', 'a-random-64-character-string' );` to wp-config.php, set a heartbeat URL, and run WP-Cron from a real server cron job.

== External services ==

Bee Monitor connects to these services:

* **WordPress.org Core Checksums API** (api.wordpress.org). Used to verify WordPress core files. When: during scans, at most once a day per WordPress version (results are cached). Data sent: your WordPress version and locale, the same information WordPress itself sends when checking for updates. You can turn this off under Settings > Integrity and site checks. Service: https://wordpress.org/ — Privacy policy: https://wordpress.org/about/privacy/
* **Heartbeat URL (optional, off by default).** If you enter a URL, Bee Monitor sends an HTTPS GET request to it after each completed scan, with the user agent "Bee Monitor/version" and no site data. Use any heartbeat monitoring service you choose, for example Healthchecks.io (https://healthchecks.io/, privacy policy: https://healthchecks.io/privacy/). That service's own terms and privacy policy apply.

Alerts are sent with your site's own wp_mail() configuration.

== Data stored ==

Bee Monitor stores data in its own database tables and options on your site only:

* File paths and SHA-256 hashes of monitored files.
* Findings with short, redacted evidence. Key, salt, password, and credential values are replaced with [redacted]; full file contents are never stored or emailed.
* Alert recipient email addresses, and a hashed record of which alerts were sent to each.
* For accounts with administrative capabilities: username, masked email address, and roles.
* For login monitoring: failure counts, masked networks (for example 203.0.113.x), and keyed hashes of attempted usernames and of the networks administrators sign in from.

Closed findings are deleted after the retention period (default 180 days). Bee Monitor suggests text for your privacy policy and supports the WordPress personal data export and erase tools. Uninstalling keeps data unless "Delete all Bee Monitor data on uninstall" is enabled.

== Frequently Asked Questions ==

= Does it block or change anything? =

No. Admins can edit content, settings, and users as usual. Bee Monitor only reports.

= How does it avoid flooding my inbox? =

Each finding is emailed once. High and critical findings are sent immediately; lower ones go to a digest. There is an hourly email cap. Core updates are verified against official checksums, and recorded plugin and theme updates are accepted automatically unless the changed files contain suspicious code.

= What do Expected and Resolved mean? =

Expected: the change is legitimate. The baseline is updated and that exact finding never alerts again. Resolved: you fixed the problem. If it reappears, you are alerted again once.

= Why does it check the directory above WordPress? =

wp-config.php and prepend files often live there. Bee Monitor only reads PHP and server config files in that one directory (not subdirectories). Turn it off under Settings > Scope and exclusions.

= What if the baseline is deleted or edited? =

You get a critical finding, and scans continue in limited mode until you rebuild the baseline from Bee Monitor > Baseline.

= What if WP-Cron does not run? =

The next scan reports the gap, the digest reports monitor health, and the optional heartbeat service alerts you independently.

= How can I test that alerts work? =

On a staging site, create `wp-content/uploads/bee-monitor-canary.php` containing `<?php echo 'canary';`, then click Run scan now. Expect a critical "Executable PHP file in uploads" email. Delete the file and mark the finding Resolved.

= Can I use WP-CLI? =

Yes: `wp bee-monitor scan`, `status`, `findings`, `accept`, `resolve`, `accept-all`, `deploy-window <minutes>`, `test-email`, and `digest`. Run `wp help bee-monitor` for details. A typical deployment: `wp bee-monitor deploy-window 30`, deploy, `wp bee-monitor scan`, then review and `wp bee-monitor accept-all`.

= Can clients see findings without changing anything? =

Yes. Choose roles under Settings > Tamper detection and data > Read-only access (single sites). Those users see the Findings screen only.

= What are the requirements? =

WordPress 6.5+, PHP 7.4+, working email delivery (an SMTP plugin is recommended), and read access to WordPress files. Admin screens require manage_options (manage_network_options on multisite).

== Changelog ==

= 1.1.0 =
* Per-recipient alert routing by category and severity, with per-recipient hourly limits.
* HTML emails with a plain-text version, sender settings, subject label, and summary evidence mode.
* Digest at a chosen time, with a new weekly option.
* Ignore rules, including "Ignore similar findings in this folder".
* Read-only access for chosen roles, Site Health tests, and WP-CLI commands with a deployment window.
* Upgrading from 1.0.x keeps your existing recipients and alert threshold.

= 1.0.1 =
* Escaping applied at output on all admin screens.
* Database table names use prepared identifiers.
* Added External services and Data stored documentation, privacy policy text, personal data export and erase, and a retention setting for closed findings.
* Server configuration evidence now shows directives only, never values.
* Removed CDN domains from the default script allowlist; removed manual translation loading.
* Scan auto-start links now require a nonce.

= 1.0.0 =
* Initial release.
