<?php
/**
 * Plugin Name:       Bee Monitor
 * Description:       Monitors PHP files, WordPress core integrity, and key site settings for signs of malware, unauthorized changes, or injection, and emails clear alerts. Bee Monitor reports findings only; it never deletes, quarantines, or modifies files.
 * Version:           1.5.0
 * Requires at least: 6.5
 * Requires PHP:      7.4
 * Author:            Keith Quinones
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       bee-monitor
 * Network:           true
 *
 * @package BeeMonitor
 */

defined( 'ABSPATH' ) || exit;

define( 'BEE_MONITOR_VERSION', '1.5.0' );
define( 'BEE_MONITOR_DB_VERSION', '3' );
define( 'BEE_MONITOR_FILE', __FILE__ );
define( 'BEE_MONITOR_DIR', plugin_dir_path( __FILE__ ) );
define( 'BEE_MONITOR_URL', plugin_dir_url( __FILE__ ) );

require_once BEE_MONITOR_DIR . 'includes/class-storage.php';
require_once BEE_MONITOR_DIR . 'includes/class-settings.php';
require_once BEE_MONITOR_DIR . 'includes/class-paths.php';
require_once BEE_MONITOR_DIR . 'includes/class-redactor.php';
require_once BEE_MONITOR_DIR . 'includes/class-signatures.php';
require_once BEE_MONITOR_DIR . 'includes/class-heuristics.php';
require_once BEE_MONITOR_DIR . 'includes/class-findings.php';
require_once BEE_MONITOR_DIR . 'includes/class-activity.php';
require_once BEE_MONITOR_DIR . 'includes/class-context.php';
require_once BEE_MONITOR_DIR . 'includes/class-site-monitor.php';
require_once BEE_MONITOR_DIR . 'includes/class-login-monitor.php';
require_once BEE_MONITOR_DIR . 'includes/class-remote.php';
require_once BEE_MONITOR_DIR . 'includes/class-scanner.php';
require_once BEE_MONITOR_DIR . 'includes/class-notifier.php';
require_once BEE_MONITOR_DIR . 'includes/class-privacy.php';
require_once BEE_MONITOR_DIR . 'includes/class-icons.php';
require_once BEE_MONITOR_DIR . 'includes/class-brand.php';
require_once BEE_MONITOR_DIR . 'includes/class-repair.php';
require_once BEE_MONITOR_DIR . 'includes/class-report.php';
require_once BEE_MONITOR_DIR . 'includes/class-site-health.php';
require_once BEE_MONITOR_DIR . 'includes/class-cli.php';
require_once BEE_MONITOR_DIR . 'includes/class-plugin.php';
require_once BEE_MONITOR_DIR . 'includes/class-admin.php';

register_activation_hook( __FILE__, array( 'BeeMonitor\Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'BeeMonitor\Plugin', 'deactivate' ) );

add_action( 'plugins_loaded', array( 'BeeMonitor\Plugin', 'instance' ) );
