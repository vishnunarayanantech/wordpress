<?php
/**
 * Runs when the plugin is deleted from the Plugins screen.
 *
 * Removes ONLY configuration and temporary data that the plugin created:
 *  - the policy settings,
 *  - transients (login lockout counters, cached diagnostics, one-off notices),
 *  - the scheduled verification event.
 *
 * Deliberately KEPT:
 *  - `wp_security_lockdown_audit_log`: security logs are never deleted automatically.
 *  - `wp_security_lockdown_state`: the change ledger (original values of options the plugin changed),
 *    so the originals stay recoverable. Remove both by hand if you want them gone:
 *      wp option delete wp_security_lockdown_audit_log wp_security_lockdown_state
 *
 * Never touched: posts, pages, comments, users, uploads, other options, plugins and themes. The
 * discussion defaults the plugin changed are left as they are (use the Rollback tab before deleting
 * the plugin if you want the originals back).
 *
 * @package WP_Security_Lockdown
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

delete_option( 'wp_security_lockdown_settings' );
wp_clear_scheduled_hook( 'wp_security_lockdown_verify_event' );

global $wpdb;
// Only this plugin's own transients (and their timeout rows): the prefix is fixed, never user input.
$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- one-off cleanup during uninstall.
	$wpdb->prepare(
		"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s",
		$wpdb->esc_like( '_transient_wp_security_lockdown_' ) . '%',
		$wpdb->esc_like( '_transient_timeout_wp_security_lockdown_' ) . '%'
	)
);
