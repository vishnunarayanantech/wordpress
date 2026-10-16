<?php
/**
 * Deactivation lifecycle.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * What deactivation does and does not do:
 *
 *  - Stops immediately (nothing is loaded any more): every runtime protection (comment/ping filters,
 *    XML-RPC rejection, REST gate, login limiter, disclosure filters, file-editor capability filter).
 *  - Removes: the scheduled verification event, temporary lockouts and cached diagnostics.
 *  - Persists: discussion options the plugin changed (default_comment_status, default_ping_status,
 *    default_pingback_flag), the policy settings, the change ledger and the audit log. These stay
 *    so that a later re-activation, or a manual rollback, still knows the original values.
 *  - Optional: with the "restore on deactivation" setting the ledger is rolled back here, using the
 *    same conflict-aware logic as the dashboard (values changed by someone else are never overwritten).
 *
 * Nothing is deleted from the audit log or from site content.
 */
class Deactivator {

	/**
	 * Runs the deactivation steps.
	 *
	 * @param bool $network_wide Unused; network activation is not supported.
	 * @return void
	 */
	public static function deactivate( $network_wide = false ) {
		unset( $network_wide );
		$plugin = Plugin::instance();

		wp_clear_scheduled_hook( Plugin::CRON_VERIFY );
		delete_transient( Activator::NOTICE_TRANSIENT );
		// Lockouts stop being enforced with the plugin; do not let stale ones resurrect on re-activation.
		Rate_Limiter::clear_all();
		Health_Check::clear_caches();

		$restored = 0;
		if ( $plugin->settings()->get( 'lifecycle.rollback_on_deactivation', false ) ) {
			foreach ( $plugin->rollback()->release_all( false ) as $result ) {
				if ( in_array( $result['status'], array( Rollback::RESTORED, Rollback::NOTHING ), true ) ) {
					++$restored;
				}
			}
		}

		$plugin->logger()->info(
			'deactivated',
			'Plugin deactivated; runtime protections have stopped.',
			array( 'restored' => $restored )
		);
		$plugin->logger()->flush();
	}
}
