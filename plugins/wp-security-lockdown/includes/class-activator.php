<?php
/**
 * Activation lifecycle.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Activation steps, in order:
 *  1. Compatibility was validated by the caller (wp_security_lockdown_activate); network activation is refused here.
 *  2. Create the default policy if none exists (never overwrite an existing one).
 *  3. Register the runtime hooks for THIS request, so the checks below see a working plugin.
 *  4. Apply the policy to persistent options idempotently, recording originals in the ledger.
 *  5. Verify the effective state in-process; HTTP verification is scheduled (see below).
 *  6. Record success / failure in the audit log and the state.
 *
 * Why HTTP verification is not run synchronously: `activate_plugin()` runs this callback BEFORE
 * the plugin is added to `active_plugins`, so a loopback request made now would reach a site on
 * which the plugin is not active yet and produce a misleading "not working". A single cron event
 * runs the HTTP probes shortly afterwards; until then the dashboard says "not verified".
 *
 * Activation never fatals on an internal error: the failure is logged and shown on the dashboard.
 */
class Activator {

	const NOTICE_TRANSIENT = 'wp_security_lockdown_activation_notice';

	/**
	 * Runs the activation steps.
	 *
	 * @param bool $network_wide Whether activated network-wide on multisite.
	 * @return void
	 */
	public static function activate( $network_wide = false ) {
		if ( is_multisite() && $network_wide ) {
			deactivate_plugins( plugin_basename( WP_SECURITY_LOCKDOWN_FILE ), true, true );
			wp_die(
				esc_html__( 'WP Security Lockdown must be activated on each site separately; network-wide activation is not supported because several controls change site-level settings.', 'wp-security-lockdown' ),
				esc_html__( 'Plugin activation failed', 'wp-security-lockdown' ),
				array( 'back_link' => true )
			);
		}

		$plugin = Plugin::instance();
		$error  = '';

		try {
			if ( false === get_option( Settings_Repository::OPTION ) ) {
				add_option( Settings_Repository::OPTION, Settings_Repository::defaults(), '', true );
			}

			$plugin->policy()->register_modules();
			$results = $plugin->policy()->apply_all();
			$plugin->policy()->verify( false );

			$changed = 0;
			foreach ( $results as $result ) {
				if ( in_array( $result['status'], array( Rollback::APPLIED, Rollback::REAPPLIED ), true ) ) {
					++$changed;
				}
			}
			$plugin->logger()->info(
				'activated',
				'Plugin activated and policy applied.',
				array(
					'version' => WP_SECURITY_LOCKDOWN_VERSION,
					'php'     => PHP_VERSION,
					'wp'      => get_bloginfo( 'version' ),
					'changed' => $changed,
				)
			);

			if ( ! wp_next_scheduled( Plugin::CRON_VERIFY ) ) {
				wp_schedule_single_event( time() + 30, Plugin::CRON_VERIFY );
			}
			set_transient( self::NOTICE_TRANSIENT, 1, HOUR_IN_SECONDS );
		} catch ( \Throwable $e ) {
			$error = get_class( $e ) . ' at ' . basename( $e->getFile() ) . ':' . $e->getLine();
			$plugin->logger()->error( 'activation_error', 'Activation hit an internal error; check the dashboard.', array( 'where' => $error ) );
		}//end try

		$previous = $plugin->state()->get( 'activation' );
		$plugin->state()->set(
			'activation',
			array(
				'time'    => time(),
				'version' => WP_SECURITY_LOCKDOWN_VERSION,
				'php'     => PHP_VERSION,
				'wp'      => get_bloginfo( 'version' ),
				'count'   => isset( $previous['count'] ) ? (int) $previous['count'] + 1 : 1,
				'error'   => $error,
			)
		);
		$plugin->logger()->flush();
	}
}
