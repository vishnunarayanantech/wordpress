<?php
/**
 * Base class for hardening modules.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * A module groups related controls. It registers its runtime hooks, reports the effective state of
 * each control and knows how to verify that the control actually works.
 *
 * Reporting vocabulary (kept deliberately small):
 *
 *  state         what the plugin can see from inside this request
 *      enforced  every hook / setting this control needs is in place
 *      partial   some of it is in place, something is missing or overridden (see failure_reason)
 *      failed    the control is switched on but is not being enforced
 *      disabled  the administrator switched it off
 *      monitor   the control only observes (security updates)
 *
 *  verification  functional evidence that the control works
 *      verified  a test showed the intended effect (see method)
 *      unverified no test has been run for the current policy, or it could not run
 *      failed    a test ran and showed the control is NOT working
 *
 *  method        in_process (hooks and filters behave as intended inside PHP),
 *                self_test (the control's storage / logic round-tripped),
 *                http_probe (a real HTTP request was rejected / sanitized as intended)
 */
abstract class Abstract_Module {

	const STATE_ENFORCED = 'enforced';
	const STATE_PARTIAL  = 'partial';
	const STATE_FAILED   = 'failed';
	const STATE_DISABLED = 'disabled';
	const STATE_MONITOR  = 'monitor';

	const VERIFIED   = 'verified';
	const UNVERIFIED = 'unverified';
	const FAILED     = 'failed';

	const METHOD_IN_PROCESS = 'in_process';
	const METHOD_SELF_TEST  = 'self_test';
	const METHOD_HTTP       = 'http_probe';
	const METHOD_NONE       = 'none';

	/**
	 * Service container.
	 *
	 * @var Plugin
	 */
	protected $plugin;

	/**
	 * Service container.
	 *
	 * @param Plugin $plugin Service container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * Returns the module slug.
	 *
	 * @return string Module slug.
	 */
	abstract public function slug();

	/**
	 * Control definitions. Translated strings: only call this when rendering the admin UI.
	 *
	 * @return array control id => array( title, description ).
	 */
	abstract public function controls();

	/**
	 * Registers runtime hooks. Must be cheap, must not touch the network or the filesystem, and
	 * must not call translation functions (it can run before `init`).
	 *
	 * @return void
	 */
	abstract public function register();

	/**
	 * Persistent options this module changes, per control.
	 *
	 * @return array control id => array( option name => desired value ).
	 */
	public function managed_options() {
		return array();
	}

	/**
	 * Effective state of every control of this module, as seen from the current request.
	 *
	 * @return array control id => report (see report_defaults()).
	 */
	abstract public function report();

	/**
	 * Functional verification.
	 *
	 * @param Http_Probe|null $probe Pass a probe to allow real HTTP requests; null limits checks to PHP.
	 * @return array control id => array( status, method, detail ).
	 */
	public function verify( ?Http_Probe $probe = null ) {
		unset( $probe );
		return array();
	}

	/**
	 * Fills a report with defaults so every control exposes the same fields.
	 *
	 * @param string $control   Control id.
	 * @param array  $overrides Values to set.
	 * @return array
	 */
	protected function make_report( $control, array $overrides ) {
		$definitions = $this->controls();
		$definition  = isset( $definitions[ $control ] ) ? $definitions[ $control ] : array();

		return array_merge(
			array(
				'id'                                       => $control,
				'module'                                   => $this->slug(),
				'title'                                    => isset( $definition['title'] ) ? $definition['title'] : $control,
				'description'                              => isset( $definition['description'] ) ? $definition['description'] : '',
				'enabled'                                  => $this->plugin->settings()->control_enabled( $control ),
				'desired'                                  => '',
				// The policy the control is meant to achieve.
												'state'    => self::STATE_DISABLED,
				'enforcement'                              => array(),
				// How it is enforced (hooks, options, constants).
												'persists' => '',
				// What stays in effect after deactivation (empty = nothing).
												'failure_reason' => '',
				'warnings'                                 => array(),
				// Compatibility warnings.
												'manual_action' => '',
				// Non-empty when a human has to do something.
												'server_level' => false,
				// True when only server configuration can finish the job.
												'details'  => array(),
			// Sub-checks: array( label, status ok|warn|fail|info, text ).
			),
			$overrides
		);
	}

	/**
	 * Convenience for verification results.
	 *
	 * @param string $status Verified / unverified / failed.
	 * @param string $method Verification method.
	 * @param string $detail Short human-readable explanation.
	 * @return array
	 */
	protected function result( $status, $method, $detail ) {
		return array(
			'status' => $status,
			'method' => $method,
			'detail' => $detail,
		);
	}

	/**
	 * Turns individual check outcomes into one verification verdict.
	 *
	 * Rules: any failing check fails the control (the strongest failing method is reported). A control
	 * is only "verified over HTTP" when at least one HTTP check actually ran and every check passed.
	 * When `$http_required` is true, in-process checks alone are NOT enough evidence (for example,
	 * a PHP filter being attached does not prove xmlrpc.php rejects requests), so the control stays
	 * "unverified" and the detail says why.
	 *
	 * @param array[] $local               In-process checks: array( bool ok, string label ).
	 * @param array[] $http                HTTP checks that ran: array( bool ok, string label ).
	 * @param bool    $http_required       Whether an HTTP probe is needed for a "verified" verdict.
	 * @param string  $http_missing_reason Why no HTTP check ran (shown when it matters).
	 * @param string  $local_method        Method name for the in-process evidence.
	 * @return array
	 */
	protected function conclude( array $local, array $http, $http_required, $http_missing_reason, $local_method = self::METHOD_IN_PROCESS ) {
		foreach ( array(
			self::METHOD_HTTP => $http,
			$local_method     => $local,
		) as $method => $checks ) {
			$failed = array();
			foreach ( $checks as $check ) {
				if ( ! $check[0] ) {
					$failed[] = $check[1];
				}
			}
			if ( $failed ) {
				return $this->result( self::FAILED, $method, implode( '; ', $failed ) );
			}
		}

		$labels = array_map(
			static function ( $check ) {
				return $check[1];
			},
			array_merge( $http, $local )
		);

		if ( $http ) {
			return $this->result( self::VERIFIED, self::METHOD_HTTP, implode( '; ', $labels ) );
		}
		if ( $http_required ) {
			$detail = $http_missing_reason ? $http_missing_reason : __( 'An HTTP probe has not run yet.', 'wp-security-lockdown' );
			return $this->result( self::UNVERIFIED, $local_method, $detail );
		}
		return $this->result( self::VERIFIED, $local_method, implode( '; ', $labels ) );
	}

	/**
	 * Whether a callback is attached to a hook (any priority).
	 *
	 * @param string   $hook     Hook name.
	 * @param callable $callback Callback (array form for methods).
	 * @return bool
	 */
	protected function hooked( $hook, $callback ) {
		return false !== has_filter( $hook, $callback );
	}
}
