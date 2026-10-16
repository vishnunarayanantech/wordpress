<?php
/**
 * XML-RPC.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;

defined( 'ABSPATH' ) || exit;

/**
 * Control `xmlrpc`.
 *
 * Why an early exit and not just `xmlrpc_enabled`: WordPress documents that this filter "only
 * controls whether XML-RPC methods requiring authentication are enabled". It does not stop
 * pingback.ping, system.listMethods, system.multicall or any other unauthenticated method. So in
 * `block` mode the request is refused with HTTP 403 on `plugins_loaded` (priority 0), before the
 * XML-RPC server class is even loaded. The filters are kept as defence in depth. Hiding the RSD
 * link or the X-Pingback header is cosmetic and is NOT what protects the site.
 *
 * In `allow` mode (for sites that explicitly need XML-RPC) the endpoint stays reachable but the
 * pingback methods, the classic DDoS-amplification vector, are always removed.
 */
class Xmlrpc_Hardening extends Abstract_Module {

	const SEEN_TRANSIENT = 'wp_security_lockdown_xmlrpc_seen';

	const PINGBACK_METHODS = array( 'pingback.ping', 'pingback.extensions.getPingbacks' );

	/**
	 * Whether register() ran in this request.
	 *
	 * @var bool Whether register() ran in this request.
	 */
	private $registered = false;

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'xmlrpc_hardening';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'xmlrpc' => array(
				'title'       => __( 'XML-RPC', 'wp-security-lockdown' ),
				'description' => __( 'Rejects every request to xmlrpc.php (HTTP 403) before WordPress loads the XML-RPC server. Pingback methods are removed even when XML-RPC is explicitly allowed.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Registers the XML-RPC hooks and, in block mode, ends an XML-RPC request.
	 *
	 * @return void
	 */
	public function register() {
		$this->registered = true;

		add_filter( 'xmlrpc_methods', array( $this, 'filter_methods' ), 999 );

		if ( 'block' !== $this->mode() ) {
			return;
		}
		add_filter( 'xmlrpc_enabled', '__return_false', 999 );
		remove_action( 'wp_head', 'rsd_link' );
		// Cosmetic: stops advertising the endpoint.

		if ( $this->is_xmlrpc_request() ) {
			$this->block_request();
		}
	}

	/**
	 * `block` or `allow`.
	 *
	 * @return string
	 */
	public function mode() {
		return 'allow' === $this->plugin->settings()->get( 'xmlrpc.mode', 'block' ) ? 'allow' : 'block';
	}

	/**
	 * Whether the current request is a request to xmlrpc.php (the constant is defined before wp-load.php runs).
	 *
	 * @return bool
	 */
	protected function is_xmlrpc_request() {
		return defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST;
	}

	/**
	 * Refuses the request. No XML-RPC code is loaded and no authentication is attempted.
	 *
	 * @return void
	 */
	protected function block_request() {
		$this->note_blocked();

		status_header( 403 );
		if ( ! headers_sent() ) {
			header( 'Content-Type: text/plain; charset=utf-8' );
			header( 'Cache-Control: no-store' );
		}
		echo 'XML-RPC is disabled on this site.';
		$this->plugin->logger()->flush();
		$this->terminate();
	}

	/**
	 * Ends the request. Separate so tests can observe a block without terminating PHP.
	 *
	 * @return void
	 */
	protected function terminate() {
		exit;
	}

	/**
	 * Logs the first rejected request of each day (never every request: attackers could flood the log).
	 *
	 * @return void
	 */
	private function note_blocked() {
		if ( false === get_transient( self::SEEN_TRANSIENT ) ) {
			set_transient( self::SEEN_TRANSIENT, time(), DAY_IN_SECONDS );
			$this->plugin->logger()->info( 'xmlrpc_blocked', 'An XML-RPC request was rejected (logged at most once per day).' );
		}
	}

	/**
	 * `xmlrpc_methods`: defence in depth.
	 *
	 * @param array $methods Registered XML-RPC methods.
	 * @return array
	 */
	public function filter_methods( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		if ( 'block' === $this->mode() ) {
			return array();
		}
		foreach ( self::PINGBACK_METHODS as $method ) {
			unset( $methods[ $method ] );
		}
		return $methods;
	}

	/**
	 * Control id => report (the shape Policy_Manager expects).
	 *
	 * @return array
	 */
	public function report() {
		return array( 'xmlrpc' => $this->build_report() );
	}

	/**
	 * Builds the report of this module's single control.
	 *
	 * @return array
	 */
	private function build_report() {
		$mode   = $this->mode();
		$report = $this->make_report(
			'xmlrpc',
			array(
				'enabled'     => true,
				'desired'     => 'block' === $mode
					? __( 'xmlrpc.php answers HTTP 403 to every request.', 'wp-security-lockdown' )
					: __( 'XML-RPC stays reachable (declared necessary), but pingback methods are removed.', 'wp-security-lockdown' ),
				'enforcement' => 'block' === $mode
					? array(
						__( 'Early exit with HTTP 403 on plugins_loaded, before the XML-RPC server class is loaded.', 'wp-security-lockdown' ),
						__( 'Filters xmlrpc_enabled=false and xmlrpc_methods=[] as defence in depth.', 'wp-security-lockdown' ),
					)
					: array( __( 'Filter xmlrpc_methods removes pingback.ping and pingback.extensions.getPingbacks.', 'wp-security-lockdown' ) ),
				'persists'    => '',
			)
		);

		$report['warnings'][] = __( 'Remote publishing clients that use XML-RPC (older WordPress mobile apps, desktop blog editors, MetaWeblog / Blogger API tools, some IFTTT / Zapier actions) stop working while XML-RPC is blocked. Use the REST API with Application Passwords instead.', 'wp-security-lockdown' );

		$jetpack = in_array( 'jetpack/jetpack.php', (array) get_option( 'active_plugins', array() ), true );
		if ( $jetpack ) {
			$report['warnings'][] = __( 'Jetpack is active. Jetpack connects to WordPress.com through xmlrpc.php, so blocking XML-RPC breaks or disconnects it.', 'wp-security-lockdown' );
			if ( 'block' === $mode ) {
				$report['manual_action'] = __( 'Jetpack needs XML-RPC. Switch XML-RPC to "Allow" in the policy settings, or deactivate Jetpack.', 'wp-security-lockdown' );
			}
		}
		if ( 'allow' === $mode ) {
			$report['warnings'][] = __( 'XML-RPC is reachable, so password guessing through system.multicall is possible. The login limiter counts these attempts, but only if it is enabled and your proxy settings are correct.', 'wp-security-lockdown' );
		}

		$methods_filter      = $this->hooked( 'xmlrpc_methods', array( $this, 'filter_methods' ) );
		$report['details'][] = array(
			'label'  => 'xmlrpc_methods',
			'status' => $methods_filter ? 'ok' : 'fail',
			'text'   => $methods_filter ? __( 'Filter is attached.', 'wp-security-lockdown' ) : __( 'Filter is NOT attached.', 'wp-security-lockdown' ),
		);

		$missing = ! $methods_filter || ! $this->registered;
		if ( 'block' === $mode ) {
			$disabled            = $this->hooked( 'xmlrpc_enabled', '__return_false' );
			$report['details'][] = array(
				'label'  => 'xmlrpc_enabled',
				'status' => $disabled ? 'ok' : 'fail',
				'text'   => $disabled ? __( 'Filter is attached.', 'wp-security-lockdown' ) : __( 'Filter is NOT attached.', 'wp-security-lockdown' ),
			);
			$missing             = $missing || ! $disabled;
		}

		if ( $missing ) {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = __( 'The XML-RPC hooks were not registered in this request.', 'wp-security-lockdown' );
		} else {
			$report['state'] = self::STATE_ENFORCED;
		}
		return $report;
	}

	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- verification deliberately invokes core hooks to prove this plugin's callbacks act on them.
	/**
	 * Verification requires an HTTP probe: a filter being attached does not prove xmlrpc.php rejects requests.
	 *
	 * @param Http_Probe|null $probe Probe or null.
	 * @return array
	 */
	public function verify( ?Http_Probe $probe = null ) {
		$mode  = $this->mode();
		$local = array();

		$methods = apply_filters(
			'xmlrpc_methods',
			array(
				'pingback.ping'                    => 'x',
				'pingback.extensions.getPingbacks' => 'x',
				'wp.getPosts'                      => 'x',
			)
		);
		if ( 'block' === $mode ) {
			$local[] = array( false === apply_filters( 'xmlrpc_enabled', true ), 'xmlrpc_enabled filter returns false' );
			$local[] = array( array() === $methods, 'no XML-RPC methods are registered' );
		} else {
			$local[] = array( ! isset( $methods['pingback.ping'] ) && ! isset( $methods['pingback.extensions.getPingbacks'] ), 'pingback methods are removed' );
		}

		$http   = array();
		$reason = __( 'Run verification to send a real request to xmlrpc.php.', 'wp-security-lockdown' );
		if ( $probe ) {
			$reason = $this->probe_http( $probe, $mode, $http );
		}
		return array( 'xmlrpc' => $this->conclude( $local, $http, true, $reason ) );
	}
	// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

	/**
	 * Sends an unauthenticated system.listMethods call to xmlrpc.php.
	 *
	 * @param Http_Probe $probe Probe.
	 * @param string     $mode  block | allow.
	 * @param array      $http  Collector for check results.
	 * @return string Why no check ran, or ''.
	 */
	private function probe_http( Http_Probe $probe, $mode, array &$http ) {
		$preflight = $probe->preflight();
		if ( ! $preflight['ok'] ) {
			/* translators: %s: error code. */
			return sprintf( __( 'HTTP probe unavailable (%s).', 'wp-security-lockdown' ), $preflight['error'] );
		}

		$response = $probe->request(
			'POST',
			site_url( 'xmlrpc.php' ),
			array(
				'headers' => array( 'Content-Type' => 'text/xml' ),
				'body'    => '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>',
			)
		);
		if ( ! $response['ok'] ) {
			return $response['error'];
		}

		$answered = false !== strpos( $response['body'], '<methodResponse>' );
		if ( 'block' === $mode ) {
			$http[] = array(
				403 === $response['code'] && ! $answered,
				sprintf( 'POST xmlrpc.php answered HTTP %d and %s an XML-RPC response (HTTP 403 without a response expected)', $response['code'], $answered ? 'returned' : 'did not return' ),
			);
		} else {
			$listed = false !== strpos( $response['body'], 'pingback.ping' );
			$http[] = array(
				$answered && ! $listed,
				sprintf( 'system.listMethods answered HTTP %d; pingback.ping %s in the method list', $response['code'], $listed ? 'IS LISTED' : 'is not listed' ),
			);
		}
		return '';
	}
}
