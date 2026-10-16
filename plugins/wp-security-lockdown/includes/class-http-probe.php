<?php
/**
 * Loopback HTTP probes used to verify controls from the outside.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Sends a small, bounded number of HTTP requests to THIS site to check how it really responds.
 *
 * Guardrails:
 *  - Only URLs on the site's own host (home_url / site_url / admin_url) are requested.
 *  - A total time budget and a request cap bound the work done by one verification run.
 *  - A preflight request runs first; if loopback is unavailable every later probe is skipped
 *    instead of waiting for N timeouts, and callers report "unverified", never "verified".
 *  - Redirects are never followed. Response bodies are size-capped.
 *  - A forwarded login session (for the authenticated REST probe) is sent only to this site and is
 *    never returned to callers or logged.
 */
class Http_Probe {

	const MAX_REQUESTS = 40;
	const MAX_BODY     = 262144;

	/**
	 * Time (microtime) after which no new request starts.
	 *
	 * @var float Unix time (microseconds) after which no new request starts.
	 */
	private $deadline;

	/**
	 * Number of requests sent so far.
	 *
	 * @var int
	 */
	private $count = 0;

	/**
	 * Result of the preflight request, once it has run.
	 *
	 * @var array|null Result of the preflight, once run.
	 */
	private $preflight = null;

	/**
	 * Cookies and nonce for authenticated probes, once attached.
	 *
	 * @var array|null array( cookies => WP_Http_Cookie[], nonce => string ) for authenticated probes.
	 */
	private $session = null;

	/**
	 * Memoized GET responses by URL.
	 *
	 * @var array Memoized GET responses by URL.
	 */
	private $memo = array();

	/**
	 * Creates a probe with a total time budget.
	 *
	 * @param float $budget_seconds Total time this probe object may spend.
	 */
	public function __construct( $budget_seconds = 25.0 ) {
		$this->deadline = microtime( true ) + max( 1.0, (float) $budget_seconds );
	}

	/**
	 * Attaches the current administrator's session so REST can be probed as that user.
	 *
	 * Requires an interactive, logged-in request by someone who can manage options. Without it
	 * (cron, CLI) the authenticated probes are simply skipped.
	 *
	 * @return bool Whether a session was attached.
	 */
	public function attach_current_session() {
		if ( ! is_user_logged_in() || ! current_user_can( 'manage_options' ) || ! defined( 'LOGGED_IN_COOKIE' ) ) {
			return false;
		}
		if ( empty( $_COOKIE[ LOGGED_IN_COOKIE ] ) || ! is_string( $_COOKIE[ LOGGED_IN_COOKIE ] ) ) {
			return false;
		}

		$this->session = array(
			'cookies' => array(
				new \WP_Http_Cookie(
					array(
						'name'  => LOGGED_IN_COOKIE,
						'value' => wp_unslash( $_COOKIE[ LOGGED_IN_COOKIE ] ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- opaque session token forwarded verbatim to this site only.
					)
				),
			),
			'nonce'   => wp_create_nonce( 'wp_rest' ),
		);
		return true;
	}

	/**
	 * Whether an authenticated session is attached.
	 *
	 * @return bool Whether an authenticated session is attached.
	 */
	public function has_session() {
		return null !== $this->session;
	}

	/**
	 * How many requests this probe has sent so far.
	 *
	 * @return int
	 */
	public function requests_made() {
		return $this->count;
	}

	/**
	 * Seconds left in the budget.
	 *
	 * @return float
	 */
	public function remaining() {
		return max( 0.0, $this->deadline - microtime( true ) );
	}

	/**
	 * Verifies once that the site can reach itself over HTTP.
	 *
	 * @return array array( ok => bool, error => string ).
	 */
	public function preflight() {
		if ( null === $this->preflight ) {
			$response        = $this->send( 'GET', home_url( '/' ), array( 'timeout' => 6 ) );
			$this->preflight = array(
				'ok'    => $response['ok'],
				'error' => $response['ok'] ? '' : $response['error'],
			);
			if ( $response['ok'] ) {
				$this->memo[ home_url( '/' ) ] = $response;
				// The front page is needed by several checks: fetch it once.
			}
		}
		return $this->preflight;
	}

	/**
	 * Sends a request after the preflight succeeded.
	 *
	 * @param string $method HTTP method.
	 * @param string $url    URL on this site.
	 * @param array  $args   Optional: headers, body, timeout, authenticated (bool).
	 * @return array array( ok, code, headers (lower-case keys), body, error ).
	 */
	public function request( $method, $url, array $args = array() ) {
		$preflight = $this->preflight();
		if ( ! $preflight['ok'] ) {
			return $this->failure( 'loopback_unavailable: ' . $preflight['error'] );
		}

		$method = strtoupper( $method );
		if ( 'GET' === $method && empty( $args ) && isset( $this->memo[ $url ] ) ) {
			return $this->memo[ $url ];
		}

		$response = $this->send( $method, $url, $args );
		if ( 'GET' === $method && empty( $args ) ) {
			$this->memo[ $url ] = $response;
		}
		return $response;
	}

	/**
	 * Low-level send with all guardrails applied.
	 *
	 * @param string $method HTTP method.
	 * @param string $url    URL.
	 * @param array  $args   Options.
	 * @return array
	 */
	private function send( $method, $url, array $args ) {
		if ( $this->count >= self::MAX_REQUESTS ) {
			return $this->failure( 'request_cap_reached' );
		}
		if ( ! $this->is_same_site( $url ) ) {
			return $this->failure( 'url_not_on_this_site' );
		}
		$left = $this->remaining();
		if ( $left < 1.0 ) {
			return $this->failure( 'time_budget_exceeded' );
		}

		$timeout = isset( $args['timeout'] ) ? (float) $args['timeout'] : 8.0;
		$request = array(
			'method'              => $method,
			'timeout'             => max( 1.0, min( $timeout, $left ) ),
			'redirection'         => 0,
			'sslverify'           => (bool) apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- core hook: same TLS policy as WordPress's own loopback requests.
			'user-agent'          => 'WP-Security-Lockdown-Probe/' . WP_SECURITY_LOCKDOWN_VERSION,
			'headers'             => isset( $args['headers'] ) && is_array( $args['headers'] ) ? $args['headers'] : array(),
			'limit_response_size' => self::MAX_BODY,
			'reject_unsafe_urls'  => false,
		);
		if ( isset( $args['body'] ) ) {
			$request['body'] = $args['body'];
		}
		if ( ! empty( $args['authenticated'] ) ) {
			if ( null === $this->session ) {
				return $this->failure( 'no_authenticated_session' );
			}
			$request['cookies']               = $this->session['cookies'];
			$request['headers']['X-WP-Nonce'] = $this->session['nonce'];
		}

		++$this->count;
		$raw = wp_remote_request( $url, $request );
		if ( is_wp_error( $raw ) ) {
			return $this->failure( substr( $raw->get_error_code() . ': ' . $raw->get_error_message(), 0, 200 ) );
		}

		$headers = array();
		foreach ( wp_remote_retrieve_headers( $raw ) as $name => $value ) {
			$headers[ strtolower( (string) $name ) ] = is_array( $value ) ? implode( ', ', $value ) : (string) $value;
		}
		return array(
			'ok'      => true,
			'code'    => (int) wp_remote_retrieve_response_code( $raw ),
			'headers' => $headers,
			'body'    => substr( (string) wp_remote_retrieve_body( $raw ), 0, self::MAX_BODY ),
			'error'   => '',
		);
	}

	/**
	 * Whether a URL points at this site's own host.
	 *
	 * @param string $url URL.
	 * @return bool
	 */
	private function is_same_site( $url ) {
		$target = wp_parse_url( $url );
		if ( empty( $target['host'] ) || empty( $target['scheme'] ) || ! in_array( $target['scheme'], array( 'http', 'https' ), true ) ) {
			return false;
		}
		foreach ( array( home_url(), site_url(), admin_url() ) as $own ) {
			$parts = wp_parse_url( $own );
			if ( ! empty( $parts['host'] ) && 0 === strcasecmp( $parts['host'], $target['host'] ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Builds the result of a request that was not made or failed.
	 *
	 * @param string $reason Why the request did not happen.
	 * @return array
	 */
	private function failure( $reason ) {
		return array(
			'ok'      => false,
			'code'    => 0,
			'headers' => array(),
			'body'    => '',
			'error'   => $reason,
		);
	}
}
