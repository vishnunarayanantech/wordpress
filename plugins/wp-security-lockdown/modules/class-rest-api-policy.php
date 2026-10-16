<?php
/**
 * REST API access policy.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;

defined( 'ABSPATH' ) || exit;

/**
 * Control `rest_api`.
 *
 * Modes
 *  - off ............ the plugin does not touch the REST API.
 *  - restricted ..... (default) anonymous requests get HTTP 401 unless the route is inside an
 *                     administrator-allowlisted namespace. Authenticated requests are NOT given any
 *                     extra access and NOT blocked: every endpoint's own permission_callback still
 *                     decides, so a subscriber still cannot read /settings and an editor still can
 *                     edit posts. wp-admin, the block editor and Site Health keep working because
 *                     they call the API with a logged-in cookie + nonce.
 *  - dashboard_only . "Full shutdown" (potentially breaking). The API is available ONLY to the
 *                     wp-admin UI itself: cookie + nonce authenticated sessions, on the core admin
 *                     namespaces (plus ones you list). Anonymous visitors, application-password /
 *                     Basic-auth / token clients, and third-party namespaces are all refused.
 *                     A literal "REST off for everyone" is deliberately not offered: the block
 *                     editor, site editor, Site Health and profile screens cannot work without it.
 *
 * Why priority 110 on `rest_authentication_errors`: core checks application passwords at 90 and the
 * cookie + nonce at 100 (a cookie WITHOUT a valid nonce is demoted to anonymous there). Running
 * afterwards means this policy sees the final authentication state, and an existing WP_Error from
 * those checks (for example a bad nonce) is always passed through untouched.
 */
class Rest_Api_Policy extends Abstract_Module {

	/** Core namespaces wp-admin calls with a cookie + nonce. */
	const DASHBOARD_NAMESPACES = array( 'wp/v2', 'wp-site-health/v1', 'wp-block-editor/v1', 'wp-abilities/v1', 'oembed/1.0' );

	/** Routes that belong to the server itself and are used by the editor (index, batching). */
	const DASHBOARD_ROUTES = array( '/', '/batch/v1' );

	/** Known plugins that call the REST API without a logged-in user. */
	const COMPAT_PLUGINS = array(
		'woocommerce/woocommerce.php'          => 'WooCommerce: block-based Cart/Checkout call the Store API (namespace wc/store/v1) as guest shoppers. Add "wc/store/v1" to the public namespaces if you use it.',
		'contact-form-7/wp-contact-form-7.php' => 'Contact Form 7 submits forms anonymously to the namespace contact-form-7/v1. Add it to the public namespaces or forms will fail.',
		'jetpack/jetpack.php'                  => 'Jetpack and WordPress.com call REST endpoints (jetpack/v4 and others) with their own signed authentication. Test the Jetpack connection after enabling this policy.',
		'gravityforms/gravityforms.php'        => 'Gravity Forms can submit forms through the namespace gf/v2.',
		'mailpoet/mailpoet.php'                => 'MailPoet subscription forms may call its REST namespace anonymously.',
	);

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'rest_api_policy';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'rest_api' => array(
				'title'       => __( 'REST API access policy', 'wp-security-lockdown' ),
				'description' => __( 'Refuses anonymous REST requests (HTTP 401) except for namespaces you explicitly allow. Logged-in requests keep working under each endpoint\'s own permission rules.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Registers the policy filter unless the mode is off.
	 *
	 * @return void
	 */
	public function register() {
		if ( 'off' === $this->mode() ) {
			return;
		}
		add_filter( 'rest_authentication_errors', array( $this, 'enforce' ), 110 );
	}

	/**
	 * Returns the configured mode.
	 *
	 * @return string off | restricted | dashboard_only.
	 */
	public function mode() {
		$mode = $this->plugin->settings()->get( 'rest.mode', 'restricted' );
		return in_array( $mode, array( 'off', 'restricted', 'dashboard_only' ), true ) ? $mode : 'restricted';
	}

	/**
	 * `rest_authentication_errors` callback.
	 *
	 * @param \WP_Error|null|true $result Result of earlier authentication filters.
	 * @return \WP_Error|null|true
	 */
	public function enforce( $result ) {
		if ( is_wp_error( $result ) ) {
			return $result;
			// Never mask a genuine authentication failure (bad nonce, bad app password...).
		}

		$decision = $this->decide( $this->current_route(), $this->auth_context() );
		if ( $decision['allow'] ) {
			return $result;
		}
		return new \WP_Error( $decision['code'], $decision['message'], array( 'status' => $decision['status'] ) );
	}

	/**
	 * Pure policy decision.
	 *
	 * @param string $route Normalized route, e.g. "/wp/v2/users".
	 * @param array  $ctx   array( user_id => int, cookie => bool, app_password => bool ).
	 * @return array array( allow => bool, code, message, status ) — code/message/status only when denied.
	 */
	public function decide( $route, array $ctx ) {
		$allow = array(
			'allow'   => true,
			'code'    => '',
			'message' => '',
			'status'  => 200,
		);
		$mode  = $this->mode();
		if ( 'off' === $mode ) {
			return $allow;
		}

		$route = self::normalize_route( $route );
		if ( empty( $ctx['user_id'] ) ) {
			if ( self::route_in_namespaces( $route, (array) $this->plugin->settings()->get( 'rest.public_namespaces', array() ) ) && 'dashboard_only' !== $mode ) {
				return $allow;
			}
			return array(
				'allow'   => false,
				'code'    => 'rest_not_logged_in',
				'message' => __( 'The REST API requires you to be logged in on this site.', 'wp-security-lockdown' ),
				'status'  => 401,
			);
		}

		if ( 'dashboard_only' === $mode ) {
			$uses_cookie = ! empty( $ctx['cookie'] ) && empty( $ctx['app_password'] );
			$extra       = (array) $this->plugin->settings()->get( 'rest.dashboard_namespaces', array() );
			$permitted   = in_array( $route, self::DASHBOARD_ROUTES, true )
				|| self::route_in_namespaces( $route, self::DASHBOARD_NAMESPACES )
				|| self::route_in_namespaces( $route, $extra );

			if ( ! $uses_cookie || ! $permitted ) {
				return array(
					'allow'   => false,
					'code'    => 'rest_forbidden',
					'message' => __( 'The REST API is restricted to the WordPress dashboard on this site.', 'wp-security-lockdown' ),
					'status'  => 403,
				);
			}
		}
		return $allow;
	}

	/**
	 * Lower-cases, adds the leading slash and removes the trailing slash, mirroring how core matches routes.
	 * Consecutive slashes are deliberately NOT collapsed: core would not match such a route either.
	 *
	 * @param string $route Raw route.
	 * @return string
	 */
	public static function normalize_route( $route ) {
		$route = strtolower( (string) $route );
		$route = '/' . trim( $route, '/' );
		return $route;
	}

	/**
	 * Whether a route lies inside any of the namespaces (namespace boundary aware: "wc/store/v1" does not match "wc/store/v10").
	 *
	 * @param string   $route      Normalized route.
	 * @param string[] $namespaces Namespaces without leading slash.
	 * @return bool
	 */
	public static function route_in_namespaces( $route, array $namespaces ) {
		// No real route contains dot segments, doubled slashes, backslashes or control characters. Refusing them means the
		// allowlist never depends on how a later layer would interpret such a string.
		if ( 1 === preg_match( '#(^|/)\.\.?(/|$)|//|\\\\|[\x00-\x1F\x7F]#', $route ) ) {
			return false;
		}
		foreach ( $namespaces as $namespace ) {
			$prefix = '/' . strtolower( trim( (string) $namespace, '/' ) );
			if ( '/' === $prefix ) {
				continue;
			}
			if ( $route === $prefix || 0 === strpos( $route, $prefix . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The route core is about to dispatch (same derivation as rest_api_loaded()).
	 *
	 * @return string Normalized route; "/" when it cannot be determined.
	 */
	protected function current_route() {
		$route = '';
		if ( isset( $GLOBALS['wp'] ) && $GLOBALS['wp'] instanceof \WP && isset( $GLOBALS['wp']->query_vars['rest_route'] ) && is_string( $GLOBALS['wp']->query_vars['rest_route'] ) ) {
			$route = $GLOBALS['wp']->query_vars['rest_route'];
		}
		return self::normalize_route( $route );
	}

	/**
	 * How the current request authenticated.
	 *
	 * @return array array( user_id, cookie, app_password ).
	 */
	protected function auth_context() {
		return array(
			'user_id'      => get_current_user_id(),
			// Set by core when the logged-in cookie was accepted; the nonce was verified at priority 100.
			'cookie'       => isset( $GLOBALS['wp_rest_auth_cookie'] ) && true === $GLOBALS['wp_rest_auth_cookie'],
			'app_password' => function_exists( 'rest_get_authenticated_app_password' ) && null !== rest_get_authenticated_app_password(),
		);
	}

	/**
	 * Control id => report (the shape Policy_Manager expects).
	 *
	 * @return array
	 */
	public function report() {
		return array( 'rest_api' => $this->build_report() );
	}

	/**
	 * Builds the report of this module's single control.
	 *
	 * @return array
	 */
	private function build_report() {
		$mode   = $this->mode();
		$report = $this->make_report(
			'rest_api',
			array(
				'enabled'     => 'off' !== $mode,
				'desired'     => $this->desired_text( $mode ),
				'enforcement' => array( __( 'Filter rest_authentication_errors at priority 110 (after core\'s application-password and cookie/nonce checks). Stops when the plugin is deactivated.', 'wp-security-lockdown' ) ),
				'persists'    => '',
			)
		);

		if ( 'off' === $mode ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}

		if ( 'dashboard_only' === $mode ) {
			$report['warnings'][] = __( 'POTENTIALLY BREAKING: in this mode application-password and token clients, mobile apps, headless front ends, WooCommerce / Jetpack REST integrations and third-party admin screens that use their own REST namespace are refused. Only the core dashboard, block editor, site editor and Site Health keep working.', 'wp-security-lockdown' );
		}
		if ( ! function_exists( 'wp_is_application_passwords_available' ) || ! wp_is_application_passwords_available() ) {
			$report['warnings'][] = __( 'Application Passwords are not available on this site (WordPress only offers them over HTTPS or in local environments), so scripts and apps cannot authenticate to the REST API at all.', 'wp-security-lockdown' );
		}
		foreach ( self::COMPAT_PLUGINS as $file => $note ) {
			if ( in_array( $file, (array) get_option( 'active_plugins', array() ), true ) ) {
				$report['warnings'][] = $note;
			}
		}

		$third_party = $this->third_party_namespaces();
		if ( $third_party ) {
			$report['warnings'][] = sprintf(
				/* translators: %s: comma separated REST namespaces. */
				__( 'Third-party REST namespaces are registered on this site: %s. Anonymous access to them is refused; allowlist a namespace only if it is meant to be public.', 'wp-security-lockdown' ),
				implode( ', ', $third_party )
			);
		}

		$attached            = $this->hooked( 'rest_authentication_errors', array( $this, 'enforce' ) );
		$report['details'][] = array(
			'label'  => 'rest_authentication_errors',
			'status' => $attached ? 'ok' : 'fail',
			'text'   => $attached ? __( 'Filter is attached.', 'wp-security-lockdown' ) : __( 'Filter is NOT attached.', 'wp-security-lockdown' ),
		);
		if ( $attached ) {
			$report['state'] = self::STATE_ENFORCED;
		} else {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = __( 'The REST policy filter is not attached in this request.', 'wp-security-lockdown' );
		}
		return $report;
	}

	/**
	 * Verifies the policy; a verified verdict requires real HTTP requests.
	 *
	 * @param Http_Probe|null $probe Probe or null.
	 * @return array
	 */
	public function verify( ?Http_Probe $probe = null ) {
		$mode = $this->mode();
		if ( 'off' === $mode ) {
			return array();
		}

		// Logic checks on the pure decision function (wiring is checked by the HTTP requests below).
		$anon   = array(
			'user_id'      => 0,
			'cookie'       => false,
			'app_password' => false,
		);
		$cookie = array(
			'user_id'      => 1,
			'cookie'       => true,
			'app_password' => false,
		);
		$local  = array(
			array( ! $this->decide( '/wp/v2/users', $anon )['allow'], 'anonymous /wp/v2/users is denied' ),
			array( ! $this->decide( '/', $anon )['allow'], 'anonymous REST index is denied' ),
			array( ! $this->decide( '/batch/v1', $anon )['allow'], 'anonymous batch endpoint is denied' ),
			array( $this->decide( '/wp/v2/types/post', $cookie )['allow'], 'a logged-in dashboard session is allowed through to the endpoint\'s own checks' ),
			array( $this->hooked( 'rest_authentication_errors', array( $this, 'enforce' ) ), 'policy filter is attached' ),
		);

		$http   = array();
		$reason = __( 'Run verification to send real anonymous and authenticated requests.', 'wp-security-lockdown' );
		if ( $probe ) {
			$reason = $this->probe_http( $probe, $http );
		}
		$result = $this->conclude( $local, $http, true, $reason );
		if ( $probe && self::VERIFIED === $result['status'] && ! $probe->has_session() ) {
			$result['detail'] .= '. ' . __( 'Logged-in dashboard requests were NOT tested in this run (it needs an interactive administrator session): use the button on the dashboard to include them.', 'wp-security-lockdown' );
		}
		return array( 'rest_api' => $result );
	}

	/**
	 * Real requests: anonymous must be refused; an authenticated dashboard session must still work.
	 *
	 * @param Http_Probe $probe Probe.
	 * @param array      $http  Collector for check results.
	 * @return string Why no check ran, or ''.
	 */
	private function probe_http( Http_Probe $probe, array &$http ) {
		$preflight = $probe->preflight();
		if ( ! $preflight['ok'] ) {
			/* translators: %s: error code. */
			return sprintf( __( 'HTTP probe unavailable (%s).', 'wp-security-lockdown' ), $preflight['error'] );
		}

		$anonymous = array(
			'GET /wp/v2/users' => array( 'GET', '/wp/v2/users' ),
			'GET / (index)'    => array( 'GET', '/' ),
			'POST /batch/v1'   => array( 'POST', '/batch/v1' ),
		);
		foreach ( $anonymous as $label => $request ) {
			$args     = 'POST' === $request[0] ? array(
				'headers' => array( 'Content-Type' => 'application/json' ),
				'body'    => '{"requests":[]}',
			) : array();
			$response = $probe->request( $request[0], add_query_arg( 'rest_route', $request[1], home_url( '/' ) ), $args );
			if ( $response['ok'] ) {
				$http[] = array(
					in_array( $response['code'], array( 401, 403 ), true ),
					sprintf( 'Anonymous %s answered HTTP %d (401 expected)', $label, $response['code'] ),
				);
			}
		}

		if ( $probe->has_session() ) {
			foreach ( array( '/wp/v2/users/me', '/wp/v2/types/post' ) as $route ) {
				$response = $probe->request(
					'GET',
					add_query_arg(
						array(
							'rest_route' => $route,
							'context'    => 'edit',
						),
						home_url( '/' )
					),
					array( 'authenticated' => true )
				);
				if ( $response['ok'] ) {
					$http[] = array(
						200 === $response['code'],
						sprintf( 'Logged-in dashboard request GET %s answered HTTP %d (200 expected)', $route, $response['code'] ),
					);
				}
			}
		}//end if
		return $http ? '' : __( 'The HTTP requests could not be completed.', 'wp-security-lockdown' );
	}

	/**
	 * Registered REST namespaces that do not belong to core, for the compatibility warning.
	 *
	 * @return string[]
	 */
	private function third_party_namespaces() {
		if ( ! function_exists( 'rest_get_server' ) ) {
			return array();
		}
		$public = (array) $this->plugin->settings()->get( 'rest.public_namespaces', array() );
		$core   = array_merge( self::DASHBOARD_NAMESPACES, array( 'batch/v1' ) );
		$found  = array();
		foreach ( rest_get_server()->get_namespaces() as $namespace ) {
			if ( ! in_array( $namespace, $core, true ) && ! in_array( $namespace, $public, true ) ) {
				$found[] = $namespace;
			}
		}
		return array_slice( $found, 0, 12 );
	}

	/**
	 * Describes the desired policy of a mode in plain language.
	 *
	 * @param string $mode Mode.
	 * @return string
	 */
	private function desired_text( $mode ) {
		switch ( $mode ) {
			case 'dashboard_only':
				return __( 'REST is usable only by the wp-admin UI (cookie + nonce) on core admin namespaces. Everything else gets 401 / 403.', 'wp-security-lockdown' );
			case 'restricted':
				return __( 'Anonymous REST requests get HTTP 401 (except allowlisted namespaces). Logged-in requests are unaffected and still subject to each endpoint\'s own permission checks.', 'wp-security-lockdown' );
			default:
				return __( 'The plugin does not restrict the REST API.', 'wp-security-lockdown' );
		}
	}
}
