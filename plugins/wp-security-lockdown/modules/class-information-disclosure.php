<?php
/**
 * Information disclosure controls.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Modules;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;

defined( 'ABSPATH' ) || exit;

/**
 * Controls: `author_enumeration`, `version_exposure`, `discovery`, `error_display`, `login_errors`.
 *
 * Honest scope: hiding the WordPress version or the discovery links does NOT prevent exploitation
 * of a vulnerable site; patching and access control do. These controls only stop handing out free
 * reconnaissance (valid login names, exact versions, a map of endpoints, PHP errors with paths).
 */
class Information_Disclosure extends Abstract_Module {

	/** Error codes that reveal whether an account exists. */
	const ENUMERATION_CODES = array( 'invalid_username', 'invalid_email', 'incorrect_password' );

	/**
	 * Returns the module slug.
	 *
	 * @return string
	 */
	public function slug() {
		return 'information_disclosure';
	}

	/**
	 * Returns the control definitions.
	 *
	 * @return array
	 */
	public function controls() {
		return array(
			'author_enumeration' => array(
				'title'       => __( 'Author / user enumeration', 'wp-security-lockdown' ),
				'description' => __( 'Stops anonymous visitors from discovering login names through ?author=N, the users sitemap and the REST users routes.', 'wp-security-lockdown' ),
			),
			'login_errors'       => array(
				'title'       => __( 'Generic login errors', 'wp-security-lockdown' ),
				'description' => __( 'Shows the same message whether the user name exists or not, on the login form and for REST Basic-auth failures.', 'wp-security-lockdown' ),
			),
			'version_exposure'   => array(
				'title'       => __( 'WordPress version exposure', 'wp-security-lockdown' ),
				'description' => __( 'Removes the generator tag and the version number from script / style URLs. This is hygiene, not protection: patching is what stops exploits.', 'wp-security-lockdown' ),
			),
			'discovery'          => array(
				'title'       => __( 'Discovery links and headers', 'wp-security-lockdown' ),
				'description' => __( 'Stops advertising the REST API, oEmbed and shortlink endpoints in page heads and headers. This removes the advertisement only; access control is provided by the REST policy.', 'wp-security-lockdown' ),
			),
			'error_display'      => array(
				'title'       => __( 'Public PHP error display', 'wp-security-lockdown' ),
				'description' => __( 'Turns off display_errors for visitors so file paths and stack traces are not printed on pages.', 'wp-security-lockdown' ),
			),
		);
	}

	/**
	 * Registers the hooks of the controls that are switched on.
	 *
	 * @return void
	 */
	public function register() {
		$s = $this->plugin->settings();

		if ( $s->control_enabled( 'author_enumeration' ) ) {
			add_action( 'template_redirect', array( $this, 'block_author_query' ), 0 );
			add_filter( 'wp_sitemaps_add_provider', array( $this, 'filter_sitemap_provider' ), 10, 2 );
			add_filter( 'rest_endpoints', array( $this, 'filter_rest_endpoints' ) );
		}

		if ( $s->control_enabled( 'version_exposure' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string', 99 );
			add_filter( 'script_loader_src', array( $this, 'mask_version' ), 20 );
			add_filter( 'style_loader_src', array( $this, 'mask_version' ), 20 );
		}

		if ( $s->control_enabled( 'discovery' ) ) {
			remove_action( 'wp_head', 'rest_output_link_wp_head', 10 );
			remove_action( 'template_redirect', 'rest_output_link_header', 11 );
			remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 4 );
			remove_action( 'wp_head', 'wp_oembed_add_discovery_links', 10 );
			remove_action( 'wp_head', 'wp_shortlink_wp_head', 10 );
			remove_action( 'template_redirect', 'wp_shortlink_header', 11 );
		}

		if ( $s->control_enabled( 'error_display' ) ) {
			$this->suppress_error_display();
		}

		if ( $s->control_enabled( 'login_errors' ) ) {
			add_filter( 'wp_login_errors', array( $this, 'generic_login_errors' ), 99 );
			add_filter( 'rest_authentication_errors', array( $this, 'generic_rest_auth_error' ), 95 );
		}
	}

	/* --------------------------------------------------------------------- author enumeration */

	/**
	 * `template_redirect` at priority 0 (before redirect_canonical turns ?author=N into /author/login/).
	 *
	 * Plain permalinks are left alone: there `?author=N` IS the canonical author URL.
	 *
	 * @return void
	 */
	public function block_author_query() {
		if ( is_user_logged_in() || ! isset( $_GET['author'] ) || '' === (string) get_option( 'permalink_structure' ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only routing decision, no state change.
			return;
		}
		$value = wp_unslash( $_GET['author'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- only tested for emptiness.
		if ( ! is_array( $value ) && '' === trim( (string) $value ) ) {
			return;
		}

		global $wp_query;
		$wp_query->set_404();
		status_header( 404 );
		nocache_headers();
	}

	/**
	 * `wp_sitemaps_add_provider`: the users sitemap lists every author's archive URL.
	 *
	 * @param \WP_Sitemaps_Provider|false $provider Provider.
	 * @param string                      $name     Provider name.
	 * @return \WP_Sitemaps_Provider|false
	 */
	public function filter_sitemap_provider( $provider, $name = '' ) {
		return 'users' === $name ? false : $provider;
	}

	/**
	 * `rest_endpoints`: for anonymous requests the users collection / item routes do not exist.
	 *
	 * @param array $endpoints Registered routes.
	 * @return array
	 */
	public function filter_rest_endpoints( $endpoints ) {
		if ( is_user_logged_in() ) {
			return $endpoints;
		}
		return $this->strip_user_routes( $endpoints );
	}

	/**
	 * Removes the users routes from a route table.
	 *
	 * @param array $endpoints Routes.
	 * @return array
	 */
	public function strip_user_routes( $endpoints ) {
		if ( ! is_array( $endpoints ) ) {
			return $endpoints;
		}
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( (string) $route, '/wp/v2/users' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/* --------------------------------------------------------------------- version exposure */

	/**
	 * `script_loader_src` / `style_loader_src`: replaces `ver=<WordPress version>` with a keyed hash of it.
	 * The value still changes whenever WordPress is updated, so browser caches are busted as before.
	 *
	 * @param string $src Asset URL.
	 * @return string
	 */
	public function mask_version( $src ) {
		global $wp_version;
		if ( ! is_string( $src ) || false === strpos( $src, 'ver=' ) ) {
			return $src;
		}
		$query = wp_parse_url( $src, PHP_URL_QUERY );
		if ( ! is_string( $query ) ) {
			return $src;
		}
		parse_str( $query, $args );
		if ( isset( $args['ver'] ) && (string) $args['ver'] === (string) $wp_version ) {
			return add_query_arg( 'ver', $this->masked_version(), $src );
		}
		return $src;
	}

	/**
	 * Returns a keyed hash of the WordPress version.
	 *
	 * @return string
	 */
	private function masked_version() {
		global $wp_version;
		return substr( hash_hmac( 'sha256', (string) $wp_version, wp_salt( 'nonce' ) ), 0, 10 );
	}

	/* --------------------------------------------------------------------- error display */

	/**
	 * Whether PHP currently prints errors into the response.
	 *
	 * @return bool
	 */
	public static function display_errors_on() {
		$value = strtolower( trim( (string) ini_get( 'display_errors' ) ) );
		return ! in_array( $value, array( '', '0', 'off', 'false', 'no', 'stderr' ), true );
	}

	/**
	 * Whether the environment is one where developers expect errors on screen.
	 *
	 * @return bool
	 */
	private function is_developer_environment() {
		return in_array( $this->environment_type(), array( 'local', 'development' ), true );
	}

	/**
	 * The WordPress environment type. Separate so tests can vary it (core caches it for the whole process).
	 *
	 * @return string
	 */
	protected function environment_type() {
		return function_exists( 'wp_get_environment_type' ) ? wp_get_environment_type() : 'production';
	}

	/**
	 * Turns display_errors off at runtime. Effective only for code that runs after this plugin loaded.
	 *
	 * @return void
	 */
	private function suppress_error_display() {
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || $this->is_developer_environment() ) {
			return;
		}
		if ( self::display_errors_on() ) {
			@ini_set( 'display_errors', '0' ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Disallowed, WordPress.PHP.NoSilencedErrors.Discouraged -- the point of this control; ini_set may be disabled by the host.
		}
	}

	/* --------------------------------------------------------------------- login errors */

	/**
	 * `wp_login_errors`: replaces "unknown user" / "wrong password" with one message.
	 *
	 * The code `incorrect_password` is kept so the login form still pre-fills what the visitor typed.
	 * Other plugins that listen to `wp_login_failed` still receive the original, detailed error.
	 *
	 * @param \WP_Error $errors Errors shown above the login form.
	 * @return \WP_Error
	 */
	public function generic_login_errors( $errors ) {
		if ( ! $errors instanceof \WP_Error || ! array_intersect( $errors->get_error_codes(), self::ENUMERATION_CODES ) ) {
			return $errors;
		}

		$clean = new \WP_Error();
		foreach ( $errors->get_error_codes() as $code ) {
			if ( in_array( $code, self::ENUMERATION_CODES, true ) ) {
				continue;
			}
			foreach ( $errors->get_error_messages( $code ) as $message ) {
				$clean->add( $code, $message, $errors->get_error_data( $code ) );
			}
		}
		$clean->add( 'incorrect_password', __( '<strong>Error:</strong> Invalid username, email address or incorrect password.', 'wp-security-lockdown' ) );
		return $clean;
	}

	/**
	 * `rest_authentication_errors` at priority 95: Basic-auth / application-password failures name
	 * the problem ("unknown user" vs "wrong password"). Report both the same way.
	 *
	 * @param \WP_Error|null|true $result Result so far.
	 * @return \WP_Error|null|true
	 */
	public function generic_rest_auth_error( $result ) {
		if ( is_wp_error( $result ) && array_intersect( $result->get_error_codes(), self::ENUMERATION_CODES ) ) {
			return new \WP_Error( 'incorrect_password', __( 'Invalid username, email address or incorrect password.', 'wp-security-lockdown' ), array( 'status' => 401 ) );
		}
		return $result;
	}

	/* --------------------------------------------------------------------- reporting */

	/**
	 * Reports every control of this module.
	 *
	 * @return array
	 */
	public function report() {
		return array(
			'author_enumeration' => $this->report_author_enumeration(),
			'login_errors'       => $this->report_login_errors(),
			'version_exposure'   => $this->report_version_exposure(),
			'discovery'          => $this->report_discovery(),
			'error_display'      => $this->report_error_display(),
		);
	}

	/**
	 * Marks a report enforced/failed depending on whether every listed hook is attached.
	 *
	 * @param array $report Report.
	 * @param array $checks Hook name => callback (or removed-action marker array).
	 * @return array
	 */
	private function judge_hooks( array $report, array $checks ) {
		$missing = array();
		foreach ( $checks as $label => $ok ) {
			$report['details'][] = array(
				'label'  => $label,
				'status' => $ok ? 'ok' : 'fail',
				'text'   => $ok ? __( 'In place.', 'wp-security-lockdown' ) : __( 'NOT in place in this request.', 'wp-security-lockdown' ),
			);
			if ( ! $ok ) {
				$missing[] = $label;
			}
		}
		if ( $missing ) {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = sprintf(
				/* translators: %s: comma separated hook names. */
				__( 'Not enforced in this request: %s.', 'wp-security-lockdown' ),
				implode( ', ', $missing )
			);
		} else {
			$report['state'] = self::STATE_ENFORCED;
		}
		return $report;
	}

	/**
	 * Reports the author enumeration control.
	 *
	 * @return array
	 */
	private function report_author_enumeration() {
		$report               = $this->make_report(
			'author_enumeration',
			array(
				'desired'     => __( 'Anonymous ?author=N answers 404 instead of redirecting to /author/<login>/; no users sitemap; no anonymous /wp/v2/users routes.', 'wp-security-lockdown' ),
				'enforcement' => array( __( 'Runtime: template_redirect (priority 0), wp_sitemaps_add_provider, rest_endpoints. Stops on deactivation.', 'wp-security-lockdown' ) ),
			)
		);
		$report['warnings'][] = __( 'Author archives (/author/<name>/) stay public by design, and a user\'s slug equals their login name unless you change the "nicename". Change it if the login must not be public.', 'wp-security-lockdown' );
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}

		$report = $this->judge_hooks(
			$report,
			array(
				'template_redirect'        => $this->hooked( 'template_redirect', array( $this, 'block_author_query' ) ),
				'wp_sitemaps_add_provider' => $this->hooked( 'wp_sitemaps_add_provider', array( $this, 'filter_sitemap_provider' ) ),
				'rest_endpoints'           => $this->hooked( 'rest_endpoints', array( $this, 'filter_rest_endpoints' ) ),
			)
		);
		if ( self::STATE_ENFORCED === $report['state'] && '' === (string) get_option( 'permalink_structure' ) ) {
			$report['state']          = self::STATE_PARTIAL;
			$report['failure_reason'] = __( 'Plain permalinks are in use, where ?author=N is the canonical author URL, so it cannot be blocked. The users sitemap and REST routes are still protected. Enable pretty permalinks to block ?author=N.', 'wp-security-lockdown' );
		}
		return $report;
	}

	/**
	 * Reports the generic login errors control.
	 *
	 * @return array
	 */
	private function report_login_errors() {
		$report               = $this->make_report(
			'login_errors',
			array(
				'desired'     => __( 'The login form and REST Basic-auth failures never reveal whether a user name exists.', 'wp-security-lockdown' ),
				'enforcement' => array( __( 'Runtime: wp_login_errors (priority 99), rest_authentication_errors (priority 95).', 'wp-security-lockdown' ) ),
			)
		);
		$report['warnings'][] = __( 'The "lost password" form still says when an account does not exist; that is core behaviour users rely on and is not changed.', 'wp-security-lockdown' );
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}
		return $this->judge_hooks(
			$report,
			array(
				'wp_login_errors'            => $this->hooked( 'wp_login_errors', array( $this, 'generic_login_errors' ) ),
				'rest_authentication_errors' => $this->hooked( 'rest_authentication_errors', array( $this, 'generic_rest_auth_error' ) ),
			)
		);
	}

	/**
	 * Reports the version exposure control.
	 *
	 * @return array
	 */
	private function report_version_exposure() {
		$report               = $this->make_report(
			'version_exposure',
			array(
				'desired'     => __( 'No generator tag or feed generator, and no WordPress version in script / style URLs.', 'wp-security-lockdown' ),
				'enforcement' => array( __( 'Runtime: wp_head generator removed; filters the_generator, script_loader_src, style_loader_src. Stops on deactivation.', 'wp-security-lockdown' ) ),
			)
		);
		$report['warnings'][] = __( 'This does not make a vulnerable site safe. Static files such as readme.html and license.txt still reveal the version and can only be hidden by the web server (see Checks).', 'wp-security-lockdown' );
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}
		return $this->judge_hooks(
			$report,
			array(
				'wp_generator removed' => false === has_action( 'wp_head', 'wp_generator' ),
				'the_generator'        => false !== has_filter( 'the_generator', '__return_empty_string' ),
				'script_loader_src'    => $this->hooked( 'script_loader_src', array( $this, 'mask_version' ) ),
				'style_loader_src'     => $this->hooked( 'style_loader_src', array( $this, 'mask_version' ) ),
			)
		);
	}

	/**
	 * Reports the discovery links control.
	 *
	 * @return array
	 */
	private function report_discovery() {
		$report               = $this->make_report(
			'discovery',
			array(
				'desired'     => __( 'Page heads and headers no longer advertise REST, oEmbed or shortlink endpoints.', 'wp-security-lockdown' ),
				'enforcement' => array( __( 'Runtime: removes wp_head / template_redirect callbacks. Stops on deactivation.', 'wp-security-lockdown' ) ),
			)
		);
		$report['warnings'][] = __( 'Clients that find the REST API through the "Link" header or <link rel="https://api.w.org/"> (some mobile and desktop apps) will no longer auto-discover it. This is not access control: the endpoints still exist and are protected by the REST policy.', 'wp-security-lockdown' );
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}
		return $this->judge_hooks(
			$report,
			array(
				'rest_output_link_wp_head removed' => false === has_action( 'wp_head', 'rest_output_link_wp_head' ),
				'rest_output_link_header removed'  => false === has_action( 'template_redirect', 'rest_output_link_header' ),
				'oEmbed discovery links removed'   => false === has_action( 'wp_head', 'wp_oembed_add_discovery_links' ),
				'shortlink removed'                => false === has_action( 'wp_head', 'wp_shortlink_wp_head' ) && false === has_action( 'template_redirect', 'wp_shortlink_header' ),
			)
		);
	}

	/**
	 * Reports the error display control.
	 *
	 * @return array
	 */
	private function report_error_display() {
		$report               = $this->make_report(
			'error_display',
			array(
				'desired'      => __( 'PHP does not print errors into pages shown to visitors.', 'wp-security-lockdown' ),
				'enforcement'  => array( __( 'Runtime: ini_set( display_errors, 0 ) when the plugin loads (not applied to local / development environments or WP-CLI).', 'wp-security-lockdown' ) ),
				'server_level' => true,
			)
		);
		$report['warnings'][] = __( 'Errors raised before this plugin loads (wp-config.php, other plugins that load earlier) cannot be suppressed from here. Set display_errors = Off in php.ini / the PHP-FPM pool for a complete fix.', 'wp-security-lockdown' );
		if ( ! $report['enabled'] ) {
			$report['state'] = self::STATE_DISABLED;
			return $report;
		}

		$on                  = self::display_errors_on();
		$report['details'][] = array(
			'label'  => 'display_errors',
			'status' => $on ? 'fail' : 'ok',
			'text'   => $on ? __( 'Currently ON for this request.', 'wp-security-lockdown' ) : __( 'Currently off for this request.', 'wp-security-lockdown' ),
		);

		if ( $this->is_developer_environment() ) {
			$report['state']          = self::STATE_PARTIAL;
			$report['failure_reason'] = __( 'Not enforced: the environment type is "local" or "development", where errors are intentionally shown.', 'wp-security-lockdown' );
		} elseif ( $on ) {
			$report['state']          = self::STATE_FAILED;
			$report['failure_reason'] = __( 'display_errors is still on. The host may have disabled ini_set() or locked the value; set display_errors = Off in php.ini.', 'wp-security-lockdown' );
			$report['manual_action']  = __( 'Set display_errors = Off in the PHP configuration.', 'wp-security-lockdown' );
		} else {
			$report['state'] = self::STATE_ENFORCED;
		}
		return $report;
	}

	/* --------------------------------------------------------------------- verification */

	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- verification deliberately invokes core hooks to prove this plugin's callbacks act on them.
	/**
	 * Verifies each control inside PHP and, when a probe is given, over HTTP.
	 *
	 * @param Http_Probe|null $probe Probe or null.
	 * @return array
	 */
	public function verify( ?Http_Probe $probe = null ) {
		$s       = $this->plugin->settings();
		$results = array();
		$front   = null;

		if ( $probe ) {
			$preflight = $probe->preflight();
			$front     = $preflight['ok'] ? $probe->request( 'GET', home_url( '/' ) ) : null;
		}
		$no_http = $probe && ( null === $front || ! $front['ok'] )
			? __( 'HTTP probe unavailable.', 'wp-security-lockdown' )
			: __( 'Run verification to fetch the front page.', 'wp-security-lockdown' );

		if ( $s->control_enabled( 'author_enumeration' ) ) {
			$results['author_enumeration'] = $this->verify_author_enumeration( $probe );
		}

		if ( $s->control_enabled( 'login_errors' ) ) {
			$errors                  = apply_filters( 'wp_login_errors', new \WP_Error( 'invalid_username', 'USERNAME_EXISTS_PROBE' ), '' );
			$rest                    = apply_filters( 'rest_authentication_errors', new \WP_Error( 'invalid_username', 'USERNAME_EXISTS_PROBE', array( 'status' => 401 ) ) );
			$local                   = array(
				array( ! $errors->has_errors() || false === strpos( implode( ' ', $errors->get_error_messages() ), 'USERNAME_EXISTS_PROBE' ), 'the login form no longer repeats the account-specific message' ),
				array( is_wp_error( $rest ) && false === strpos( implode( ' ', $rest->get_error_messages() ), 'USERNAME_EXISTS_PROBE' ), 'REST Basic-auth failures are generic' ),
			);
			$results['login_errors'] = $this->conclude( $local, array(), false, '' );
		}

		if ( $s->control_enabled( 'version_exposure' ) ) {
			global $wp_version;
			$local = array(
				array( false === has_action( 'wp_head', 'wp_generator' ), 'wp_generator is not hooked to wp_head' ),
				array( '' === apply_filters( 'the_generator', '<generator>', 'rss2' ), 'feed generator tag is empty' ),
				array( false === strpos( apply_filters( 'script_loader_src', '/x.js?ver=' . $wp_version, 'x' ), 'ver=' . $wp_version ), 'script URLs no longer carry the version' ),
			);
			$http  = array();
			if ( $front && $front['ok'] ) {
				$http[] = array( 1 !== preg_match( '/<meta[^>]+name=["\']generator["\'][^>]+WordPress/i', $front['body'] ), 'front page has no WordPress generator meta tag' );
				$http[] = array( false === strpos( $front['body'], 'ver=' . $wp_version ), 'front page HTML contains no ver=' . $wp_version );
			}
			$results['version_exposure'] = $this->conclude( $local, $http, false, $no_http );
		}

		if ( $s->control_enabled( 'discovery' ) ) {
			$local = array(
				array( false === has_action( 'wp_head', 'rest_output_link_wp_head' ), 'REST <link> removed from wp_head' ),
				array( false === has_action( 'template_redirect', 'rest_output_link_header' ), 'REST Link header removed' ),
				array( false === has_action( 'wp_head', 'wp_shortlink_wp_head' ), 'shortlink <link> removed' ),
			);
			$http  = array();
			if ( $front && $front['ok'] ) {
				$http[] = array( false === strpos( $front['body'], 'api.w.org' ), 'front page HTML has no api.w.org discovery link' );
				$http[] = array( empty( $front['headers']['link'] ) || false === strpos( $front['headers']['link'], 'api.w.org' ), 'response has no api.w.org Link header' );
			}
			$results['discovery'] = $this->conclude( $local, $http, false, $no_http );
		}

		if ( $s->control_enabled( 'error_display' ) ) {
			if ( $this->is_developer_environment() ) {
				$results['error_display'] = $this->result( self::UNVERIFIED, self::METHOD_NONE, __( 'Skipped: local / development environment.', 'wp-security-lockdown' ) );
			} else {
				$results['error_display'] = $this->conclude( array( array( ! self::display_errors_on(), 'display_errors is off for this request' ) ), array(), false, '' );
			}
		}
		return $results;
	}
	// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound

	// phpcs:disable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- verification deliberately invokes core hooks to prove this plugin's callbacks act on them.
	/**
	 * ?author=N must not redirect to the author archive for an anonymous visitor.
	 *
	 * @param Http_Probe|null $probe Probe or null.
	 * @return array
	 */
	private function verify_author_enumeration( ?Http_Probe $probe = null ) {
		// Test the filter chain, not the registry: in the request that activated the plugin the registry
		// was already built (at `init`) before this filter existed, which would be a false failure.
		$local = array(
			array( false === apply_filters( 'wp_sitemaps_add_provider', 'provider', 'users' ), 'the users sitemap provider would be refused registration' ),
			array( 'provider' === apply_filters( 'wp_sitemaps_add_provider', 'provider', 'posts' ), 'other sitemap providers are untouched' ),
			array(
				array( '/wp/v2/posts' => 1 ) === $this->strip_user_routes(
					array(
						'/wp/v2/users'               => 1,
						'/wp/v2/users/(?P<id>[\d]+)' => 1,
						'/wp/v2/posts'               => 1,
					)
				),
				'anonymous REST routes exclude /wp/v2/users',
			),
			array( $this->hooked( 'template_redirect', array( $this, 'block_author_query' ) ), 'template_redirect hook attached' ),
		);

		if ( '' === (string) get_option( 'permalink_structure' ) ) {
			return $this->result( self::UNVERIFIED, self::METHOD_IN_PROCESS, __( 'Plain permalinks: ?author=N cannot be blocked (it is the canonical author URL).', 'wp-security-lockdown' ) );
		}

		$http   = array();
		$reason = __( 'Run verification to request ?author=N.', 'wp-security-lockdown' );
		if ( $probe ) {
			$authors = get_users(
				array(
					'has_published_posts' => true,
					'number'              => 1,
					'fields'              => 'ID',
				)
			);
			if ( ! $authors ) {
				$reason = __( 'No author with published posts exists, so ?author=N would not redirect even without the control; nothing to test against.', 'wp-security-lockdown' );
			} else {
				$response = $probe->request( 'GET', add_query_arg( 'author', (int) $authors[0], home_url( '/' ) ) );
				$reason   = $response['ok'] ? '' : $response['error'];
				if ( $response['ok'] ) {
					$http[] = array(
						404 === $response['code'] && empty( $response['headers']['location'] ),
						sprintf( 'Anonymous /?author=%d answered HTTP %d (404 without a redirect expected)', (int) $authors[0], $response['code'] ),
					);
				}
			}
		}//end if
		return $this->conclude( $local, $http, true, $reason );
	}
	// phpcs:enable WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound
}
