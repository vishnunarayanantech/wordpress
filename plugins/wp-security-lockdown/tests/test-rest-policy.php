<?php
/**
 * REST API access policy.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Http_Probe;

class Test_Rest_Policy extends Test_Case {

	/** @var int */
	private $admin;

	/** @var int */
	private $subscriber;

	public function set_up() {
		parent::set_up();
		$this->admin      = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->subscriber = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->configure();
	}

	/**
	 * Dispatches a request the way the REST server does for a request that passed authentication.
	 */
	private function dispatch( $method, $route, array $params = array() ) {
		$request = new \WP_REST_Request( $method, $route );
		foreach ( $params as $key => $value ) {
			$request->set_param( $key, $value );
		}
		return rest_do_request( $request );
	}

	/** ---------------------------------------------------------------- anonymous */

	/**
	 * @dataProvider anonymous_routes
	 */
	public function test_anonymous_requests_are_refused( $route ) {
		$result = $this->rest_auth( $route, 0 );
		$this->assertWPError( $result, "$route must not be reachable anonymously" );
		$this->assertSame( 'rest_not_logged_in', $result->get_error_code() );
		$this->assertSame( 401, $result->get_error_data()['status'] );
	}

	public function anonymous_routes() {
		return array(
			'index'               => array( '/' ),
			'users'               => array( '/wp/v2/users' ),
			'a user'              => array( '/wp/v2/users/1' ),
			'posts'               => array( '/wp/v2/posts' ),
			'comments'            => array( '/wp/v2/comments' ),
			'oembed'              => array( '/oembed/1.0/embed' ),
			'batch'               => array( '/batch/v1' ),
			'site health'         => array( '/wp-site-health/v1/tests/https-status' ),
			'namespace index'     => array( '/wp/v2' ),
			'a route that is not' => array( '/does/not/exist' ),
		);
	}

	public function test_the_refusal_does_not_reveal_whether_a_route_exists() {
		$real = $this->rest_auth( '/wp/v2/users', 0 );
		$fake = $this->rest_auth( '/nope/v9/nothing', 0 );
		$this->assertSame( $real->get_error_code(), $fake->get_error_code() );
		$this->assertSame( $real->get_error_message(), $fake->get_error_message() );
	}

	public function test_route_spelling_tricks_do_not_slip_past() {
		foreach ( array( '/WP/V2/Users', '/wp/v2/users/', '//wp/v2/users', '/wp/v2/users//', '/Wp/V2/POSTS' ) as $route ) {
			$this->assertWPError( $this->rest_auth( $route, 0 ), "$route" );
		}
	}

	public function test_an_unknown_route_context_is_denied_by_default() {
		global $wp;
		unset( $wp->query_vars['rest_route'] );
		wp_set_current_user( 0 );
		$this->assertWPError( apply_filters( 'rest_authentication_errors', null ), 'If the route cannot be determined an anonymous request is refused.' );
	}

	public function test_a_cookie_without_a_nonce_is_anonymous() {
		$result = $this->rest_auth( '/wp/v2/users/me', $this->admin, 'cookie_no_nonce' );
		$this->assertWPError( $result, 'Core demotes a cookie without a nonce to anonymous (CSRF protection); the policy must keep it that way.' );
		$this->assertSame( 401, $result->get_error_data()['status'] );
	}

	/** ---------------------------------------------------------------- allowlist */

	public function test_a_public_namespace_is_reachable_anonymously_but_only_that_namespace() {
		$this->configure( array( 'rest' => array( 'public_namespaces' => array( 'contact-form-7/v1' ) ) ) );

		foreach ( array( '/contact-form-7/v1', '/contact-form-7/v1/contact-forms/12/feedback', '/CONTACT-FORM-7/V1/x' ) as $route ) {
			$this->assertNotWPError( $this->rest_auth( $route, 0 ), "$route is the allowlisted namespace" );
		}
		foreach ( array( '/contact-form-7/v10/x', '/contact-form-7', '/contact-form-7-evil/v1/x', '/wp/v2/users', '/contact-form-7/v1/../../wp/v2/users', '/contact-form-7/v1/./x', '/contact-form-7/v1//x', "/contact-form-7/v1/x\x00", '/contact-form-7/v1/..', '/x/contact-form-7/v1', '/contact-form-7/v1\\..\\wp' ) as $route ) {
			$this->assertWPError( $this->rest_auth( $route, 0 ), "$route is not inside the allowlisted namespace" );
		}
	}

	public function test_no_public_exception_exists_by_default() {
		$this->assertSame( array(), $this->plugin->settings()->get( 'rest.public_namespaces' ) );
	}

	/** ---------------------------------------------------------------- authenticated */

	public function test_authenticated_requests_pass_the_gate_and_the_endpoint_decides() {
		$this->assertNotWPError( $this->rest_auth( '/wp/v2/settings', $this->admin, 'cookie' ) );
		$this->assertSame( 200, $this->dispatch( 'GET', '/wp/v2/settings' )->get_status(), 'An administrator may read settings.' );

		$this->assertNotWPError( $this->rest_auth( '/wp/v2/settings', $this->subscriber, 'cookie' ), 'Being logged in is enough for the gate...' );
		$this->assertSame( 403, $this->dispatch( 'GET', '/wp/v2/settings' )->get_status(), '...but the endpoint still refuses a subscriber: authentication alone never grants access.' );
	}

	public function test_unauthorized_requests_are_still_refused_by_each_endpoint() {
		$this->rest_auth( '/wp/v2/users', $this->subscriber, 'cookie' );
		$this->assertSame( 403, $this->dispatch( 'GET', '/wp/v2/users', array( 'context' => 'edit' ) )->get_status() );
		$this->assertSame(
			403,
			$this->dispatch(
				'POST',
				'/wp/v2/posts',
				array(
					'title'  => 'x',
					'status' => 'draft',
				)
			)->get_status()
		);
		$this->assertSame(
			403,
			$this->dispatch(
				'POST',
				'/wp/v2/users',
				array(
					'username' => 'x',
					'email'    => 'x@example.org',
					'password' => 'a-long-enough-password',
				)
			)->get_status()
		);
		$this->assertSame( 403, $this->dispatch( 'GET', '/wp/v2/plugins' )->get_status() );
	}

	public function test_an_existing_authentication_error_is_never_masked() {
		add_filter(
			'rest_authentication_errors',
			static function () {
				return new \WP_Error( 'rest_cookie_invalid_nonce', 'Cookie check failed', array( 'status' => 403 ) );
			},
			50
		);
		$result = $this->rest_auth( '/wp/v2/users', $this->admin, 'cookie' );
		$this->assertWPError( $result );
		$this->assertSame( 'rest_cookie_invalid_nonce', $result->get_error_code() );
		$this->assertSame( 403, $result->get_error_data()['status'] );
	}

	public function test_the_policy_never_grants_access_that_an_earlier_filter_denied() {
		add_filter(
			'rest_authentication_errors',
			static function () {
				return new \WP_Error( 'custom_denied', 'No', array( 'status' => 451 ) );
			},
			10
		);
		$this->assertSame( 'custom_denied', $this->rest_auth( '/wp/v2/users', $this->admin, 'cookie' )->get_error_code() );
	}

	/** ---------------------------------------------------------------- administration keeps working */

	public function test_block_editor_and_dashboard_requests_keep_working_for_an_administrator() {
		$this->setExpectedDeprecated( 'WP_User_Query' ); // Core's users endpoint still passes the deprecated `who` argument.
		$this->assertNotWPError( $this->rest_auth( '/wp/v2/types/post', $this->admin, 'cookie' ) );

		$requests = array(
			array( 'GET', '/wp/v2/users/me', array(), 200 ),
			array( 'GET', '/wp/v2/types/post', array( 'context' => 'edit' ), 200 ),
			array( 'GET', '/wp/v2/types', array( 'context' => 'edit' ), 200 ),
			array( 'GET', '/wp/v2/settings', array(), 200 ),
			array( 'GET', '/wp/v2/block-types', array(), 200 ),
			array( 'GET', '/wp/v2/taxonomies', array( 'context' => 'edit' ), 200 ),
			array( 'GET', '/wp/v2/themes', array( 'status' => 'active' ), 200 ),
			array(
				'GET',
				'/wp/v2/users',
				array(
					'who'      => 'authors',
					'per_page' => 100,
				),
				200,
			),
			array( 'GET', '/wp/v2/posts', array( 'context' => 'edit' ), 200 ),
			array( 'GET', '/', array(), 200 ),
		);
		foreach ( $requests as $r ) {
			$this->assertSame( $r[3], $this->dispatch( $r[0], $r[1], $r[2] )->get_status(), "{$r[0]} {$r[1]} as the editor UI would send it" );
		}

		$created = $this->dispatch(
			'POST',
			'/wp/v2/posts',
			array(
				'title'   => 'Draft from the editor',
				'status'  => 'draft',
				'content' => 'x',
			)
		);
		$this->assertSame( 201, $created->get_status() );
		$this->assertSame( 200, $this->dispatch( 'POST', '/wp/v2/posts/' . $created->get_data()['id'], array( 'title' => 'Renamed' ) )->get_status() );
	}

	public function test_an_editor_can_use_the_editor_apis_an_author_dropdown_needs() {
		$this->setExpectedDeprecated( 'WP_User_Query' ); // Core's users endpoint still passes the deprecated `who` argument.
		$editor = self::factory()->user->create( array( 'role' => 'editor' ) );
		$this->assertNotWPError( $this->rest_auth( '/wp/v2/users', $editor, 'cookie' ) );
		$this->assertSame( 200, $this->dispatch( 'GET', '/wp/v2/users', array( 'who' => 'authors' ) )->get_status() );
	}

	public function test_internal_server_side_dispatch_is_not_subject_to_the_http_gate() {
		wp_set_current_user( 0 );
		$response = $this->dispatch( 'GET', '/wp/v2/posts' );
		$this->assertSame( 200, $response->get_status(), 'Themes and plugins that call the REST API from PHP are trusted code and keep working; only HTTP requests are gated.' );
	}

	/** ---------------------------------------------------------------- application passwords */

	private function with_application_password( $password_ok = true ) {
		add_filter( 'wp_is_application_passwords_available', '__return_true' );
		add_filter( 'application_password_is_api_request', '__return_true' );
		list( $password )         = \WP_Application_Passwords::create_new_application_password( $this->admin, array( 'name' => 'phpunit' ) );
		$_SERVER['PHP_AUTH_USER'] = get_userdata( $this->admin )->user_login;
		$_SERVER['PHP_AUTH_PW']   = $password_ok ? $password : 'wrong wrong wrong wrong';

		global $wp, $current_user, $wp_rest_auth_cookie, $wp_rest_application_password_status, $wp_rest_application_password_uuid;
		$wp->query_vars['rest_route']        = '/wp/v2/posts';
		$current_user                        = null;
		$wp_rest_auth_cookie                 = null;
		$wp_rest_application_password_status = null;
		$wp_rest_application_password_uuid   = null;
		unset( $_SERVER['HTTP_X_WP_NONCE'] );
		wp_get_current_user(); // Runs determine_current_user, which validates the Basic-auth credentials.
	}

	public function test_an_application_password_client_is_authenticated_and_allowed_in_restricted_mode() {
		$this->with_application_password( true );
		$this->assertSame( $this->admin, get_current_user_id() );
		$this->assertNotWPError( apply_filters( 'rest_authentication_errors', null ) );
		$this->assertNotNull( rest_get_authenticated_app_password() );
	}

	public function test_an_application_password_client_is_refused_in_dashboard_only_mode() {
		$this->configure( array( 'rest' => array( 'mode' => 'dashboard_only' ) ) );
		$this->with_application_password( true );
		$result = apply_filters( 'rest_authentication_errors', null );
		$this->assertWPError( $result );
		$this->assertSame( 403, $result->get_error_data()['status'] );
	}

	public function test_a_wrong_application_password_gets_a_generic_error_that_does_not_reveal_the_account() {
		$this->configure( array( 'login' => array( 'generic_errors' => true ) ) );
		$this->with_application_password( false );
		$result = apply_filters( 'rest_authentication_errors', null );
		$this->assertWPError( $result );
		$this->assertContains( $result->get_error_code(), array( 'incorrect_password' ) );
		$this->assertStringNotContainsString( get_userdata( $this->admin )->user_login, $result->get_error_message() );
		$this->assertSame( 401, $result->get_error_data()['status'] );
	}

	/** ---------------------------------------------------------------- dashboard-only ("full shutdown") */

	public function test_dashboard_only_keeps_the_dashboard_and_editor_working() {
		$this->configure( array( 'rest' => array( 'mode' => 'dashboard_only' ) ) );
		foreach ( array( '/', '/batch/v1', '/wp/v2/posts', '/wp/v2/users/me', '/wp-site-health/v1/directory-sizes', '/wp-block-editor/v1/navigation-fallback', '/wp-abilities/v1/abilities', '/oembed/1.0/proxy' ) as $route ) {
			$this->assertNotWPError( $this->rest_auth( $route, $this->admin, 'cookie' ), "$route is used by wp-admin and must keep working for a logged-in dashboard session" );
		}
		$this->rest_auth( '/wp/v2/settings', $this->admin, 'cookie' );
		$this->assertSame( 200, $this->dispatch( 'GET', '/wp/v2/settings' )->get_status() );
	}

	public function test_dashboard_only_refuses_everything_that_is_not_the_dashboard() {
		$this->configure(
			array(
				'rest' => array(
					'mode'              => 'dashboard_only',
					'public_namespaces' => array( 'contact-form-7/v1' ),
				),
			)
		);

		$this->assertWPError( $this->rest_auth( '/wp/v2/posts', 0 ), 'anonymous' );
		$this->assertWPError( $this->rest_auth( '/contact-form-7/v1/x', 0 ), 'the public allowlist is ignored in this mode' );
		$this->assertWPError( $this->rest_auth( '/wp/v2/posts', $this->admin, 'other' ), 'token / non-cookie clients' );
		$denied = $this->rest_auth( '/wc/v3/orders', $this->admin, 'cookie' );
		$this->assertWPError( $denied, 'third-party namespaces' );
		$this->assertSame( 403, $denied->get_error_data()['status'] );
	}

	public function test_dashboard_only_extra_namespaces_apply_to_logged_in_sessions_only() {
		$this->configure(
			array(
				'rest' => array(
					'mode'                 => 'dashboard_only',
					'dashboard_namespaces' => array( 'wc-admin' ),
				),
			)
		);
		$this->assertNotWPError( $this->rest_auth( '/wc-admin/options', $this->admin, 'cookie' ) );
		$this->assertWPError( $this->rest_auth( '/wc-admin/options', 0 ) );
		$this->assertWPError( $this->rest_auth( '/wc-admin/options', $this->admin, 'other' ), 'A listed namespace is still dashboard-session only.' );
	}

	/** ---------------------------------------------------------------- modes and reporting */

	public function test_off_mode_registers_nothing_and_changes_nothing() {
		$this->configure( array( 'rest' => array( 'mode' => 'off' ) ) );
		$this->assertFalse( has_filter( 'rest_authentication_errors', array( $this->module( 'rest_api_policy' ), 'enforce' ) ) );
		$this->assertNotWPError( $this->rest_auth( '/wp/v2/users', 0 ) );
		$this->assertSame( 'disabled', $this->module( 'rest_api_policy' )->report()['rest_api']['state'] );
	}

	public function test_the_filter_runs_after_core_checks_so_it_sees_the_final_authentication() {
		$priorities = array();
		foreach ( $GLOBALS['wp_filter']['rest_authentication_errors']->callbacks as $priority => $callbacks ) {
			foreach ( $callbacks as $callback ) {
				$priorities[ is_array( $callback['function'] ) ? get_class( $callback['function'][0] ) . '::' . $callback['function'][1] : (string) $callback['function'] ] = $priority;
			}
		}
		$this->assertSame( 90, $priorities['rest_application_password_check_errors'] );
		$this->assertSame( 100, $priorities['rest_cookie_check_errors'] );
		$this->assertSame( 110, $priorities['WP_Security_Lockdown\Modules\Rest_Api_Policy::enforce'] );
	}

	public function test_report_warns_about_third_party_integrations_and_missing_application_passwords() {
		update_option( 'active_plugins', array( 'woocommerce/woocommerce.php', 'contact-form-7/wp-contact-form-7.php' ) );
		$warnings = implode( ' ', $this->module( 'rest_api_policy' )->report()['rest_api']['warnings'] );
		$this->assertStringContainsString( 'WooCommerce', $warnings );
		$this->assertStringContainsString( 'Contact Form 7', $warnings );
		$this->assertStringContainsString( 'Application Passwords are not available', $warnings );
	}

	public function test_dashboard_only_report_is_labelled_potentially_breaking() {
		$this->configure( array( 'rest' => array( 'mode' => 'dashboard_only' ) ) );
		$this->assertStringContainsString( 'POTENTIALLY BREAKING', implode( ' ', $this->module( 'rest_api_policy' )->report()['rest_api']['warnings'] ) );
	}

	/** ---------------------------------------------------------------- verification */

	public function test_without_http_the_control_is_never_called_verified() {
		$result = $this->module( 'rest_api_policy' )->verify()['rest_api'];
		$this->assertSame( 'unverified', $result['status'] );
	}

	public function test_http_verification_requires_anonymous_requests_to_be_refused() {
		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'rest_route' ) ? $this->http_response( 401, '{"code":"rest_not_logged_in"}' ) : $this->http_response( 200, '<html></html>' );
			}
		);
		$good = $this->module( 'rest_api_policy' )->verify( new Http_Probe() )['rest_api'];
		$this->assertSame( 'verified', $good['status'] );
		$this->assertSame( 'http_probe', $good['method'] );
		$this->assertStringContainsString( 'NOT tested', $good['detail'], 'Without an interactive session the dashboard requests are not tested, and the result says so.' );

		remove_all_filters( 'pre_http_request' );
		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'rest_route' ) ? $this->http_response( 200, '[{"slug":"admin"}]' ) : $this->http_response( 200, '<html></html>' );
			}
		);
		$this->assertSame( 'failed', $this->module( 'rest_api_policy' )->verify( new Http_Probe() )['rest_api']['status'], 'An anonymous 200 means the API is open.' );
	}
}
