<?php
/**
 * Base test case.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Audit_Logger;
use WP_Security_Lockdown\Plugin;
use WP_Security_Lockdown\Rate_Limiter;
use WP_Security_Lockdown\Settings_Repository;
use WP_Security_Lockdown\State_Repository;

/**
 * Thrown by test doubles instead of calling exit().
 */
class Terminated extends \Exception {}

/**
 * Gives every test a clean plugin: stored data reset, services recreated, and none of the plugin's
 * runtime hooks attached, so a test registers exactly the modules (and settings) it is about.
 */
abstract class Test_Case extends \WP_UnitTestCase {

	/** @var Plugin */
	protected $plugin;

	/**
	 * @return void
	 */
	public function set_up() {
		parent::set_up();

		$this->strip_plugin_hooks();
		foreach ( array( Settings_Repository::OPTION, State_Repository::OPTION, Audit_Logger::OPTION ) as $option ) {
			delete_option( $option );
		}
		Rate_Limiter::clear_all();

		Plugin::reset();
		$this->plugin = Plugin::instance();
		$this->plugin->settings();
	}

	/**
	 * Throws the plugin object graph away and builds a fresh one (settings are re-read from the database).
	 *
	 * @return void
	 */
	protected function reload_plugin() {
		Plugin::reset();
		$this->plugin = Plugin::instance();
		$this->plugin->settings();
	}

	/**
	 * Detaches every hook that belongs to the plugin (those registered by the bootstrap and by earlier tests).
	 *
	 * @return void
	 */
	protected function strip_plugin_hooks() {
		global $wp_filter;
		foreach ( $wp_filter as $hook => $hook_object ) {
			foreach ( $hook_object->callbacks as $priority => $callbacks ) {
				foreach ( $callbacks as $callback ) {
					$function = $callback['function'];
					// The plugin's own objects (and test doubles that extend them), but never the WordPress test
					// library's hooks, which are registered on the test case object itself.
					if ( is_array( $function ) && is_object( $function[0] ) && ! ( $function[0] instanceof \WP_UnitTestCase_Base ) && 0 === strpos( get_class( $function[0] ), 'WP_Security_Lockdown\\' ) ) {
						remove_filter( $hook, $function, $priority );
					}
				}
			}
		}
		// Callbacks the plugin registers by function name.
		remove_filter( 'comments_open', '__return_false', 999 );
		remove_filter( 'pings_open', '__return_false', 999 );
		remove_filter( 'xmlrpc_enabled', '__return_false', 999 );
		remove_filter( 'the_generator', '__return_empty_string', 99 );
	}

	/**
	 * Applies a partial policy and registers every module against it.
	 *
	 * @param array $partial Section => key => value.
	 * @return void
	 */
	protected function configure( array $partial = array() ) {
		$this->strip_plugin_hooks();
		if ( $partial ) {
			$this->plugin->settings()->update( $partial );
		}
		$this->plugin->policy()->register_modules();
	}

	/**
	 * Returns one module by slug.
	 *
	 * @param string $slug Module slug.
	 * @return \WP_Security_Lockdown\Abstract_Module
	 */
	protected function module( $slug ) {
		foreach ( $this->plugin->policy()->modules() as $module ) {
			if ( $module->slug() === $slug ) {
				return $module;
			}
		}
		$this->fail( "No module $slug" );
	}

	/**
	 * Creates a user and makes them the current user.
	 *
	 * @param string $role Role.
	 * @return int User id.
	 */
	protected function login_as( $role ) {
		$id = self::factory()->user->create( array( 'role' => $role ) );
		wp_set_current_user( $id );
		return $id;
	}

	/**
	 * Simulates the authentication stage of a REST request (what WP_REST_Server::serve_request() does
	 * before dispatching) and returns the result of the `rest_authentication_errors` filter chain.
	 *
	 * @param string $route  Route, e.g. "/wp/v2/users".
	 * @param int    $user   User id (0 = anonymous).
	 * @param string $how    anonymous | cookie (valid nonce) | cookie_no_nonce | other (token / app password style).
	 * @return \WP_Error|true|null
	 */
	protected function rest_auth( $route, $user = 0, $how = 'anonymous' ) {
		global $wp, $wp_rest_auth_cookie, $wp_rest_application_password_status, $wp_rest_application_password_uuid;

		$wp->query_vars['rest_route']        = $route;
		$wp_rest_auth_cookie                 = null;
		$wp_rest_application_password_status = null;
		$wp_rest_application_password_uuid   = null;
		unset( $_SERVER['HTTP_X_WP_NONCE'] );
		wp_set_current_user( $user );

		if ( 'cookie' === $how || 'cookie_no_nonce' === $how ) {
			$wp_rest_auth_cookie = true;
			if ( 'cookie' === $how ) {
				$_SERVER['HTTP_X_WP_NONCE'] = wp_create_nonce( 'wp_rest' );
			}
		}
		if ( 'app_password' === $how ) {
			$wp_rest_application_password_uuid = 'test-uuid';
		}
		return apply_filters( 'rest_authentication_errors', null );
	}

	/** @var array[] Requests seen by mock_http(): array( url, args ). */
	protected $http_calls = array();

	/**
	 * Replaces the network: every wp_remote_*() call is answered by $router( $url, $args ).
	 *
	 * @param callable $router Returns a response array (see http_response()) or a WP_Error.
	 * @return void
	 */
	protected function mock_http( callable $router ) {
		$this->http_calls = array();
		add_filter(
			'pre_http_request',
			function ( $pre, $args, $url ) use ( $router ) {
				$this->http_calls[] = array( $url, $args );
				return call_user_func( $router, $url, $args );
			},
			10,
			3
		);
	}

	/**
	 * Builds a response in the shape wp_remote_request() returns.
	 *
	 * @param int    $code    Status code.
	 * @param string $body    Body.
	 * @param array  $headers Headers.
	 * @return array
	 */
	protected function http_response( $code, $body = '', array $headers = array() ) {
		return array(
			'headers'  => $headers,
			'body'     => $body,
			'response' => array(
				'code'    => $code,
				'message' => 'Mock',
			),
			'cookies'  => array(),
			'filename' => null,
		);
	}

	/**
	 * Whether an authentication result lets the request proceed.
	 *
	 * @param mixed $result Result of rest_auth().
	 * @return bool
	 */
	protected function is_allowed( $result ) {
		return ! is_wp_error( $result );
	}
}
