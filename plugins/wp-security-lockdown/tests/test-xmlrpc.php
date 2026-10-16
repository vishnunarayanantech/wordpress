<?php
/**
 * XML-RPC rejection.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Modules\Xmlrpc_Hardening;

/**
 * Module whose "is this xmlrpc.php?" answer is controllable and which throws instead of exit().
 */
class Testable_Xmlrpc extends Xmlrpc_Hardening {
	public $is_request = true;
	protected function is_xmlrpc_request() {
		return $this->is_request;
	}
	protected function terminate() {
		throw new Terminated( 'exit' );
	}
}

class Test_Xmlrpc extends Test_Case {

	/**
	 * Registers a module and reports what it did to the response.
	 *
	 * @return array array( terminated, status codes sent, body ).
	 */
	private function run_module( Testable_Xmlrpc $module ) {
		$codes = array();
		add_filter(
			'status_header',
			static function ( $header, $code ) use ( &$codes ) {
				$codes[] = $code;
				return $header;
			},
			10,
			2
		);
		$terminated = false;
		ob_start();
		try {
			$module->register();
		} catch ( Terminated $e ) {
			$terminated = true;
		}
		$body = ob_get_clean();
		return array( $terminated, $codes, $body );
	}

	private function new_module() {
		return new Testable_Xmlrpc( $this->plugin );
	}

	public function test_block_mode_rejects_the_request_with_403_before_anything_else_runs() {
		[ $terminated, $codes, $body ] = $this->run_module( $this->new_module() );

		$this->assertTrue( $terminated, 'The request must be ended.' );
		$this->assertSame( array( 403 ), $codes );
		$this->assertSame( 'XML-RPC is disabled on this site.', $body );
		$this->assertStringNotContainsString( '<methodResponse', $body );
	}

	public function test_rejection_does_not_depend_on_hiding_the_endpoint() {
		// The RSD link and the X-Pingback header are cosmetic. Prove the rejection works with them left in place.
		add_action( 'wp_head', 'rsd_link' );
		[ $terminated ] = $this->run_module( $this->new_module() );
		$this->assertTrue( $terminated );
	}

	public function test_requests_that_are_not_xmlrpc_are_untouched() {
		$module                        = $this->new_module();
		$module->is_request            = false;
		[ $terminated, $codes, $body ] = $this->run_module( $module );

		$this->assertFalse( $terminated );
		$this->assertSame( array(), $codes );
		$this->assertSame( '', $body );
	}

	public function test_allow_mode_keeps_the_endpoint_but_never_the_pingback_methods() {
		$this->plugin->settings()->update( array( 'xmlrpc' => array( 'mode' => 'allow' ) ) );
		[ $terminated ] = $this->run_module( $this->new_module() );
		$this->assertFalse( $terminated, 'Declared as necessary: the endpoint stays reachable.' );

		$methods = apply_filters(
			'xmlrpc_methods',
			array(
				'pingback.ping'                    => 'x',
				'pingback.extensions.getPingbacks' => 'x',
				'wp.getPosts'                      => 'x',
				'system.listMethods'               => 'x',
			)
		);
		$this->assertArrayNotHasKey( 'pingback.ping', $methods );
		$this->assertArrayNotHasKey( 'pingback.extensions.getPingbacks', $methods );
		$this->assertArrayHasKey( 'wp.getPosts', $methods );
		$this->assertTrue( apply_filters( 'xmlrpc_enabled', true ), 'Allowed mode must not force the authenticated methods off.' );
	}

	public function test_core_xmlrpc_server_exposes_no_methods_in_block_mode_and_no_pingbacks_in_allow_mode() {
		require_once ABSPATH . WPINC . '/class-IXR.php';
		require_once ABSPATH . WPINC . '/class-wp-xmlrpc-server.php';

		$this->run_module( $this->new_module() );
		$server = new \wp_xmlrpc_server();
		$this->assertSame( array(), $server->methods, 'Defence in depth: even if the early exit were bypassed there is nothing to call.' );
		$this->assertFalse( $server->login( 'anyone', 'anything' ), 'Authenticated methods are disabled.' );
		$this->assertSame( 405, $server->error->code );

		$this->plugin->settings()->update( array( 'xmlrpc' => array( 'mode' => 'allow' ) ) );
		$this->configure();
		$this->run_module( $this->new_module() );
		$server = new \wp_xmlrpc_server();
		$this->assertArrayNotHasKey( 'pingback.ping', $server->methods );
		$this->assertArrayHasKey( 'wp.getUsersBlogs', $server->methods );
	}

	public function test_without_the_plugin_core_still_serves_pingbacks() {
		// Control experiment: this is the amplification vector the plugin removes.
		$this->strip_plugin_hooks();
		require_once ABSPATH . WPINC . '/class-IXR.php';
		require_once ABSPATH . WPINC . '/class-wp-xmlrpc-server.php';
		$server = new \wp_xmlrpc_server();
		$this->assertArrayHasKey( 'pingback.ping', $server->methods );
	}

	public function test_core_documents_that_xmlrpc_enabled_alone_is_not_enough() {
		// With only the documented filter, an unauthenticated method is still registered and served.
		$this->strip_plugin_hooks();
		add_filter( 'xmlrpc_enabled', '__return_false' );
		require_once ABSPATH . WPINC . '/class-IXR.php';
		require_once ABSPATH . WPINC . '/class-wp-xmlrpc-server.php';
		$server = new \wp_xmlrpc_server();
		$this->assertArrayHasKey( 'pingback.ping', $server->methods, 'xmlrpc_enabled=false does not remove unauthenticated methods, which is why the plugin ends the request instead.' );
	}

	public function test_a_blocked_request_is_logged_at_most_once_a_day() {
		$this->run_module( $this->new_module() );
		$this->run_module( $this->new_module() );
		$this->run_module( $this->new_module() );
		$events = array_column( $this->plugin->logger()->entries( 50 ), 'e' );
		$this->assertSame( 1, count( array_keys( $events, 'xmlrpc_blocked', true ) ), 'Attackers must not be able to flood the log.' );
	}

	public function test_report_requires_the_hooks_to_have_registered() {
		$module = $this->new_module();
		$this->assertSame( 'failed', $module->report()['xmlrpc']['state'], 'Before register() nothing is enforced and the report must say so.' );
		$this->run_module( $module );
		$this->assertSame( 'enforced', $module->report()['xmlrpc']['state'] );
	}

	public function test_jetpack_triggers_a_compatibility_warning_and_a_manual_action() {
		update_option( 'active_plugins', array( 'jetpack/jetpack.php' ) );
		$this->run_module( $this->new_module() );
		$report = $this->new_module()->report()['xmlrpc'];
		$this->assertStringContainsString( 'Jetpack', implode( ' ', $report['warnings'] ) );
		$this->assertNotSame( '', $report['manual_action'] );
	}

	public function test_a_filter_alone_is_never_enough_to_be_called_verified() {
		$this->run_module( $this->new_module() );
		$result = $this->new_module()->verify()['xmlrpc'];
		$this->assertSame( 'unverified', $result['status'], 'Without a real request nobody knows xmlrpc.php rejects anything.' );
	}

	public function test_http_verification_requires_403_and_no_xmlrpc_response() {
		$this->run_module( $this->new_module() );

		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'xmlrpc.php' ) ? $this->http_response( 403, 'XML-RPC is disabled on this site.' ) : $this->http_response( 200, '<html></html>' );
			}
		);
		$good = $this->new_module()->verify( new Http_Probe() )['xmlrpc'];
		$this->assertSame( 'verified', $good['status'] );
		$this->assertSame( 'http_probe', $good['method'] );

		remove_all_filters( 'pre_http_request' );
		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'xmlrpc.php' ) ? $this->http_response( 200, '<?xml version="1.0"?><methodResponse><params></params></methodResponse>' ) : $this->http_response( 200, '<html></html>' );
			}
		);
		$bad = $this->new_module()->verify( new Http_Probe() )['xmlrpc'];
		$this->assertSame( 'failed', $bad['status'], 'xmlrpc.php answering with an XML-RPC response means the endpoint is NOT rejected.' );
	}

	public function test_a_server_that_answers_403_but_returns_xmlrpc_is_not_verified() {
		$this->run_module( $this->new_module() );
		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'xmlrpc.php' ) ? $this->http_response( 403, '<methodResponse>…</methodResponse>' ) : $this->http_response( 200, '' );
			}
		);
		$this->assertSame( 'failed', $this->new_module()->verify( new Http_Probe() )['xmlrpc']['status'] );
	}

	public function test_loopback_failure_leaves_the_control_unverified_never_verified() {
		$this->run_module( $this->new_module() );
		$this->mock_http(
			function () {
				return new \WP_Error( 'http_request_failed', 'cURL error 6: Could not resolve host' );
			}
		);
		$result = $this->new_module()->verify( new Http_Probe() )['xmlrpc'];
		$this->assertSame( 'unverified', $result['status'] );
		$this->assertStringContainsString( 'unavailable', $result['detail'] );
		$this->assertCount( 1, $this->http_calls, 'After the preflight fails no further requests are attempted.' );
	}

	public function test_allow_mode_verification_checks_that_pingback_is_not_listed() {
		$this->plugin->settings()->update( array( 'xmlrpc' => array( 'mode' => 'allow' ) ) );
		$this->configure();
		$this->run_module( $this->new_module() );

		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'xmlrpc.php' ) ? $this->http_response( 200, '<methodResponse><string>wp.getPosts</string></methodResponse>' ) : $this->http_response( 200, '' );
			}
		);
		$this->assertSame( 'verified', $this->new_module()->verify( new Http_Probe() )['xmlrpc']['status'] );

		remove_all_filters( 'pre_http_request' );
		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'xmlrpc.php' ) ? $this->http_response( 200, '<methodResponse><string>pingback.ping</string></methodResponse>' ) : $this->http_response( 200, '' );
			}
		);
		$this->assertSame( 'failed', $this->new_module()->verify( new Http_Probe() )['xmlrpc']['status'] );
	}
}
