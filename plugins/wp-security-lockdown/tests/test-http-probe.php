<?php
/**
 * Loopback probe guardrails.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Http_Probe;

class Test_Http_Probe extends Test_Case {

	public function tear_down() {
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		parent::tear_down();
	}

	private function ok() {
		$this->mock_http(
			function () {
				return $this->http_response( 200, 'body', array( 'X-Test' => 'yes' ) );
			}
		);
	}

	public function test_only_this_sites_own_host_is_ever_requested() {
		$this->ok();
		$probe = new Http_Probe();
		$probe->preflight(); // The one legitimate request (to this site); everything below must add none.
		foreach ( array( 'http://evil.example.com/', 'https://example.org.evil.com/', 'http://localhost.evil/', 'ftp://example.org/', 'file:///etc/passwd', 'javascript:alert(1)', '//example.org/x', 'http:///nohost' ) as $url ) {
			$before   = count( $this->http_calls );
			$response = $probe->request( 'GET', $url );
			$this->assertFalse( $response['ok'], $url );
			$this->assertSame( $before, count( $this->http_calls ), "$url must not reach the network" );
		}
	}

	public function test_the_sites_own_urls_are_allowed() {
		$this->ok();
		$probe = new Http_Probe();
		foreach ( array( home_url( '/' ), site_url( 'xmlrpc.php' ), admin_url( 'admin-ajax.php' ), home_url( '/?x=1' ) ) as $url ) {
			$this->assertTrue( $probe->request( 'GET', $url )['ok'], $url );
		}
	}

	public function test_requests_are_conservative() {
		$this->ok();
		$probe = new Http_Probe();
		$probe->request(
			'POST',
			home_url( '/x' ),
			array(
				'timeout' => 9999,
				'body'    => 'a=1',
			)
		);
		$args = $this->http_calls[ count( $this->http_calls ) - 1 ][1];

		$this->assertSame( 0, $args['redirection'], 'Redirects are never followed.' );
		$this->assertLessThanOrEqual( 25, $args['timeout'], 'A request cannot outlive the total budget.' );
		$this->assertGreaterThan( 0, $args['limit_response_size'], 'Responses are size-capped.' );
		$this->assertStringContainsString( 'WP-Security-Lockdown-Probe', $args['user-agent'] );
		$this->assertFalse( $args['reject_unsafe_urls'] );
		$this->assertEmpty( $args['cookies'], 'No session is sent unless an authenticated probe was requested.' );
		$this->assertArrayNotHasKey( 'X-WP-Nonce', $args['headers'] );
	}

	public function test_tls_verification_follows_wordpress_loopback_policy() {
		$this->ok();
		add_filter( 'https_local_ssl_verify', '__return_true' );
		( new Http_Probe() )->request( 'GET', home_url( '/x' ) );
		$this->assertTrue( $this->http_calls[ count( $this->http_calls ) - 1 ][1]['sslverify'] );
	}

	public function test_a_failed_preflight_stops_all_further_requests() {
		$this->mock_http(
			function () {
				return new \WP_Error( 'http_request_failed', 'cURL error 7: connection refused' );
			}
		);
		$probe = new Http_Probe();
		for ( $i = 0; $i < 5; $i++ ) {
			$response = $probe->request( 'GET', home_url( '/page' . $i ) );
			$this->assertFalse( $response['ok'] );
			$this->assertStringContainsString( 'loopback_unavailable', $response['error'] );
		}
		$this->assertCount( 1, $this->http_calls, 'One failed preflight, then nothing: no waiting for N timeouts.' );
	}

	public function test_the_request_count_is_capped() {
		$this->ok();
		$probe = new Http_Probe();
		$last  = null;
		for ( $i = 0; $i < Http_Probe::MAX_REQUESTS + 10; $i++ ) {
			$last = $probe->request( 'POST', home_url( '/' . $i ), array( 'body' => 'x' ) );
		}
		$this->assertSame( 'request_cap_reached', $last['error'] );
		$this->assertLessThanOrEqual( Http_Probe::MAX_REQUESTS, count( $this->http_calls ) );
		$this->assertSame( Http_Probe::MAX_REQUESTS, $probe->requests_made() );
	}

	public function test_the_total_time_budget_is_enforced() {
		$this->ok();
		$probe = new Http_Probe( 2.0 );
		$this->assertTrue( $probe->request( 'GET', home_url( '/' ) )['ok'] );
		usleep( 1150000 );
		$this->assertLessThan( 1.0, $probe->remaining(), 'Less than a second left: no new request may start.' );
		$late = $probe->request( 'POST', home_url( '/late' ), array( 'body' => 'x' ) );
		$this->assertSame( 'time_budget_exceeded', $late['error'] );
	}

	public function test_identical_get_requests_are_made_once() {
		$this->ok();
		$probe = new Http_Probe();
		$probe->request( 'GET', home_url( '/same' ) );
		$probe->request( 'GET', home_url( '/same' ) );
		$probe->request( 'GET', home_url( '/same' ) );
		$urls = array_column( $this->http_calls, 0 );
		$this->assertSame( 1, count( array_keys( $urls, home_url( '/same' ), true ) ) );
	}

	public function test_the_front_page_fetched_by_the_preflight_is_reused() {
		$this->ok();
		$probe = new Http_Probe();
		$probe->preflight();
		$probe->request( 'GET', home_url( '/' ) );
		$this->assertCount( 1, $this->http_calls, 'The preflight response doubles as the front-page fetch.' );
	}

	public function test_headers_are_lower_cased_and_bodies_capped() {
		$this->mock_http(
			function () {
				return $this->http_response(
					200,
					str_repeat( 'x', Http_Probe::MAX_BODY + 5000 ),
					array(
						'Content-Type' => 'text/html',
						'X-Pingback'   => 'a',
					)
				);
			}
		);
		$response = ( new Http_Probe() )->request( 'GET', home_url( '/' ) );
		$this->assertSame( 'text/html', $response['headers']['content-type'] );
		$this->assertLessThanOrEqual( Http_Probe::MAX_BODY, strlen( $response['body'] ) );
	}

	/** ---------------------------------------------------------------- authenticated session */

	public function test_a_session_is_attached_only_for_a_logged_in_administrator_with_a_cookie() {
		$probe = new Http_Probe();
		$this->assertFalse( $probe->attach_current_session(), 'Nobody logged in.' );

		$this->login_as( 'subscriber' );
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'subscriber-cookie';
		$this->assertFalse( $probe->attach_current_session(), 'Not an administrator.' );

		$this->login_as( 'administrator' );
		unset( $_COOKIE[ LOGGED_IN_COOKIE ] );
		$this->assertFalse( $probe->attach_current_session(), 'No login cookie in this request (cron, CLI).' );

		$_COOKIE[ LOGGED_IN_COOKIE ] = array( 'not', 'a', 'string' );
		$this->assertFalse( $probe->attach_current_session() );

		$_COOKIE[ LOGGED_IN_COOKIE ] = 'admin|1234|token|hmac';
		$this->assertTrue( $probe->attach_current_session() );
		$this->assertTrue( $probe->has_session() );
	}

	public function test_the_session_is_sent_to_this_site_only_and_never_returned_or_stored() {
		$this->login_as( 'administrator' );
		$_COOKIE[ LOGGED_IN_COOKIE ] = 'admin|SECRET-SESSION-VALUE|token|hmac';
		$this->ok();
		$probe = new Http_Probe();
		$probe->attach_current_session();

		$response = $probe->request( 'GET', home_url( '/?rest_route=/wp/v2/users/me' ), array( 'authenticated' => true ) );
		$sent     = $this->http_calls[ count( $this->http_calls ) - 1 ][1];
		$this->assertSame( LOGGED_IN_COOKIE, $sent['cookies'][0]->name );
		$this->assertNotEmpty( $sent['headers']['X-WP-Nonce'] );
		$this->assertCount( 1, $sent['cookies'], 'Only the one cookie REST authentication needs.' );

		$external = $probe->request( 'GET', 'http://evil.example.com/', array( 'authenticated' => true ) );
		$this->assertFalse( $external['ok'], 'The session can never be sent anywhere else.' );

		$this->assertStringNotContainsString( 'SECRET-SESSION-VALUE', wp_json_encode( $response ), 'The response structure never carries the session.' );
		$this->plugin->logger()->flush();
		$this->assertStringNotContainsString( 'SECRET-SESSION-VALUE', wp_json_encode( array( get_option( 'wp_security_lockdown_audit_log' ), get_option( 'wp_security_lockdown_state' ) ) ) );
	}

	public function test_an_authenticated_request_without_a_session_is_refused() {
		$this->ok();
		$probe = new Http_Probe();
		$this->assertSame( 'no_authenticated_session', $probe->request( 'GET', home_url( '/x' ), array( 'authenticated' => true ) )['error'] );
	}
}
