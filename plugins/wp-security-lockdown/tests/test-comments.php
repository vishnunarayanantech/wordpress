<?php
/**
 * Comments, trackbacks and pingbacks.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

class Test_Comments extends Test_Case {

	/** @var int */
	private $post_id;

	public function set_up() {
		parent::set_up();
		update_option( 'default_comment_status', 'open' );
		update_option( 'default_ping_status', 'open' );
		$this->post_id = self::factory()->post->create(
			array(
				'post_status'    => 'publish',
				'comment_status' => 'open',
				'ping_status'    => 'open',
			)
		);
		$this->configure();
	}

	/**
	 * Complete comment data, as real callers (wp-comments-post.php, XML-RPC) pass it to wp_new_comment().
	 */
	private function comment_data( array $overrides = array() ) {
		return array_merge(
			array(
				'comment_post_ID'      => $this->post_id,
				'comment_author'       => 'Visitor',
				'comment_author_email' => 'visitor@example.org',
				'comment_author_url'   => '',
				'comment_content'      => 'hello',
				'comment_type'         => 'comment',
				'comment_parent'       => 0,
				'user_id'              => 0,
				'comment_author_IP'    => '203.0.113.9',
				'comment_agent'        => 'phpunit',
			),
			$overrides
		);
	}

	private function count_comments() {
		return (int) get_comments(
			array(
				'post_id' => $this->post_id,
				'status'  => 'all',
				'count'   => true,
				'type'    => 'all',
			)
		);
	}

	private function rest( $method, $route, array $params = array() ) {
		$request = new \WP_REST_Request( $method, $route );
		foreach ( $params as $key => $value ) {
			$request->set_param( $key, $value );
		}
		return rest_do_request( $request );
	}

	public function test_comments_and_pings_are_closed_even_for_posts_stored_as_open() {
		$this->assertSame( 'open', get_post( $this->post_id )->comment_status, 'The stored post setting is not rewritten (non-destructive).' );
		$this->assertFalse( comments_open( $this->post_id ) );
		$this->assertFalse( pings_open( $this->post_id ) );
	}

	public function test_existing_comments_are_kept_and_remain_readable() {
		$comment_id = self::factory()->comment->create(
			array(
				'comment_post_ID' => $this->post_id,
				'comment_content' => 'old comment',
			)
		);
		$this->assertSame( 1, $this->count_comments() );
		$this->assertSame( 'old comment', get_comment( $comment_id )->comment_content );
		$this->assertSame( 1, (int) get_comments_number( $this->post_id ) );
	}

	public function test_the_front_end_submission_handler_refuses_and_stores_nothing() {
		$result = wp_handle_comment_submission(
			array(
				'comment_post_ID' => $this->post_id,
				'author'          => 'Visitor',
				'email'           => 'visitor@example.org',
				'comment'         => 'Hello there',
			)
		);
		$this->assertWPError( $result );
		$this->assertSame( 'comment_closed', $result->get_error_code() );
		$this->assertSame( 0, $this->count_comments() );
	}

	public function test_wp_new_comment_refuses_every_public_type_even_if_comments_open_were_bypassed() {
		remove_filter( 'comments_open', '__return_false', 999 ); // Simulate another plugin overriding the first layer.
		foreach ( array( 'comment', '', 'trackback', 'pingback', 'review' ) as $type ) {
			$result = wp_new_comment(
				$this->comment_data(
					array(
						'comment_content' => 'type ' . $type,
						'comment_type'    => $type,
					)
				),
				true
			);
			$this->assertWPError( $result, "type '$type' must be refused" );
			$this->assertSame( 'wp_security_lockdown_comments_closed', $result->get_error_code() );
		}
		$this->assertSame( 0, $this->count_comments(), 'Nothing may have been written.' );
	}

	public function test_xmlrpc_style_and_admin_reply_callers_are_covered_by_the_same_choke_point() {
		$this->login_as( 'administrator' );
		$result = wp_new_comment(
			$this->comment_data(
				array(
					'comment_content' => 'admin quick reply',
					'user_id'         => get_current_user_id(),
				)
			),
			true
		);
		$this->assertWPError( $result, 'Even an administrator cannot create a public comment while the policy is on.' );
	}

	public function test_editor_notes_are_not_public_comments_and_stay_available() {
		$this->assertSame( 1, apply_filters( 'pre_comment_approved', 1, array( 'comment_type' => 'note' ) ) );

		$this->login_as( 'administrator' );
		$response = $this->rest(
			'POST',
			'/wp/v2/comments',
			array(
				'post'    => $this->post_id,
				'content' => 'Please rephrase',
				'type'    => 'note',
			)
		);
		$this->assertSame( 201, $response->get_status(), 'Core editorial Notes are a dashboard feature, not public comments.' );
	}

	public function test_rest_comment_creation_is_refused_for_authenticated_users() {
		$this->login_as( 'administrator' );
		$response = $this->rest(
			'POST',
			'/wp/v2/comments',
			array(
				'post'    => $this->post_id,
				'content' => 'rest comment',
			)
		);
		$this->assertSame( 403, $response->get_status() );
		$this->assertSame( 'rest_comment_closed', $response->as_error()->get_error_code() );
		$this->assertSame( 0, $this->count_comments() );
	}

	public function test_rest_has_a_second_layer_that_does_not_depend_on_comments_open() {
		remove_filter( 'comments_open', '__return_false', 999 );
		$this->login_as( 'administrator' );
		$response = $this->rest(
			'POST',
			'/wp/v2/comments',
			array(
				'post'    => $this->post_id,
				'content' => 'rest comment',
			)
		);
		$this->assertSame( 403, $response->get_status(), 'rest_pre_insert_comment must also reject.' );
		$this->assertSame( 0, $this->count_comments() );
	}

	public function test_anonymous_rest_comment_creation_is_refused() {
		wp_set_current_user( 0 );
		add_filter( 'rest_allow_anonymous_comments', '__return_true' ); // Even if some plugin opens it up.
		$response = $this->rest(
			'POST',
			'/wp/v2/comments',
			array(
				'post'         => $this->post_id,
				'content'      => 'anon',
				'author_name'  => 'x',
				'author_email' => 'x@example.org',
			)
		);
		$this->assertGreaterThanOrEqual( 400, $response->get_status() );
		$this->assertSame( 0, $this->count_comments() );
	}

	public function test_moderating_existing_comments_over_rest_still_works() {
		$comment_id = self::factory()->comment->create(
			array(
				'comment_post_ID'  => $this->post_id,
				'comment_approved' => '1',
			)
		);
		$this->login_as( 'administrator' );
		$response = $this->rest( 'POST', '/wp/v2/comments/' . $comment_id, array( 'status' => 'hold' ) );
		$this->assertSame( 200, $response->get_status(), 'Closing comments must not stop moderators managing the existing ones.' );
		$this->assertSame( '0', get_comment( $comment_id )->comment_approved );
	}

	public function test_comments_are_not_deleted_by_applying_or_rolling_back_the_policy() {
		$comment_id = self::factory()->comment->create( array( 'comment_post_ID' => $this->post_id ) );
		$this->plugin->policy()->apply_all();
		$this->plugin->policy()->rollback();
		$this->assertNotNull( get_comment( $comment_id ) );
	}

	public function test_new_content_defaults_to_closed_because_the_persistent_options_are_set() {
		$this->plugin->policy()->apply_all();
		$new = self::factory()->post->create( array( 'post_status' => 'publish' ) );
		$this->assertSame( 'closed', get_post( $new )->comment_status );
		$this->assertSame( 'closed', get_post( $new )->ping_status );
	}

	public function test_the_pingback_header_is_not_advertised() {
		$headers = apply_filters(
			'wp_headers',
			array(
				'X-Pingback'   => 'http://example.org/xmlrpc.php',
				'Content-Type' => 'text/html',
			)
		);
		$this->assertArrayNotHasKey( 'X-Pingback', $headers );
		$this->assertArrayHasKey( 'Content-Type', $headers );
	}

	public function test_switching_the_control_off_removes_every_hook() {
		$this->configure( array( 'comments' => array( 'enabled' => false ) ) );
		foreach ( array( 'comments_open', 'pings_open' ) as $hook ) {
			$this->assertFalse( has_filter( $hook, '__return_false' ), "$hook" );
		}
		$this->assertFalse( has_filter( 'pre_comment_approved', array( $this->module( 'comments_hardening' ), 'reject_public_comment' ) ) );
		$this->assertTrue( comments_open( $this->post_id ), 'The post is open again.' );
		$report = $this->module( 'comments_hardening' )->report()['comments'];
		$this->assertSame( 'disabled', $report['state'] );
	}

	public function test_the_report_distinguishes_configured_enforced_and_drifted() {
		$this->plugin->policy()->apply_all();
		$this->assertSame( 'enforced', $this->module( 'comments_hardening' )->report()['comments']['state'] );

		update_option( 'default_ping_status', 'open' ); // Someone changed a persistent default.
		$report = $this->module( 'comments_hardening' )->report()['comments'];
		$this->assertSame( 'partial', $report['state'], 'Runtime protection is active but a persistent default drifted.' );
		$this->assertStringContainsString( 'default_ping_status', $report['failure_reason'] );
	}

	public function test_a_missing_hook_is_reported_as_failed_not_enforced() {
		remove_filter( 'pings_open', '__return_false', 999 );
		$report = $this->module( 'comments_hardening' )->report()['comments'];
		$this->assertSame( 'failed', $report['state'] );
		$this->assertStringContainsString( 'pings_open', $report['failure_reason'] );
	}

	public function test_verification_in_process_passes_and_detects_a_broken_control() {
		$this->plugin->policy()->apply_all();
		$ok = $this->module( 'comments_hardening' )->verify()['comments'];
		$this->assertSame( 'verified', $ok['status'] );
		$this->assertSame( 'in_process', $ok['method'] );

		remove_filter( 'comments_open', '__return_false', 999 );
		$bad = $this->module( 'comments_hardening' )->verify()['comments'];
		$this->assertSame( 'failed', $bad['status'], 'If comments could be opened, the control must not be reported as working.' );
	}

	public function test_http_verification_requires_a_403_from_the_comment_form_handler() {
		$this->plugin->policy()->apply_all();

		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'wp-comments-post.php' ) ? $this->http_response( 403, 'Sorry, comments are closed for this item.' ) : $this->http_response( 200, '<html></html>' );
			}
		);
		$closed = $this->module( 'comments_hardening' )->verify( new \WP_Security_Lockdown\Http_Probe() )['comments'];
		$this->assertSame( 'verified', $closed['status'] );
		$this->assertSame( 'http_probe', $closed['method'] );

		remove_all_filters( 'pre_http_request' );
		$this->mock_http(
			function ( $url ) {
				return false !== strpos( $url, 'wp-comments-post.php' ) ? $this->http_response( 200, 'Please fill the required fields.' ) : $this->http_response( 200, '<html></html>' );
			}
		);
		$open = $this->module( 'comments_hardening' )->verify( new \WP_Security_Lockdown\Http_Probe() )['comments'];
		$this->assertSame( 'failed', $open['status'], 'A form handler that does not answer 403 means comments are still accepted.' );
	}

	public function test_the_http_probe_never_sends_comment_content() {
		$this->plugin->policy()->apply_all();
		$this->mock_http(
			function () {
				return $this->http_response( 403 );
			}
		);
		$this->module( 'comments_hardening' )->verify( new \WP_Security_Lockdown\Http_Probe() );
		foreach ( $this->http_calls as $call ) {
			if ( false !== strpos( $call[0], 'wp-comments-post.php' ) ) {
				$this->assertSame( '', $call[1]['body']['comment'], 'The probe must never be able to create a comment.' );
			}
		}
		$this->assertNotEmpty( $this->http_calls );
	}
}
