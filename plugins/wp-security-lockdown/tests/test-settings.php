<?php
/**
 * Settings repository: defaults, sanitization, persistence.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Settings_Repository;

class Test_Settings extends Test_Case {

	public function test_defaults_are_the_secure_baseline() {
		$s = $this->plugin->settings();
		$this->assertTrue( $s->get( 'comments.enabled' ) );
		$this->assertSame( 'block', $s->get( 'xmlrpc.mode' ) );
		$this->assertSame( 'restricted', $s->get( 'rest.mode' ) );
		$this->assertTrue( $s->get( 'login.limiter' ) );
		$this->assertSame( 3, $s->get( 'login.max_attempts' ) );
		$this->assertSame( DAY_IN_SECONDS, $s->get( 'login.window' ) );
		$this->assertSame( DAY_IN_SECONDS, $s->get( 'login.lockout' ) );
		$this->assertSame( 64, $s->get( 'login.min_password_length' ) );
		$this->assertSame( array(), $s->get( 'login.trusted_proxies' ), 'No proxy is trusted unless the administrator says so.' );
		$this->assertSame( '', $s->get( 'login.proxy_header' ) );
		$this->assertFalse( $s->get( 'lifecycle.rollback_on_deactivation' ), 'Deactivation must not undo anything by default.' );
	}

	public function test_update_returns_changed_paths_and_persists() {
		$s       = $this->plugin->settings();
		$changed = $s->update( array( 'rest' => array( 'mode' => 'dashboard_only' ) ) );
		$this->assertSame( array( 'rest.mode' ), $changed );
		$this->assertSame( 'dashboard_only', get_option( Settings_Repository::OPTION )['rest']['mode'] );
		$this->assertSame( array(), $s->update( array( 'rest' => array( 'mode' => 'dashboard_only' ) ) ), 'Saving the same value is a no-op.' );
	}

	public function test_garbage_input_is_coerced_not_trusted() {
		$s = $this->plugin->settings();
		$s->update(
			array(
				'rest'    => array( 'mode' => 'everything-open' ),
				'xmlrpc'  => array( 'mode' => array( 'x' ) ),
				'login'   => array(
					'max_attempts'        => '9999',
					'window'              => -5,
					'lockout'             => 'abc',
					'min_password_length' => 3,
				),
				'unknown' => array( 'evil' => '<script>' ),
			)
		);
		$this->assertSame( 'restricted', $s->get( 'rest.mode' ) );
		$this->assertSame( 'block', $s->get( 'xmlrpc.mode' ) );
		$this->assertSame( 20, $s->get( 'login.max_attempts' ), 'Clamped to the maximum.' );
		$this->assertSame( 60, $s->get( 'login.window' ), 'Clamped to the minimum.' );
		$this->assertSame( DAY_IN_SECONDS, $s->get( 'login.lockout' ), 'Non-numeric falls back to the default.' );
		$this->assertSame( 8, $s->get( 'login.min_password_length' ), 'A positive length below 8 is raised to 8.' );
		$this->assertArrayNotHasKey( 'unknown', get_option( Settings_Repository::OPTION ) );
	}

	public function test_min_password_length_zero_switches_the_policy_off() {
		$this->plugin->settings()->update( array( 'login' => array( 'min_password_length' => 0 ) ) );
		$this->assertFalse( $this->plugin->settings()->control_enabled( 'password_policy' ) );
	}

	public function test_ip_lists_are_validated_normalized_and_bounded() {
		$s = $this->plugin->settings();
		$s->update(
			array(
				'login' => array(
					'allowlist'       => "203.0.113.5\n198.51.100.0/24, not-an-ip, 2001:DB8::/32\n10.0.0.0/33\n203.0.113.5",
					'trusted_proxies' => array_map(
						static function ( $i ) {
							return '10.1.' . $i . '.1';
						},
						range( 0, 99 )
					),
				),
			)
		);
		$this->assertSame( array( '203.0.113.5', '198.51.100.0/24', '2001:db8::/32' ), $s->get( 'login.allowlist' ) );
		$this->assertCount( Settings_Repository::MAX_LIST_ENTRIES, $s->get( 'login.trusted_proxies' ) );
	}

	public function test_proxy_header_is_ignored_without_a_trusted_proxy() {
		$s = $this->plugin->settings();
		$s->update( array( 'login' => array( 'proxy_header' => 'X-Forwarded-For' ) ) );
		$this->assertSame( '', $s->get( 'login.proxy_header' ), 'A forwarded header must never be honoured without an explicit proxy list.' );

		$s->update(
			array(
				'login' => array(
					'trusted_proxies' => '10.0.0.1',
					'proxy_header'    => 'X-Forwarded-For',
				),
			)
		);
		$this->assertSame( 'X-Forwarded-For', $s->get( 'login.proxy_header' ) );

		$s->update( array( 'login' => array( 'proxy_header' => 'X-Not-A-Real-Header' ) ) );
		$this->assertSame( '', $s->get( 'login.proxy_header' ), 'Only known client-IP headers can be configured.' );
	}

	public function test_core_admin_namespaces_cannot_be_made_public() {
		$s = $this->plugin->settings();
		$s->update( array( 'rest' => array( 'public_namespaces' => "wp/v2\nwp-site-health/v1\nBATCH/v1\ncontact-form-7/v1\n../etc\n/wc/store/v1/" ) ) );
		$this->assertSame( array( 'contact-form-7/v1', 'wc/store/v1' ), $s->get( 'rest.public_namespaces' ) );
	}

	public function test_corrupted_stored_option_cannot_break_reads() {
		foreach ( array(
			'a string',
			123,
			null,
			array(
				'rest'  => 'oops',
				'login' => array( 'max_attempts' => array() ),
			),
		) as $bad ) {
			update_option( Settings_Repository::OPTION, $bad );
			$this->plugin->settings()->flush_cache();
			$this->assertSame( 'restricted', $this->plugin->settings()->get( 'rest.mode' ) );
			$this->assertSame( 3, $this->plugin->settings()->get( 'login.max_attempts' ) );
		}
	}

	public function test_fingerprint_changes_when_policy_changes() {
		$s      = $this->plugin->settings();
		$before = $s->fingerprint();
		$s->update( array( 'comments' => array( 'enabled' => false ) ) );
		$this->assertNotSame( $before, $s->fingerprint() );
	}

	public function test_sanitize_callback_runs_on_every_write_once_registered() {
		$this->plugin->register_setting();
		update_option(
			Settings_Repository::OPTION,
			array(
				'login' => array( 'max_attempts' => '9999' ),
				'rest'  => array( 'mode' => 'nope' ),
			)
		);
		$stored = get_option( Settings_Repository::OPTION );
		$this->assertSame( 20, $stored['login']['max_attempts'] );
		$this->assertSame( 'restricted', $stored['rest']['mode'] );
	}
}
