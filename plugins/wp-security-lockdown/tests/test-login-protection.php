<?php
/**
 * Login rate limiting and password policy.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Audit_Logger;
use WP_Security_Lockdown\Modules\Login_Protection;
use WP_Security_Lockdown\Rate_Limiter;
use WP_Security_Lockdown\State_Repository;

class Testable_Login_Protection extends Login_Protection {
	public $kill = false;
	protected function kill_switch() {
		return $this->kill;
	}
}

class Test_Login_Protection extends Test_Case {

	const PASSWORD = 'correct horse battery staple';

	/** @var int Controllable clock for the limiter. */
	private $now = 3000000;

	public function set_up() {
		parent::set_up();
		self::factory()->user->create(
			array(
				'user_login' => 'victim',
				'user_pass'  => self::PASSWORD,
				'role'       => 'subscriber',
			)
		);
		$_SERVER['REMOTE_ADDR'] = '198.51.100.10';
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $GLOBALS['pagenow'] );
		// The shipped defaults are deliberately strict (3 attempts, 24 h, 64 characters); these tests exercise the
		// mechanisms with a moderate policy and test_shipped_defaults_are_the_strict_policy() pins the defaults.
		$this->configure(
			array(
				'login' => array(
					'max_attempts'        => 5,
					'window'              => 900,
					'lockout'             => 900,
					'min_password_length' => 12,
				),
			)
		);
	}

	public function test_shipped_defaults_are_the_strict_policy() {
		$defaults = \WP_Security_Lockdown\Settings_Repository::defaults()['login'];
		$this->assertSame( 3, $defaults['max_attempts'] );
		$this->assertSame( DAY_IN_SECONDS, $defaults['window'] );
		$this->assertSame( DAY_IN_SECONDS, $defaults['lockout'] );
		$this->assertSame( 64, $defaults['min_password_length'] );
	}

	public function tear_down() {
		$_SERVER['REMOTE_ADDR'] = '127.0.0.1';
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CF_CONNECTING_IP'], $_POST['pass1'], $GLOBALS['pagenow'] );
		parent::tear_down();
	}

	private function login_module() {
		return $this->module( 'login_protection' );
	}

	/**
	 * Forget the per-request client assessment (a request has one client; a test pretends to be several).
	 */
	private function new_client( $ip, array $server = array() ) {
		$_SERVER['REMOTE_ADDR'] = $ip;
		foreach ( array( 'HTTP_X_FORWARDED_FOR', 'HTTP_CF_CONNECTING_IP' ) as $key ) {
			unset( $_SERVER[ $key ] );
		}
		foreach ( $server as $key => $value ) {
			$_SERVER[ $key ] = $value;
		}
		$property = new \ReflectionProperty( Login_Protection::class, 'subject' );
		$property->setAccessible( true );
		$property->setValue( $this->login_module(), null );
	}

	/**
	 * Replaces the module's limiter with one driven by $this->now.
	 */
	private function use_clock() {
		$property = new \ReflectionProperty( Login_Protection::class, 'limiter' );
		$property->setAccessible( true );
		$property->setValue(
			$this->login_module(),
			new Rate_Limiter(
				5,
				900,
				900,
				function () {
					return $this->now;
				}
			)
		);
	}

	private function attempt( $user, $password ) {
		return wp_authenticate( $user, $password );
	}

	private function fail_times( $times, $user = 'victim' ) {
		$last = null;
		for ( $i = 0; $i < $times; $i++ ) {
			$last = $this->attempt( $user, 'wrong password ' . $i );
		}
		return $last;
	}

	private function code( $result ) {
		return is_wp_error( $result ) ? $result->get_error_code() : 'ok';
	}

	/** ---------------------------------------------------------------- locking */

	public function test_the_client_is_locked_after_the_threshold_and_not_before() {
		for ( $i = 1; $i <= 5; $i++ ) {
			$this->assertSame( 'incorrect_password', $this->code( $this->attempt( 'victim', 'wrong' ) ), "attempt $i is an ordinary failure" );
		}
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', 'wrong' ) ), 'attempt 6 is blocked' );
	}

	public function test_a_correct_password_is_refused_while_locked() {
		$this->fail_times( 5 );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', self::PASSWORD ) ), 'An attacker must not learn that a guess was right during a lock.' );
	}

	public function test_a_correct_password_works_before_the_lock() {
		$this->fail_times( 4 );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );
	}

	public function test_the_lock_message_is_the_same_for_real_and_unknown_users() {
		$this->fail_times( 5, 'no_such_user' );
		$real    = $this->attempt( 'victim', 'x' );
		$unknown = $this->attempt( 'another_unknown', 'x' );
		$this->assertSame( $real->get_error_message(), $unknown->get_error_message() );
		$this->assertStringNotContainsString( 'victim', $real->get_error_message() );
		$this->assertStringContainsString( 'minute', $real->get_error_message() );
	}

	public function test_accounts_are_never_locked_only_client_addresses() {
		$this->fail_times( 6 );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', self::PASSWORD ) ) );

		$this->new_client( '203.0.113.99' ); // The real owner, from another network.
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ), 'An attacker cannot lock the legitimate user out of their own account.' );
	}

	public function test_the_lock_expires_by_itself_and_blocked_attempts_do_not_extend_it() {
		$this->use_clock();
		$this->fail_times( 5 );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', 'x' ) ) );

		$this->now += 600;
		$this->fail_times( 20 ); // Keeps hammering while blocked.
		$this->now += 301;       // 901s after the lock was created.
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ), 'No permanent lock: it ended after the configured time despite continued attempts.' );
	}

	public function test_a_successful_login_does_not_reset_the_counter() {
		$this->use_clock();
		$this->fail_times( 4 );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );
		$this->attempt( 'victim', 'wrong' ); // The 5th failure in the window.
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', 'wrong' ) ), 'An attacker with one valid account must not be able to reset the counter between guesses.' );
	}

	public function test_allowlisted_addresses_are_never_blocked() {
		$this->plugin->settings()->update( array( 'login' => array( 'allowlist' => "198.51.100.0/24\n203.0.113.5" ) ) );
		$this->reload_plugin();
		$this->configure();
		$this->new_client( '198.51.100.10' );

		$this->fail_times( 15 );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );
		$this->assertSame( 0, ( new Rate_Limiter( 5, 900, 900 ) )->snapshot()['tracked'], 'Allowlisted clients are not even tracked.' );
	}

	public function test_forged_forwarding_headers_do_not_evade_the_limit() {
		for ( $i = 1; $i <= 5; $i++ ) {
			$_SERVER['HTTP_X_FORWARDED_FOR'] = '203.0.113.' . $i; // A different identity every time.
			$this->new_client( '198.51.100.10', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.' . $i ) );
			$this->attempt( 'victim', 'wrong' );
		}
		$this->new_client( '198.51.100.10', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.250' ) );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', 'wrong' ) ), 'The connecting address is what counts; client-supplied headers are ignored.' );
	}

	/** ---------------------------------------------------------------- proxies */

	public function test_behind_an_unconfigured_proxy_the_limiter_fails_open_and_the_dashboard_says_so() {
		$this->new_client( '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) );
		$result = $this->fail_times( 30 );
		$this->assertSame( 'incorrect_password', $this->code( $result ), 'Every visitor shares the proxy address: locking it would lock everyone out.' );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );

		$noted = $this->plugin->state()->get( 'proxy_degraded' );
		$this->assertSame( 'unconfigured_proxy', $noted['reason'] );

		$report = $this->login_module()->report()['login_limiter'];
		$this->assertSame( 'partial', $report['state'], 'A limiter that is not counting must not be reported as enforced.' );
		$this->assertNotSame( '', $report['manual_action'] );
		$this->assertStringContainsString( 'NOT counting', $report['failure_reason'] );
	}

	public function test_a_trusted_proxy_lets_the_limiter_tell_clients_apart() {
		$this->plugin->settings()->update(
			array(
				'login' => array(
					'trusted_proxies' => '10.0.0.5',
					'proxy_header'    => 'X-Forwarded-For',
				),
			)
		);
		$this->reload_plugin();
		$this->configure();

		$this->new_client( '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.7' ) );
		$this->fail_times( 5 );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', 'x' ) ), 'Client .7 is locked.' );

		$this->new_client( '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.8' ) );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ), 'Client .8 behind the same proxy is unaffected.' );

		$this->new_client( '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '1.1.1.1, 203.0.113.7' ) );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', self::PASSWORD ) ), 'A forged left-hand entry cannot shed the lock.' );
	}

	public function test_a_trusted_proxy_that_sends_no_header_makes_the_limiter_fail_open() {
		$this->plugin->settings()->update(
			array(
				'login' => array(
					'trusted_proxies' => '10.0.0.5',
					'proxy_header'    => 'X-Forwarded-For',
				),
			)
		);
		$this->reload_plugin();
		$this->configure();
		$this->new_client( '10.0.0.5' );

		$this->fail_times( 12 );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ), 'Do not lock the proxy\'s own address.' );
		$this->assertSame( 'proxy_header_unusable', $this->plugin->state()->get( 'proxy_degraded' )['reason'] );
	}

	/**
	 * Declares a trusted proxy the way the settings screen does, then rebuilds the plugin like the next request would.
	 */
	private function declare_proxy( $header ) {
		$this->plugin->settings()->update(
			array(
				'login' => array(
					'trusted_proxies' => '10.0.0.5',
					'proxy_header'    => $header,
				),
			)
		);
		$this->reload_plugin();
		$this->configure();
	}

	public function test_a_degraded_record_still_counts_while_the_proxy_settings_are_unchanged() {
		$this->new_client( '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) );
		$this->fail_times( 3 );

		// The administrator's own request comes from a public address and is not degraded, but visitors behind the proxy are.
		$this->new_client( '198.51.100.10' );
		$report = $this->login_module()->report()['login_limiter'];
		$this->assertSame( 'partial', $report['state'], 'Earlier evidence that the limiter is not counting must not be forgotten while nothing was fixed.' );
		$this->assertStringContainsString( 'not configured as trusted', $report['failure_reason'], 'The explanation must match what was observed.' );
	}

	public function test_a_degraded_record_made_before_the_proxy_settings_changed_is_not_blamed_on_the_new_setup() {
		$this->new_client( '10.0.0.5', array( 'HTTP_X_FORWARDED_FOR' => '203.0.113.9' ) );
		$this->fail_times( 3 );
		$this->assertSame( 'partial', $this->login_module()->report()['login_limiter']['state'] );

		$this->declare_proxy( 'X-Forwarded-For' );
		$this->new_client( '198.51.100.10' );

		$this->assertSame( 'enforced', $this->login_module()->report()['login_limiter']['state'], 'The record describes a configuration that no longer exists; the dashboard must not keep warning about it.' );
	}

	public function test_a_missing_header_record_is_dropped_when_the_header_setting_changes() {
		$this->declare_proxy( 'X-Forwarded-For' );
		$this->new_client( '10.0.0.5' );
		$this->fail_times( 3 );

		$this->new_client( '198.51.100.10' );
		$report = $this->login_module()->report()['login_limiter'];
		$this->assertSame( 'partial', $report['state'] );
		$this->assertStringContainsString( 'configured trusted proxy', $report['failure_reason'] );

		$this->declare_proxy( 'CF-Connecting-IP' );
		$this->new_client( '198.51.100.10' );
		$this->assertSame( 'enforced', $this->login_module()->report()['login_limiter']['state'] );
	}

	public function test_a_degraded_record_without_a_scope_from_an_older_version_is_ignored() {
		$this->plugin->state()->set(
			'proxy_degraded',
			array(
				'time'   => time(),
				'reason' => 'proxy_header_unusable',
			)
		);
		$this->new_client( '198.51.100.10' );
		$this->assertSame( 'enforced', $this->login_module()->report()['login_limiter']['state'] );
	}

	public function test_noting_a_degraded_proxy_is_throttled_per_configuration() {
		$state = $this->plugin->state();
		$old   = time() - 600;
		$state->set(
			'proxy_degraded',
			array(
				'time'   => $old,
				'reason' => 'unconfigured_proxy',
				'scope'  => 'aaaa',
			)
		);

		$state->note_proxy_degraded( 'unconfigured_proxy', 'aaaa' );
		$this->assertSame( $old, $state->get( 'proxy_degraded' )['time'], 'The same observation within the hour is not written again.' );

		$state->note_proxy_degraded( 'unconfigured_proxy', 'bbbb' );
		$noted = $state->get( 'proxy_degraded' );
		$this->assertSame( 'bbbb', $noted['scope'], 'A new configuration is recorded immediately.' );
		$this->assertGreaterThan( $old, $noted['time'] );
	}

	public function test_a_visitor_with_a_public_address_is_limited_even_if_a_proxy_header_is_present_but_untrusted() {
		$this->new_client( '198.51.100.10', array( 'HTTP_CF_CONNECTING_IP' => '9.9.9.9' ) );
		$this->fail_times( 5 );
		$this->assertSame( Login_Protection::LOCKED_CODE, $this->code( $this->attempt( 'victim', 'x' ) ) );
	}

	/** ---------------------------------------------------------------- responses */

	public function test_the_login_page_answers_429_with_retry_after_only_there() {
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
		$this->fail_times( 5 );

		$this->attempt( 'victim', 'x' );
		$this->assertNotContains( 429, $codes, 'Outside wp-login.php (XML-RPC, REST, wp_signon callers) no HTTP status is forced.' );

		$GLOBALS['pagenow'] = 'wp-login.php';
		$this->attempt( 'victim', 'x' );
		$this->assertContains( 429, $codes );
	}

	public function test_the_lock_error_has_a_stable_code_for_integrations() {
		$this->fail_times( 5 );
		$this->assertSame( 'wp_security_lockdown_locked', $this->attempt( 'victim', 'x' )->get_error_code() );
	}

	/** ---------------------------------------------------------------- privacy and secrets */

	public function test_usernames_passwords_and_addresses_never_reach_storage_or_logs() {
		// People sometimes type their PASSWORD into the user name field.
		for ( $i = 0; $i < 6; $i++ ) {
			$this->attempt( 'Hunter2-Is-My-Password!', 'Another-Secret-' . $i );
		}
		$this->plugin->logger()->flush();

		global $wpdb;
		$dump = wp_json_encode( $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE '%wp_security_lockdown%'", ARRAY_A ) );
		foreach ( array( 'Hunter2', 'Another-Secret', '198.51.100.10', 'victim' ) as $needle ) {
			$this->assertStringNotContainsString( $needle, $dump, "'$needle' must not be stored by the plugin" );
		}
		$this->assertContains( 'login_lockout', array_column( $this->plugin->logger()->entries( 20 ), 'e' ), 'The lockout itself is logged.' );
	}

	public function test_lockout_logging_is_throttled_and_uses_anonymized_addresses() {
		$this->fail_times( 5 );
		$this->new_client( '198.51.100.20' );
		$this->fail_times( 5 );
		$this->new_client( '198.51.100.30' );
		$this->fail_times( 5 );

		$entries = array_filter(
			$this->plugin->logger()->entries( 50 ),
			static function ( $entry ) {
				return 'login_lockout' === $entry['e'];
			}
		);
		$this->assertCount( 1, $entries, 'A distributed attack must not be able to flood the log.' );
		$this->assertSame( '198.51.100.0', array_values( $entries )[0]['c']['client'], 'The stored address is anonymized.' );
	}

	/** ---------------------------------------------------------------- switches */

	public function test_the_emergency_override_switches_the_limiter_off() {
		$module       = new Testable_Login_Protection( $this->plugin );
		$module->kill = true;
		$this->strip_plugin_hooks();
		$module->register();

		$this->assertFalse( has_filter( 'authenticate', array( $module, 'enforce_lock' ) ) );
		$this->fail_times( 20 );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ), 'The documented recovery path works even for a client that was locked.' );

		$report = $module->report()['login_limiter'];
		$this->assertSame( 'disabled', $report['state'] );
		$this->assertStringContainsString( 'WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER', implode( ' ', $report['warnings'] ) );
	}

	public function test_switching_the_limiter_off_in_the_policy_registers_nothing() {
		$this->configure( array( 'login' => array( 'limiter' => false ) ) );
		$this->assertFalse( has_filter( 'authenticate', array( $this->login_module(), 'enforce_lock' ) ) );
		$this->assertFalse( has_action( 'wp_login_failed', array( $this->login_module(), 'record_failure' ) ) );
		$this->fail_times( 20 );
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );
	}

	public function test_registering_the_modules_does_not_touch_the_database() {
		global $wpdb;
		$this->plugin->settings()->all();
		$this->strip_plugin_hooks();
		$before = $wpdb->num_queries;
		$this->plugin->policy()->register_modules();
		$this->assertSame( $before, $wpdb->num_queries, 'Hook registration must be free: it runs on every request.' );
	}

	/** ---------------------------------------------------------------- password policy */

	public function test_short_new_passwords_are_rejected_on_the_profile_screens() {
		$errors = new \WP_Error();
		$this->login_module()->check_profile_password( $errors, true, (object) array( 'user_pass' => 'short' ) );
		$this->assertContains( 'pass', $errors->get_error_codes() );

		$ok = new \WP_Error();
		$this->login_module()->check_profile_password( $ok, true, (object) array( 'user_pass' => 'a-sufficiently-long-passphrase' ) );
		$this->assertFalse( $ok->has_errors() );

		$unchanged = new \WP_Error();
		$this->login_module()->check_profile_password( $unchanged, true, (object) array( 'user_pass' => '' ) );
		$this->assertFalse( $unchanged->has_errors(), 'Saving a profile without touching the password must not complain.' );
	}

	public function test_the_wordpress_user_edit_flow_uses_the_check() {
		$this->login_as( 'administrator' );
		$_POST = array(
			'user_login' => 'newbie',
			'email'      => 'newbie@example.org',
			'pass1'      => 'short',
			'pass2'      => 'short',
			'role'       => 'subscriber',
		);
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$result = edit_user();
		$this->assertWPError( $result );
		$this->assertContains( 'pass', $result->get_error_codes() );
		$_POST = array();
	}

	public function test_short_passwords_are_rejected_on_the_reset_form() {
		$errors         = new \WP_Error();
		$_POST['pass1'] = 'tiny';
		do_action( 'validate_password_reset', $errors, get_user_by( 'login', 'victim' ) );
		$this->assertContains( 'password_too_short', $errors->get_error_codes() );

		$errors         = new \WP_Error();
		$_POST['pass1'] = 'a-sufficiently-long-passphrase';
		do_action( 'validate_password_reset', $errors, get_user_by( 'login', 'victim' ) );
		$this->assertFalse( $errors->has_errors() );
	}

	public function test_short_passwords_are_rejected_over_rest() {
		$this->login_as( 'administrator' );
		$request = new \WP_REST_Request( 'POST', '/wp/v2/users' );
		$request->set_body_params(
			array(
				'username' => 'restuser',
				'email'    => 'rest@example.org',
				'password' => 'short',
			)
		);
		$response = rest_do_request( $request );
		$this->assertSame( 400, $response->get_status() );
		$this->assertSame( 'rest_user_invalid_password', $response->as_error()->get_error_code() );

		$request->set_body_params(
			array(
				'username' => 'restuser2',
				'email'    => 'rest2@example.org',
				'password' => 'a-sufficiently-long-passphrase',
			)
		);
		$this->assertSame( 201, rest_do_request( $request )->get_status() );
	}

	public function test_length_is_counted_in_characters_not_bytes() {
		$this->assertNull( $this->login_module()->password_error( str_repeat( "\u{1F512}", 12 ) ), '12 characters are 12 characters even though they are 48 bytes.' );
		$this->assertNotNull( $this->login_module()->password_error( str_repeat( "\u{1F512}", 11 ) ) );
	}

	public function test_the_minimum_length_is_configurable_and_zero_turns_it_off() {
		$this->configure( array( 'login' => array( 'min_password_length' => 20 ) ) );
		$this->assertNotNull( $this->login_module()->password_error( str_repeat( 'a', 19 ) ) );
		$this->assertNull( $this->login_module()->password_error( str_repeat( 'a', 20 ) ) );

		$this->configure( array( 'login' => array( 'min_password_length' => 0 ) ) );
		$this->assertFalse( has_action( 'user_profile_update_errors', array( $this->login_module(), 'check_profile_password' ) ) );
	}

	/** ---------------------------------------------------------------- reporting and verification */

	public function test_the_report_shows_counts_but_never_other_clients_addresses() {
		$others = array( '203.0.113.77', '198.51.100.222' );
		foreach ( $others as $ip ) {
			$this->new_client( $ip );
			$this->fail_times( 5 );
		}
		$this->new_client( '198.51.100.10' ); // The administrator looking at the dashboard.

		$report = $this->login_module()->report()['login_limiter'];
		$this->assertSame( 'enforced', $report['state'] );
		$details = array_column( $report['details'], 'text', 'label' );
		$this->assertSame( '2 / 2', $details['Tracked / locked clients now'] );
		$this->assertStringContainsString( '198.51.100.10', $details['Client address for this request'], 'The viewer sees their own address, which helps them configure proxies.' );

		$dump = wp_json_encode( $report );
		foreach ( $others as $ip ) {
			$this->assertStringNotContainsString( $ip, $dump );
			$this->assertStringNotContainsString( \WP_Security_Lockdown\Client_IP::bucket_key( $ip ), $dump );
		}
	}

	public function test_self_test_verification_passes_and_cannot_pass_with_the_hooks_missing() {
		$results = $this->login_module()->verify();
		$this->assertSame( 'verified', $results['login_limiter']['status'] );
		$this->assertSame( 'self_test', $results['login_limiter']['method'] );
		$this->assertStringContainsString( 'No real login attempts', $results['login_limiter']['detail'] );
		$this->assertSame( 'verified', $results['password_policy']['status'] );
		$this->assertSame( 0, ( new Rate_Limiter( 5, 900, 900 ) )->snapshot()['tracked'], 'The self-test cleans up after itself.' );

		$this->strip_plugin_hooks();
		$broken = $this->login_module()->verify();
		$this->assertSame( 'failed', $broken['login_limiter']['status'] );
		$this->assertSame( 'failed', $broken['password_policy']['status'] );
	}

	public function test_the_self_test_never_counts_against_the_real_client() {
		$this->login_module()->verify();
		$this->login_module()->verify();
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );
		$this->assertSame(
			array(
				'tracked' => 0,
				'locked'  => 0,
			),
			( new Rate_Limiter( 5, 900, 900 ) )->snapshot()
		);
	}

	public function test_the_dashboard_can_clear_all_lockouts() {
		$this->fail_times( 5 );
		$this->assertSame( 1, ( new Rate_Limiter( 5, 900, 900 ) )->snapshot()['locked'] );
		Rate_Limiter::clear_all();
		$this->assertInstanceOf( \WP_User::class, $this->attempt( 'victim', self::PASSWORD ) );
	}
}
