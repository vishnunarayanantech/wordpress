<?php
/**
 * Administration screen: authorization, nonces, escaping, Settings API, rollback UI.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Activator;
use WP_Security_Lockdown\Admin\Admin;
use WP_Security_Lockdown\Audit_Logger;
use WP_Security_Lockdown\Rate_Limiter;
use WP_Security_Lockdown\Settings_Repository;
use WP_Security_Lockdown\State_Repository;

class Testable_Admin extends Admin {
	protected function terminate() {
		throw new Terminated( 'exit' );
	}
}

class Test_Admin extends Test_Case {

	/** @var Testable_Admin */
	private $admin;

	/** @var string|null Location a redirect would have gone to. */
	private $redirect;

	/** @var int */
	private $admin_id;

	/** @var int */
	private $subscriber_id;

	public function set_up() {
		parent::set_up();
		$this->admin_id      = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$this->subscriber_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		$this->admin         = new Testable_Admin( $this->plugin );
		$this->redirect      = null;
		add_filter(
			'wp_redirect',
			function ( $location ) {
				$this->redirect = $location;
				return false; // Do not actually redirect.
			}
		);
		$this->configure();
	}

	public function tear_down() {
		$_POST                     = array();
		$_GET                      = array();
		$_REQUEST                  = array();
		$_SERVER['REQUEST_METHOD'] = 'GET';
		parent::tear_down();
	}

	/**
	 * Prepares a form submission as a given user.
	 */
	private function submit( $user_id, $action, array $extra = array(), $nonce_action = null, $method = 'POST' ) {
		wp_set_current_user( $user_id );
		$_POST                     = array_merge(
			array(
				'action'   => $action,
				'_wpnonce' => wp_create_nonce( null === $nonce_action ? $action : $nonce_action ),
			),
			$extra
		);
		$_REQUEST                  = $_POST;
		$_SERVER['REQUEST_METHOD'] = $method;
	}

	/**
	 * Runs a handler; returns 'done' when it finished by redirecting, or the WPDieException.
	 */
	private function invoke_handler( $method ) {
		try {
			$this->admin->$method();
		} catch ( Terminated $e ) {
			return 'done';
		} catch ( \WPDieException $e ) {
			return $e;
		}
		return 'returned';
	}

	private function render( $tab = 'overview' ) {
		$_GET['tab'] = $tab;
		ob_start();
		$this->admin->render();
		return ob_get_clean();
	}

	public function actions() {
		return array(
			'verify'   => array( 'wp_security_lockdown_verify', 'handle_verify' ),
			'apply'    => array( 'wp_security_lockdown_apply', 'handle_apply' ),
			'rollback' => array( 'wp_security_lockdown_rollback', 'handle_rollback' ),
			'clear'    => array( 'wp_security_lockdown_clear_lockouts', 'handle_clear_lockouts' ),
		);
	}

	/** ---------------------------------------------------------------- authorization */

	public function test_every_state_changing_action_is_an_admin_post_handler() {
		$this->admin->register();
		foreach ( $this->actions() as $set ) {
			$this->assertNotFalse( has_action( 'admin_post_' . $set[0] ), $set[0] );
		}
		$this->assertFalse( has_action( 'admin_post_nopriv_wp_security_lockdown_verify' ), 'Never reachable by logged-out visitors.' );
		$this->assertFalse( has_action( 'wp_ajax_nopriv_wp_security_lockdown_verify' ) );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_a_get_request_cannot_change_anything( $action, $method ) {
		$this->submit( $this->admin_id, $action, array(), null, 'GET' );
		$result = $this->invoke_handler( $method );
		$this->assertInstanceOf( \WPDieException::class, $result );
		$this->assertSame( 405, $result->getCode() );
		$this->assertNull( $this->redirect );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_a_user_without_the_capability_is_refused_even_with_a_valid_nonce( $action, $method ) {
		$this->submit( $this->subscriber_id, $action );
		$result = $this->invoke_handler( $method );
		$this->assertInstanceOf( \WPDieException::class, $result );
		$this->assertSame( 403, $result->getCode() );
		$this->assertStringContainsString( 'not allowed', $result->getMessage(), 'Authorization is checked first, so a valid nonce is never a substitute for it.' );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_authorization_comes_before_the_nonce_so_outsiders_learn_nothing_about_nonces( $action, $method ) {
		$this->submit( $this->subscriber_id, $action );
		unset( $_POST['_wpnonce'], $_REQUEST['_wpnonce'] ); // No nonce at all.
		$result = $this->invoke_handler( $method );
		$this->assertInstanceOf( \WPDieException::class, $result );
		$this->assertStringContainsString( 'not allowed', $result->getMessage(), 'An unauthorized user is told only that they are not allowed, never whether their nonce was valid.' );
		$this->assertStringNotContainsString( 'expired', $result->getMessage() );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_a_logged_out_visitor_is_refused( $action, $method ) {
		$this->submit( 0, $action );
		$result = $this->invoke_handler( $method );
		$this->assertInstanceOf( \WPDieException::class, $result );
		$this->assertSame( 403, $result->getCode() );
	}

	/**
	 * @dataProvider actions
	 */
	public function test_an_administrator_still_needs_a_valid_nonce( $action, $method ) {
		$this->submit( $this->admin_id, $action );
		unset( $_POST['_wpnonce'], $_REQUEST['_wpnonce'] );
		$missing = $this->invoke_handler( $method );
		$this->assertInstanceOf( \WPDieException::class, $missing );
		$this->assertSame( 403, $missing->getCode() );
		$this->assertStringContainsString( 'expired', $missing->getMessage() );

		$_POST['_wpnonce']    = 'deadbeef00';
		$_REQUEST['_wpnonce'] = 'deadbeef00';
		$this->assertInstanceOf( \WPDieException::class, $this->invoke_handler( $method ), 'A forged nonce is rejected.' );

		$this->submit( $this->admin_id, $action, array(), 'some_other_action' );
		$this->assertInstanceOf( \WPDieException::class, $this->invoke_handler( $method ), 'A nonce for a different action is rejected.' );
		$this->assertNull( $this->redirect );
	}

	public function test_a_nonce_belongs_to_the_user_who_received_it() {
		$this->submit( $this->admin_id, 'wp_security_lockdown_apply' );
		$nonce = $_POST['_wpnonce'];
		$other = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $other );
		$_POST['_wpnonce']    = $nonce;
		$_REQUEST['_wpnonce'] = $nonce;
		$this->assertInstanceOf( \WPDieException::class, $this->invoke_handler( 'handle_apply' ), 'A nonce harvested for another administrator is useless.' );
	}

	public function test_dashboard_pages_require_the_capability() {
		wp_set_current_user( $this->subscriber_id );
		$_GET['tab'] = 'overview';
		try {
			ob_start();
			$this->admin->render();
			ob_end_clean();
			$this->fail( 'A subscriber must not be able to render the dashboard.' );
		} catch ( \WPDieException $e ) {
			ob_end_clean();
			$this->assertSame( 403, $e->getCode() );
		}
	}

	public function test_the_menu_entry_requires_manage_options() {
		wp_set_current_user( $this->admin_id );
		global $submenu;
		$submenu['options-general.php'] = array(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$this->admin->add_menu();
		$entries = array_filter(
			$submenu['options-general.php'],
			static function ( $item ) {
				return Admin::SLUG === $item[2];
			}
		);
		$this->assertCount( 1, $entries );
		$this->assertSame( 'manage_options', array_values( $entries )[0][1] );
	}

	/** ---------------------------------------------------------------- the actions work */

	public function test_apply_reasserts_the_policy_and_redirects_to_the_dashboard() {
		update_option( 'default_comment_status', 'open' );
		$this->submit( $this->admin_id, 'wp_security_lockdown_apply' );
		$this->assertSame( 'done', $this->invoke_handler( 'handle_apply' ) );
		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );
		$this->assertStringStartsWith( admin_url( 'options-general.php' ), $this->redirect );
		$this->assertStringContainsString( 'page=wp-security-lockdown', $this->redirect );
	}

	public function test_rollback_does_not_overwrite_a_newer_change_unless_forced() {
		update_option( 'default_pingback_flag', '1' );
		$this->plugin->policy()->apply_all();
		update_option( 'default_pingback_flag', '5' ); // Changed after the plugin set it.

		$this->submit( $this->admin_id, 'wp_security_lockdown_rollback' );
		$this->assertSame( 'done', $this->invoke_handler( 'handle_rollback' ) );
		$this->assertSame( '5', get_option( 'default_pingback_flag' ), 'A conflict is reported, not overwritten.' );
		$detail = get_transient( 'wp_security_lockdown_rollback_' . $this->admin_id );
		$this->assertSame( array( 'default_pingback_flag' ), $detail['conflicts'] );
		$this->assertStringContainsString( 'rollback', $this->redirect );

		// An array posted as "force" must not count as consent.
		$this->submit( $this->admin_id, 'wp_security_lockdown_rollback', array( 'force' => array( '1' ) ) );
		$this->invoke_handler( 'handle_rollback' );
		$this->assertSame( '5', get_option( 'default_pingback_flag' ) );

		$this->submit( $this->admin_id, 'wp_security_lockdown_rollback', array( 'force' => '1' ) );
		$this->invoke_handler( 'handle_rollback' );
		$this->assertSame( '1', get_option( 'default_pingback_flag' ), 'Explicit consent restores the original.' );
		$this->assertSame( 'open', get_option( 'default_comment_status' ) );
	}

	public function test_clear_lockouts_clears_them() {
		$limiter = new Rate_Limiter( 1, 600, 600 );
		$limiter->record_failure( str_repeat( 'c', 32 ) );
		$this->assertSame( 1, $limiter->snapshot()['locked'] );

		$this->submit( $this->admin_id, 'wp_security_lockdown_clear_lockouts' );
		$this->assertSame( 'done', $this->invoke_handler( 'handle_clear_lockouts' ) );
		$this->assertSame( 0, $limiter->snapshot()['locked'] );
		$this->assertContains( 'lockouts_cleared', array_column( $this->plugin->logger()->entries( 10 ), 'e' ) );
	}

	public function test_verify_runs_the_checks_and_records_the_outcome_even_when_the_network_is_down() {
		$this->mock_http(
			function () {
				return new \WP_Error( 'http_request_failed', 'no network' );
			}
		);
		$this->submit( $this->admin_id, 'wp_security_lockdown_verify' );
		$this->assertSame( 'done', $this->invoke_handler( 'handle_verify' ) );

		$verification = $this->plugin->state()->verification();
		$this->assertSame( 'unverified', $verification['xmlrpc']['status'], 'No loopback means no HTTP verification, and it is not faked.' );
		$this->assertNotEmpty( $this->plugin->state()->get( 'checks' )['rows'] );
		$own = array_filter(
			$this->http_calls,
			static function ( $call ) {
				return false === strpos( $call[0], 'api.wordpress.org' ); // Core's own PHP-support lookup is a different matter.
			}
		);
		$this->assertCount( 1, $own, 'After the failed preflight no further requests to this site are made.' );
	}

	/** ---------------------------------------------------------------- rendering */

	public function test_every_tab_renders_with_the_expected_structure() {
		wp_set_current_user( $this->admin_id );
		foreach ( Admin::TABS as $tab ) {
			$html = $this->render( $tab );
			$this->assertStringContainsString( '<div class="wrap wp-security-lockdown">', $html, $tab );
			$this->assertStringContainsString( 'nav-tab-active', $html );
			$this->assertDoesNotMatchRegularExpression( '/(Warning|Notice|Fatal error|Deprecated):/', $html, $tab );
		}
	}

	public function test_an_unknown_or_hostile_tab_falls_back_to_the_overview() {
		wp_set_current_user( $this->admin_id );
		foreach ( array( '../../wp-config', 'overview/../../x', '<script>', 'settings.php', '' ) as $tab ) {
			$html = $this->render( $tab );
			$this->assertStringContainsString( 'Run verification and diagnostics', $html );
			$this->assertStringNotContainsString( 'Policy settings', strip_tags( substr( $html, strpos( $html, '</nav>' ) ) ) );
		}
	}

	public function test_the_overview_never_calls_an_unverified_site_protected() {
		wp_set_current_user( $this->admin_id );
		$html = $this->render( 'overview' );
		$this->assertStringContainsString( 'not yet proven', $html );
		$this->assertStringNotContainsString( 'Every enabled control is enforced and verified', $html );
	}

	public function test_all_green_controls_do_not_hide_open_findings() {
		wp_set_current_user( $this->admin_id );
		$verification = array();
		foreach ( array_keys( $this->plugin->policy()->reports() ) as $id ) {
			$verification[ $id ] = array(
				'status' => 'verified',
				'method' => 'http_probe',
				'detail' => 'x',
			);
		}
		$this->plugin->state()->record_verification( $verification, $this->plugin->settings()->fingerprint() );

		$html = $this->render( 'overview' );
		if ( false !== strpos( $html, 'Every enabled control is enforced and verified, but' ) ) {
			$this->assertStringContainsString( 'finding', $html );
		} else {
			$this->assertStringNotContainsString( 'and there are no open findings', $html, 'The test environment has open findings (e.g. root database user), so the headline must not be fully green.' );
		}
	}

	public function test_notice_text_comes_from_a_fixed_table_never_from_the_request() {
		wp_set_current_user( $this->admin_id );
		set_transient( 'wp_security_lockdown_notice_' . $this->admin_id, '<img src=x onerror=alert(1)>', 60 );
		$html = $this->render( 'overview' );
		$this->assertStringNotContainsString( 'onerror', $html );

		set_transient( 'wp_security_lockdown_notice_' . $this->admin_id, array( 'x' ), 60 );
		$this->assertStringNotContainsString( 'Array', $this->render( 'overview' ) );

		set_transient( 'wp_security_lockdown_notice_' . $this->admin_id, 'applied', 60 );
		$this->assertStringContainsString( 'The policy was applied', $this->render( 'overview' ) );
		$this->assertFalse( get_transient( 'wp_security_lockdown_notice_' . $this->admin_id ), 'A notice is shown once.' );

		$_GET['notice']  = '<script>alert(1)</script>';
		$_GET['message'] = '<script>alert(1)</script>';
		$this->assertStringNotContainsString( 'alert(1)', $this->render( 'overview' ), 'Query parameters never become page text.' );
	}

	public function test_hostile_data_is_escaped_on_every_tab() {
		wp_set_current_user( $this->admin_id );
		$xss = '"><script>alert("xss")</script><svg onload=alert(1)>';

		update_option(
			Audit_Logger::OPTION,
			array(
				array(
					't' => time(),
					'l' => 'warning',
					'e' => $xss,
					'm' => $xss,
					'c' => array( $xss => $xss ),
				),
				array(
					't' => 'not-a-number',
					'l' => $xss,
					'e' => array( 'array' ),
					'm' => null,
					'c' => 'string',
				),
			)
		);
		$state = array(
			'ledger'       => array(
				$xss => array(
					'control'  => $xss,
					'existed'  => true,
					'original' => $xss,
					'applied'  => $xss,
					'changed'  => true,
					'time'     => 1,
				),
			),
			'verification' => array(
				'comments' => array(
					'status'      => 'verified',
					'method'      => 'in_process',
					'detail'      => $xss,
					'time'        => time(),
					'fingerprint' => $this->plugin->settings()->fingerprint(),
				),
			),
			'checks'       => array(
				'time' => time(),
				'rows' => array(
					array(
						'id'          => 'x',
						'group'       => 'environment',
						'title'       => $xss,
						'status'      => 'fail',
						'summary'     => $xss,
						'remediation' => $xss,
						'requires'    => 'manual',
						'deep'        => true,
					),
				),
			),
		);
		update_option( State_Repository::OPTION, $state );
		$this->reload_plugin();
		$this->configure();
		$this->admin = new Testable_Admin( $this->plugin );
		wp_set_current_user( $this->admin_id );

		foreach ( Admin::TABS as $tab ) {
			$html = $this->render( $tab );
			$this->assertStringNotContainsString( '<script>alert("xss")', $html, "$tab: raw script tag" );
			$this->assertStringNotContainsString( '<svg onload', $html, "$tab: raw svg handler" );
			$this->assertStringNotContainsString( '"><script', $html, "$tab: attribute break-out" );
		}
		$this->assertStringContainsString( '&lt;script&gt;', $this->render( 'audit' ), 'The text is shown, escaped.' );
	}

	public function test_a_corrupted_audit_log_cannot_break_the_audit_tab() {
		wp_set_current_user( $this->admin_id );
		foreach ( array( 'garbage', 5, array( 'x', 1, null, array() ) ) as $bad ) {
			update_option( Audit_Logger::OPTION, $bad );
			$this->assertStringContainsString( 'Audit log', $this->render( 'audit' ) );
		}
	}

	public function test_the_rollback_tab_explains_lifecycle_and_recovery() {
		wp_set_current_user( $this->admin_id );
		$html = $this->render( 'rollback' );
		foreach ( array( 'Stops immediately on deactivation', 'Stays in the database', 'WP_SECURITY_LOCKDOWN_DISABLE', 'WP_SECURITY_LOCKDOWN_DISABLE_LOGIN_LIMITER', 'wp-security-lockdown.off', 'wp plugin deactivate' ) as $needle ) {
			$this->assertStringContainsString( $needle, $html );
		}
	}

	public function test_the_rollback_tab_shows_conflicts_clearly() {
		update_option( 'default_ping_status', 'open' );
		$this->plugin->policy()->apply_all();
		update_option( 'default_ping_status', 'weird' );
		wp_set_current_user( $this->admin_id );

		$html = $this->render( 'rollback' );
		$this->assertStringContainsString( 'default_ping_status', $html );
		$this->assertStringContainsString( 'restoring would overwrite a newer change', $html );
		$this->assertStringContainsString( 'name="force"', $html );
		$this->assertStringContainsString( '_wpnonce', $html );
	}

	/** ---------------------------------------------------------------- Settings API */

	public function test_settings_are_registered_with_the_settings_api() {
		$this->plugin->register_setting();
		$this->admin->register_settings_ui();

		global $wp_settings_sections, $wp_settings_fields;
		$this->assertArrayHasKey( Admin::SLUG, $wp_settings_sections );
		$this->assertGreaterThanOrEqual( 6, count( $wp_settings_sections[ Admin::SLUG ] ) );
		$fields = 0;
		foreach ( $wp_settings_fields[ Admin::SLUG ] as $section ) {
			foreach ( $section as $field ) {
				++$fields;
				$this->assertIsCallable( $field['callback'] );
			}
		}
		$this->assertGreaterThanOrEqual( 18, $fields );

		$registered = get_registered_settings();
		$this->assertSame( array( $this->plugin->settings(), 'sanitize_for_settings_api' ), $registered[ Settings_Repository::OPTION ]['sanitize_callback'] );
		$this->assertFalse( $registered[ Settings_Repository::OPTION ]['show_in_rest'], 'The policy is never exposed through the REST settings endpoint.' );
		$this->assertSame( 'manage_options', apply_filters( 'option_page_capability_' . \WP_Security_Lockdown\Plugin::OPTION_GROUP, 'manage_options' ) );
	}

	public function test_the_settings_tab_renders_inputs_for_the_stored_option_only() {
		$this->plugin->register_setting();
		$this->admin->register_settings_ui();
		wp_set_current_user( $this->admin_id );
		$html = $this->render( 'settings' );

		$this->assertStringContainsString( 'action="options.php"', $html );
		$this->assertMatchesRegularExpression( '/name=[\'"]option_page[\'"] value=[\'"]wp_security_lockdown[\'"]/', $html );
		$this->assertStringContainsString( 'name="wp_security_lockdown_settings[login][max_attempts]"', $html );
		$this->assertStringContainsString( 'name="wp_security_lockdown_settings[rest][mode]"', $html );
		$this->assertStringContainsString( '_wpnonce', $html );
		preg_match_all( '/name="([^"]+)"/', $html, $names );
		foreach ( $names[1] as $name ) {
			if ( 0 === strpos( $name, 'wp_security_lockdown_settings[' ) ) {
				$this->assertMatchesRegularExpression( '/^wp_security_lockdown_settings\[[a-z]+\]\[[a-z_]+\]$/', $name );
			}
		}
	}

	public function test_hostile_form_input_is_sanitized_and_explained() {
		global $wp_settings_errors;
		$wp_settings_errors = array(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited

		$clean = $this->plugin->settings()->sanitize_for_settings_api(
			array(
				'rest'  => array(
					'mode'              => '<script>',
					'public_namespaces' => "wp/v2\ncontact-form-7/v1\n<script>alert(1)</script>",
				),
				'login' => array(
					'max_attempts'    => '5; DROP TABLE wp_users',
					'allowlist'       => "1.2.3.4\n<b>x</b>\n999.1.1.1",
					'proxy_header'    => 'X-Forwarded-For',
					'trusted_proxies' => '',
				),
				'files' => array( 'file_editor' => array( 'x' ) ),
			)
		);
		$this->assertSame( 'restricted', $clean['rest']['mode'] );
		$this->assertSame( array( 'contact-form-7/v1' ), $clean['rest']['public_namespaces'] );
		$this->assertSame( 5, $clean['login']['max_attempts'], 'A non-numeric value falls back to the default.' );
		$this->assertSame( array( '1.2.3.4' ), $clean['login']['allowlist'] );
		$this->assertSame( '', $clean['login']['proxy_header'] );

		$messages = wp_list_pluck( $wp_settings_errors, 'message' );
		$joined   = implode( ' ', $messages );
		$this->assertStringContainsString( 'cannot be made public', $joined );
		$this->assertStringContainsString( 'no trusted proxy', $joined );
		$this->assertStringNotContainsString( '<script>', $joined, 'WordPress prints settings errors as raw HTML, so rejected input must arrive already escaped.' );
		$this->assertStringNotContainsString( '<b>', $joined );
		$this->assertStringContainsString( '&lt;script&gt;', $joined, 'It is still shown, as text.' );
	}

	public function test_the_settings_page_save_path_is_the_sanitizer() {
		$this->plugin->register_setting();
		update_option(
			Settings_Repository::OPTION,
			array(
				'login' => array(
					'allowlist'    => 'not-an-ip',
					'max_attempts' => 999,
				),
			)
		);
		$stored = get_option( Settings_Repository::OPTION );
		$this->assertSame( array(), $stored['login']['allowlist'] );
		$this->assertSame( 20, $stored['login']['max_attempts'] );
	}

	/** ---------------------------------------------------------------- activation notice */

	public function test_the_activation_notice_is_shown_only_to_administrators() {
		set_transient( Activator::NOTICE_TRANSIENT, 1, 60 );
		set_current_screen( 'plugins' );

		wp_set_current_user( $this->subscriber_id );
		ob_start();
		$this->admin->activation_notice();
		$this->assertSame( '', ob_get_clean() );

		wp_set_current_user( $this->admin_id );
		ob_start();
		$this->admin->activation_notice();
		$out = ob_get_clean();
		$this->assertStringContainsString( 'HTTP verification has not run yet', $out );
		$this->assertStringContainsString( 'nothing is reported as verified', $out );
	}
}
