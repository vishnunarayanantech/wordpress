<?php
/**
 * Information disclosure controls.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Modules\Information_Disclosure;

class Testable_Information_Disclosure extends Information_Disclosure {
	public $env = 'production';
	protected function environment_type() {
		return $this->env;
	}
}

class Test_Information_Disclosure extends Test_Case {

	/** @var string|false */
	private $display_errors;

	public function set_up() {
		parent::set_up();
		$this->display_errors = ini_get( 'display_errors' );
		$this->configure();
	}

	public function tear_down() {
		ini_set( 'display_errors', (string) $this->display_errors ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Blacklisted
		unset( $_GET['author'] );
		parent::tear_down();
	}

	private function disclosure() {
		return $this->module( 'information_disclosure' );
	}

	/** ---------------------------------------------------------------- author enumeration */

	private function author_with_post() {
		$author = self::factory()->user->create(
			array(
				'role'       => 'author',
				'user_login' => 'victim_author',
			)
		);
		self::factory()->post->create(
			array(
				'post_author' => $author,
				'post_status' => 'publish',
			)
		);
		return $author;
	}

	private function request_author_query( $value ) {
		$_GET['author'] = $value;
		$this->go_to( home_url( '/?author=' . ( is_array( $value ) ? '1' : $value ) ) );
		$_GET['author'] = $value;
		$this->disclosure()->block_author_query();
	}

	public function test_author_id_probing_gets_a_404_instead_of_a_redirect_to_the_login_name() {
		$this->set_permalink_structure( '/%postname%/' );
		$author = $this->author_with_post();
		wp_set_current_user( 0 );

		$this->request_author_query( (string) $author );
		$this->assertTrue( is_404() );
	}

	public function test_control_experiment_core_would_redirect_to_the_author_archive() {
		$this->set_permalink_structure( '/%postname%/' );
		$author = $this->author_with_post();
		$this->strip_plugin_hooks();
		wp_set_current_user( 0 );
		$this->go_to( home_url( '/?author=' . $author ) );
		$_GET['author'] = (string) $author;
		$redirect       = redirect_canonical( home_url( '/?author=' . $author ), false );
		$this->assertStringContainsString( 'victim_author', (string) $redirect, 'Without the control, ?author=N discloses the login name.' );
	}

	public function test_logged_in_users_are_not_blocked() {
		$this->set_permalink_structure( '/%postname%/' );
		$author = $this->author_with_post();
		$this->login_as( 'subscriber' );
		$this->request_author_query( (string) $author );
		$this->assertFalse( is_404() );
	}

	public function test_plain_permalinks_are_left_alone_because_author_id_is_the_canonical_url() {
		$this->set_permalink_structure( '' );
		$author = $this->author_with_post();
		wp_set_current_user( 0 );
		$this->request_author_query( (string) $author );
		$this->assertFalse( is_404() );
		$report = $this->disclosure()->report()['author_enumeration'];
		$this->assertSame( 'partial', $report['state'], 'The dashboard must say the control cannot fully apply with plain permalinks.' );
	}

	public function test_empty_author_parameter_is_ignored_and_array_is_blocked() {
		$this->set_permalink_structure( '/%postname%/' );
		wp_set_current_user( 0 );
		$this->request_author_query( '' );
		$this->assertFalse( is_404() );
		$this->request_author_query( array( '1' ) );
		$this->assertTrue( is_404() );
	}

	public function test_the_users_sitemap_is_refused_and_other_sitemaps_are_untouched() {
		$this->assertFalse( apply_filters( 'wp_sitemaps_add_provider', 'provider', 'users' ) );
		foreach ( array( 'posts', 'taxonomies' ) as $name ) {
			$this->assertSame( 'provider', apply_filters( 'wp_sitemaps_add_provider', 'provider', $name ) );
		}
	}

	public function test_anonymous_rest_requests_do_not_see_the_users_routes() {
		$routes = array(
			'/wp/v2/users'               => 1,
			'/wp/v2/users/(?P<id>[\d]+)' => 1,
			'/wp/v2/users/me'            => 1,
			'/wp/v2/posts'               => 1,
			'/wp/v2/usersx'              => 1,
		);
		wp_set_current_user( 0 );
		$anon = apply_filters( 'rest_endpoints', $routes );
		$this->assertSame( array( '/wp/v2/posts' ), array_keys( $anon ), 'Everything under /wp/v2/users is hidden from anonymous requests.' );

		$this->login_as( 'subscriber' );
		$this->assertSame( array_keys( $routes ), array_keys( apply_filters( 'rest_endpoints', $routes ) ), 'Logged-in requests (the block editor) keep the routes.' );
	}

	/** ---------------------------------------------------------------- version and discovery */

	public function test_the_wordpress_version_is_masked_in_asset_urls_but_other_versions_are_not() {
		global $wp_version;
		$masked = $this->disclosure()->mask_version( 'http://example.org/wp-includes/js/a.js?ver=' . $wp_version );
		$this->assertStringNotContainsString( $wp_version, $masked );
		$this->assertMatchesRegularExpression( '/\?ver=[0-9a-f]{10}$/', $masked );
		$this->assertSame( $masked, $this->disclosure()->mask_version( 'http://example.org/wp-includes/js/a.js?ver=' . $wp_version ), 'Stable, so caching still works.' );

		$this->assertSame( 'http://example.org/p.js?ver=1.2.3', $this->disclosure()->mask_version( 'http://example.org/p.js?ver=1.2.3' ), 'A plugin\'s own version is not touched.' );
		$this->assertSame( 'http://example.org/p.js', $this->disclosure()->mask_version( 'http://example.org/p.js' ) );
		$relative = $this->disclosure()->mask_version( '/a.js?x=1&ver=' . $wp_version );
		$this->assertStringStartsWith( '/a.js?x=1&ver=', $relative, 'Relative URLs and extra query arguments are handled.' );
		$this->assertStringNotContainsString( $wp_version, $relative );
		$this->assertSame( 42, $this->disclosure()->mask_version( 42 ) );
	}

	public function test_the_masked_value_changes_when_wordpress_is_updated() {
		global $wp_version;
		$original   = $wp_version;
		$a          = $this->disclosure()->mask_version( '/a.js?ver=' . $wp_version );
		$wp_version = '99.0.1'; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$b          = $this->disclosure()->mask_version( '/a.js?ver=99.0.1' );
		$wp_version = $original; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
		$this->assertNotSame( explode( 'ver=', $a )[1], explode( 'ver=', $b )[1], 'Browser caches must still be busted by a core update.' );
	}

	public function test_generator_output_is_removed() {
		$this->assertFalse( has_action( 'wp_head', 'wp_generator' ) );
		$this->assertSame( '', apply_filters( 'the_generator', '<generator>https://wordpress.org/?v=x</generator>', 'rss2' ) );
	}

	public function test_discovery_hooks_are_removed() {
		foreach ( array( array( 'wp_head', 'rest_output_link_wp_head' ), array( 'template_redirect', 'rest_output_link_header' ), array( 'wp_head', 'wp_oembed_add_discovery_links' ), array( 'wp_head', 'wp_shortlink_wp_head' ), array( 'template_redirect', 'wp_shortlink_header' ) ) as $pair ) {
			$this->assertFalse( has_action( $pair[0], $pair[1] ), "{$pair[1]} on {$pair[0]}" );
		}
	}

	public function test_discovery_verification_fails_when_the_core_hooks_are_present() {
		$this->assertSame( 'verified', $this->disclosure()->verify()['discovery']['status'] );
		add_action( 'wp_head', 'rest_output_link_wp_head', 10, 0 ); // A theme or plugin put it back.
		$this->assertSame( 'failed', $this->disclosure()->verify()['discovery']['status'], 'A check that cannot fail would give false assurance.' );
	}

	public function test_version_and_discovery_http_verification_inspects_the_front_page() {
		global $wp_version;
		$page = static function ( $generator, $api ) use ( $wp_version ) {
			return '<html><head>' . ( $generator ? '<meta name="generator" content="WordPress ' . $wp_version . '" />' : '' ) . ( $api ? '<link rel="https://api.w.org/" href="x" />' : '' ) . '</head></html>';
		};

		$this->mock_http(
			function () use ( $page ) {
				return $this->http_response( 200, $page( false, false ) );
			}
		);
		$clean = $this->disclosure()->verify( new Http_Probe() );
		$this->assertSame( 'http_probe', $clean['version_exposure']['method'] );
		$this->assertSame( 'verified', $clean['version_exposure']['status'] );
		$this->assertSame( 'verified', $clean['discovery']['status'] );

		remove_all_filters( 'pre_http_request' );
		$this->mock_http(
			function () use ( $page ) {
				return $this->http_response( 200, $page( true, true ), array( 'link' => '<http://x/wp-json/>; rel="https://api.w.org/"' ) );
			}
		);
		$leaky = $this->disclosure()->verify( new Http_Probe() );
		$this->assertSame( 'failed', $leaky['version_exposure']['status'], 'Another plugin or theme still prints the generator tag.' );
		$this->assertSame( 'failed', $leaky['discovery']['status'] );
	}

	/** ---------------------------------------------------------------- login errors */

	private function login_error_text( \WP_Error $error ) {
		$shown = apply_filters( 'wp_login_errors', $error, '' );
		return wp_strip_all_tags( implode( ' ', $shown->get_error_messages() ) );
	}

	public function test_unknown_user_and_wrong_password_look_identical() {
		self::factory()->user->create(
			array(
				'user_login' => 'real_user',
				'user_pass'  => 'a-correct-long-password',
			)
		);

		$unknown = wp_signon(
			array(
				'user_login'    => 'no_such_user',
				'user_password' => 'x',
			)
		);
		$wrong   = wp_signon(
			array(
				'user_login'    => 'real_user',
				'user_password' => 'wrong',
			)
		);
		$this->assertSame( 'invalid_username', $unknown->get_error_code(), 'Core\'s own errors do differ...' );
		$this->assertSame( 'incorrect_password', $wrong->get_error_code() );

		$this->assertSame( $this->login_error_text( $unknown ), $this->login_error_text( $wrong ), '...but what the visitor is shown must not.' );
		$this->assertStringNotContainsString( 'real_user', $this->login_error_text( $wrong ) );
		$this->assertStringNotContainsString( 'no_such_user', $this->login_error_text( $unknown ) );
	}

	public function test_other_login_messages_are_preserved() {
		$errors = new \WP_Error( 'loggedout', 'You are now logged out.', 'message' );
		$errors->add( 'invalid_email', 'The email x is not registered' );
		$shown = apply_filters( 'wp_login_errors', $errors, '' );
		$this->assertContains( 'loggedout', $shown->get_error_codes() );
		$this->assertStringContainsString( 'You are now logged out.', implode( ' ', $shown->get_error_messages( 'loggedout' ) ) );
		$this->assertNotContains( 'invalid_email', $shown->get_error_codes() );
	}

	public function test_listeners_of_wp_login_failed_still_get_the_detailed_error() {
		$seen = array();
		add_action(
			'wp_login_failed',
			static function ( $username, $error ) use ( &$seen ) {
				$seen[] = $error->get_error_code();
			},
			10,
			2
		);
		wp_authenticate( 'no_such_user', 'x' );
		$this->assertContains( 'invalid_username', $seen, 'Security tooling that logs the real reason keeps working.' );
	}

	public function test_rest_basic_auth_failures_are_generic_and_other_errors_untouched() {
		foreach ( array( 'invalid_username', 'incorrect_password' ) as $code ) {
			$out = apply_filters( 'rest_authentication_errors', new \WP_Error( $code, 'The username bob is not registered', array( 'status' => 401 ) ) );
			$this->assertWPError( $out );
			$this->assertSame( 'incorrect_password', $out->get_error_code() );
			$this->assertStringNotContainsString( 'bob', $out->get_error_message() );
			$this->assertSame( 401, $out->get_error_data()['status'] );
		}
		$nonce = apply_filters( 'rest_authentication_errors', new \WP_Error( 'rest_cookie_invalid_nonce', 'Cookie check failed', array( 'status' => 403 ) ) );
		$this->assertSame( 'rest_cookie_invalid_nonce', $nonce->get_error_code() );
		$this->assertTrue( $this->disclosure()->generic_rest_auth_error( true ), 'A successful authentication result is passed through untouched.' );
		$this->assertNull( $this->disclosure()->generic_rest_auth_error( null ) );
	}

	public function test_login_errors_verification_can_fail() {
		$this->assertSame( 'verified', $this->disclosure()->verify()['login_errors']['status'] );
		$this->strip_plugin_hooks();
		$this->assertSame( 'failed', $this->disclosure()->verify()['login_errors']['status'] );
	}

	/** ---------------------------------------------------------------- error display */

	public function test_display_errors_is_switched_off_for_production_visitors() {
		ini_set( 'display_errors', '1' ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Blacklisted
		$this->assertTrue( Information_Disclosure::display_errors_on() );

		$module = new Testable_Information_Disclosure( $this->plugin );
		$module->register();
		$this->assertFalse( Information_Disclosure::display_errors_on() );
		$this->assertSame( 'verified', $module->verify()['error_display']['status'] );
		$this->assertSame( 'enforced', $module->report()['error_display']['state'] );
	}

	public function test_display_errors_is_left_alone_in_a_developer_environment_and_the_dashboard_says_so() {
		ini_set( 'display_errors', '1' ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Blacklisted
		$module      = new Testable_Information_Disclosure( $this->plugin );
		$module->env = 'local';
		$module->register();
		$this->assertTrue( Information_Disclosure::display_errors_on() );
		$report = $module->report()['error_display'];
		$this->assertSame( 'partial', $report['state'] );
		$this->assertSame( 'unverified', $module->verify()['error_display']['status'] );
	}

	public function test_a_host_that_forces_display_errors_on_is_reported_as_failed_not_enforced() {
		ini_set( 'display_errors', '1' ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Blacklisted
		$module = new Testable_Information_Disclosure( $this->plugin ); // register() deliberately not called: simulates ini_set being ineffective.
		$report = $module->report()['error_display'];
		$this->assertSame( 'failed', $report['state'] );
		$this->assertNotSame( '', $report['manual_action'] );
		$this->assertSame( 'failed', $module->verify()['error_display']['status'] );
	}

	/**
	 * @dataProvider display_errors_values
	 */
	public function test_display_errors_parsing( $value, $expected ) {
		ini_set( 'display_errors', $value ); // phpcs:ignore WordPress.PHP.IniSet.display_errors_Blacklisted
		$this->assertSame( $expected, Information_Disclosure::display_errors_on(), var_export( $value, true ) );
	}

	public function display_errors_values() {
		return array( array( '1', true ), array( 'On', true ), array( 'stdout', true ), array( '0', false ), array( 'Off', false ), array( '', false ), array( 'stderr', false ) );
	}

	/** ---------------------------------------------------------------- reporting */

	public function test_every_control_reports_disabled_when_switched_off_and_registers_nothing() {
		$this->configure(
			array(
				'disclosure' => array(
					'author_enumeration' => false,
					'version'            => false,
					'discovery'          => false,
					'error_display'      => false,
				),
				'login'      => array( 'generic_errors' => false ),
			)
		);
		foreach ( $this->disclosure()->report() as $id => $report ) {
			$this->assertSame( 'disabled', $report['state'], $id );
		}
		$this->assertFalse( has_filter( 'wp_login_errors', array( $this->disclosure(), 'generic_login_errors' ) ) );
		$this->assertFalse( has_action( 'template_redirect', array( $this->disclosure(), 'block_author_query' ) ) );
	}

	public function test_the_reports_never_claim_hiding_is_protection() {
		foreach ( array( 'version_exposure', 'discovery' ) as $id ) {
			$text = $this->disclosure()->report()[ $id ]['description'] . ' ' . implode( ' ', $this->disclosure()->report()[ $id ]['warnings'] );
			$this->assertMatchesRegularExpression( '/not (access control|protection)|does not make|hygiene|patching/i', $text, $id );
		}
	}
}
