<?php
/**
 * Diagnostics (checks that need a person or the server) and the security-header audit.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Health_Check;
use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Security_Headers_Audit;
use WP_Security_Lockdown\State_Repository;

class Test_Health_Check extends Test_Case {

	/** @var Health_Check */
	private $health;

	public function set_up() {
		parent::set_up();
		$this->health = $this->plugin->health();
		delete_site_transient( 'php_check_' . md5( PHP_VERSION ) );
	}

	private function row( array $rows, $id ) {
		foreach ( $rows as $row ) {
			if ( $row['id'] === $id ) {
				return $row;
			}
		}
		$this->fail( "No row $id" );
	}

	private function live( $id ) {
		return $this->row( $this->health->live_checks(), $id );
	}

	/**
	 * A mocked site where every path answers as given by $map (url fragment => response); others are 404.
	 */
	private function site( array $map = array() ) {
		$this->mock_http(
			function ( $url ) use ( $map ) {
				foreach ( $map as $fragment => $response ) {
					if ( false !== strpos( $url, $fragment ) ) {
						return $response;
					}
				}
				return $this->http_response( 404, '<html>Not found</html>', array( 'content-type' => 'text/html' ) );
			}
		);
	}

	/** ---------------------------------------------------------------- shape */

	public function test_every_row_has_the_documented_shape_and_vocabulary() {
		$this->site();
		$this->health->run( true );
		$rows = $this->health->all()['rows']; // Live rows with the deep results merged over their placeholders.
		$ids  = array();
		foreach ( $rows as $row ) {
			foreach ( array( 'id', 'group', 'title', 'status', 'summary', 'remediation', 'requires', 'deep' ) as $key ) {
				$this->assertArrayHasKey( $key, $row, $row['id'] ?? '?' );
			}
			$this->assertContains( $row['status'], array( 'pass', 'warn', 'fail', 'info' ), $row['id'] );
			$this->assertContains( $row['requires'], array( '', 'manual', 'server' ), $row['id'] );
			$this->assertArrayHasKey( $row['group'], Health_Check::groups(), $row['id'] );
			$this->assertNotSame( '', $row['summary'], $row['id'] );
			if ( in_array( $row['status'], array( 'warn', 'fail' ), true ) ) {
				$this->assertNotSame( '', $row['remediation'], $row['id'] . ': a finding must say what to do' );
				$this->assertNotSame( '', $row['requires'], $row['id'] . ': a finding must say who has to act' );
			}
			$ids[] = $row['id'];
		}
		$this->assertGreaterThan( 15, count( $rows ) );
		$this->assertSame( $ids, array_values( array_unique( $ids ) ), 'Every check appears exactly once.' );
	}

	public function test_live_checks_make_no_network_requests() {
		$this->mock_http(
			function () {
				return $this->http_response( 200 );
			}
		);
		$this->health->live_checks();
		$this->health->all();
		$this->assertSame( array(), $this->http_calls, 'A page view must never trigger HTTP requests.' );
	}

	/** ---------------------------------------------------------------- accounts */

	public function test_a_predictable_admin_account_is_a_manual_finding() {
		$existing = username_exists( 'admin' ); // The WordPress test installation creates one.
		if ( $existing ) {
			wp_delete_user( $existing );
		}
		$this->assertSame( 'pass', $this->live( 'admin_username' )['status'] );
		self::factory()->user->create(
			array(
				'user_login' => 'admin',
				'role'       => 'administrator',
			)
		);
		$row = $this->live( 'admin_username' );
		$this->assertSame( 'warn', $row['status'] );
		$this->assertSame( 'manual', $row['requires'] );
	}

	public function test_open_registration_with_a_privileged_default_role_is_a_problem() {
		$this->assertSame( 'pass', $this->live( 'registration' )['status'] );

		update_option( 'users_can_register', 1 );
		update_option( 'default_role', 'subscriber' );
		$this->assertSame( 'info', $this->live( 'registration' )['status'] );

		update_option( 'default_role', 'administrator' );
		$row = $this->live( 'registration' );
		$this->assertSame( 'fail', $row['status'] );
		$this->assertStringContainsString( 'administrator', $row['summary'] );
	}

	public function test_mfa_is_reported_honestly_and_never_as_enforced() {
		$none = $this->live( 'mfa' );
		$this->assertSame( 'warn', $none['status'] );
		$this->assertStringContainsString( 'NOT available or enforced', $none['summary'] );

		update_option( 'active_plugins', array( 'two-factor/two-factor.php' ) );
		$found = $this->live( 'mfa' );
		$this->assertSame( 'info', $found['status'], 'Presence of a plugin is not proof of enforcement, so the best possible status is "info".' );
		$this->assertStringContainsString( 'Two Factor', $found['summary'] );
		$this->assertStringContainsString( 'cannot verify', $found['summary'] );
		$this->assertSame( 'manual', $found['requires'] );
	}

	/** ---------------------------------------------------------------- environment */

	public function test_the_root_database_account_is_flagged_without_revealing_credentials() {
		$row = $this->live( 'db_user' );
		$this->assertSame( defined( 'DB_USER' ) && 0 === strcasecmp( DB_USER, 'root' ) ? 'fail' : 'pass', $row['status'] );
		$text = wp_json_encode( $row );
		$this->assertStringNotContainsString( DB_PASSWORD, $text );
		$this->assertStringNotContainsString( DB_HOST, $text );
		$this->assertStringNotContainsString( DB_NAME, $text );
	}

	public function test_a_site_on_plain_http_is_warned_in_production_only() {
		$row = $this->live( 'https' );
		$this->assertContains( $row['status'], array( 'warn', 'info' ) );
		$this->assertSame( 'server', $row['requires'] );
		$this->assertStringContainsString( 'Application Passwords', $row['summary'] );
	}

	/**
	 * @dataProvider php_support_cases
	 */
	public function test_php_support_status_comes_from_wordpress_org_data( $data, $status ) {
		set_site_transient( 'php_check_' . md5( PHP_VERSION ), $data, WEEK_IN_SECONDS );
		$row = $this->live( 'php_version' );
		$this->assertSame( $status, $row['status'] );
		if ( 'fail' === $status ) {
			$this->assertStringContainsString( 'no longer receives security fixes', $row['summary'] );
			$this->assertStringContainsString( '8.3', $row['remediation'] );
		}
	}

	public function php_support_cases() {
		$base = array(
			'recommended_version' => '8.3',
			'minimum_version'     => '7.4',
			'is_acceptable'       => true,
		);
		return array(
			'end of life'     => array(
				$base + array(
					'is_secure'    => false,
					'is_supported' => false,
				),
				'fail',
			),
			'security only'   => array(
				$base + array(
					'is_secure'    => true,
					'is_supported' => false,
				),
				'warn',
			),
			'fully supported' => array(
				$base + array(
					'is_secure'    => true,
					'is_supported' => true,
				),
				'pass',
			),
		);
	}

	public function test_php_support_is_not_looked_up_on_a_page_view() {
		$row = $this->live( 'php_version' );
		$this->assertSame( 'info', $row['status'] );
		$this->assertStringContainsString( 'run diagnostics', $row['summary'] );
	}

	public function test_an_unreachable_wordpress_org_gives_an_honest_info_row() {
		$this->mock_http(
			function () {
				return new \WP_Error( 'http_request_failed', 'offline' );
			}
		);
		$rows = $this->health->run( true );
		$this->assertSame( 'info', $this->row( $rows, 'php_version' )['status'] );
		$this->assertStringContainsString( 'Could not determine', $this->row( $rows, 'php_version' )['summary'] );
	}

	/** ---------------------------------------------------------------- exposure probes */

	public function test_nothing_exposed_gives_a_pass_that_states_its_limits() {
		$this->site();
		$row = $this->row( $this->health->run( true ), 'exposed_files' );
		$this->assertSame( 'pass', $row['status'] );
		$this->assertStringContainsString( 'not a vulnerability scan', $row['summary'] );
	}

	/**
	 * @dataProvider exposures
	 */
	public function test_each_commonly_leaked_file_is_detected( $fragment, $response, $label ) {
		$this->site( array( $fragment => $response ) );
		$row = $this->row( $this->health->run( true ), 'exposed_files' );
		$this->assertSame( 'fail', $row['status'], $label );
		$this->assertStringContainsString( $label, $row['summary'] );
		$this->assertSame( 'server', $row['requires'] );
	}

	public function exposures() {
		$text = array( 'content-type' => 'text/plain' );
		return array(
			'git in wp-content' => array( '/wp-content/.git/HEAD', $this->http( 200, "ref: refs/heads/main\n", $text ), '.git/HEAD (wp-content)' ),
			'config backup'     => array( 'wp-config.php.bak', $this->http( 200, "<?php define('DB_NAME', 'x');", $text ), 'wp-config.php.bak' ),
			'config old'        => array( 'wp-config.php.old', $this->http( 200, '$table_prefix = "wp_";', $text ), 'wp-config.php.old' ),
			'env file'          => array( '/.env', $this->http( 200, "APP_KEY=base64:abc\nDB_HOST=x", $text ), '.env' ),
			'debug log'         => array( '/wp-content/debug.log', $this->http( 200, '[16-Oct-2026] PHP Warning: x', $text ), 'wp-content/debug.log' ),
		);
	}

	private function http( $code, $body, array $headers = array() ) {
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

	public function test_a_soft_404_page_is_not_mistaken_for_a_leak() {
		// A catch-all that answers 200 with the site's HTML for every path.
		$html = $this->http( 200, '<html><body>Welcome! DB_NAME ref: refs/heads/main</body></html>', array( 'content-type' => 'text/html; charset=UTF-8' ) );
		$this->mock_http(
			function () use ( $html ) {
				return $html;
			}
		);
		$row = $this->row( $this->health->run( true ), 'exposed_files' );
		$this->assertSame( 'pass', $row['status'], 'HTML pages must not count as leaked config backups, .env files, git metadata or logs.' );
	}

	public function test_response_bodies_are_never_stored_or_shown() {
		$this->site( array( 'wp-config.php.bak' => $this->http( 200, "<?php define('DB_PASSWORD', 'TOP-SECRET-PASSWORD-9'); define('DB_NAME','x');", array( 'content-type' => 'text/plain' ) ) ) );
		$rows = $this->health->run( true );
		$this->assertSame( 'fail', $this->row( $rows, 'exposed_files' )['status'] );
		$stored = wp_json_encode( array( $rows, get_option( State_Repository::OPTION ), get_option( 'wp_security_lockdown_audit_log' ) ) );
		$this->assertStringNotContainsString( 'TOP-SECRET-PASSWORD-9', $stored, 'The probe inspects bodies in memory only.' );
	}

	public function test_version_files_and_directory_listings_are_reported_as_server_matters() {
		$this->site(
			array(
				'readme.html' => $this->http( 200, '<html>WordPress readme</html>' ),
				'license.txt' => $this->http( 200, 'GNU GENERAL PUBLIC LICENSE' ),
				'/uploads/'   => $this->http( 200, '<html><title>Index of /wp-content/uploads</title></html>' ),
			)
		);
		$rows    = $this->health->run( true );
		$version = $this->row( $rows, 'version_files' );
		$this->assertSame( 'warn', $version['status'] );
		$this->assertStringContainsString( 'readme.html and license.txt', $version['summary'] );
		$this->assertStringContainsString( 'undone by every core update', $version['summary'] );
		$this->assertSame( 'server', $version['requires'] );
		$this->assertSame( 'warn', $this->row( $rows, 'directory_listing' )['status'] );
	}

	public function test_an_unreachable_site_gives_info_rows_not_false_passes() {
		$this->mock_http(
			function () {
				return new \WP_Error( 'http_request_failed', 'refused' );
			}
		);
		$rows = $this->health->run( true );
		$this->assertSame( 'info', $this->row( $rows, 'exposed_files' )['status'] );
		$this->assertSame( 'info', $this->row( $rows, 'headers' )['status'] );
		$own = array_filter(
			$this->http_calls,
			static function ( $c ) {
				return false === strpos( $c[0], 'api.wordpress.org' );
			}
		);
		$this->assertCount( 1, $own );
	}

	public function test_a_deep_run_stays_within_the_request_budget() {
		$this->site();
		$probe = new Http_Probe();
		$this->health->run( true, $probe );
		$this->assertLessThanOrEqual( Http_Probe::MAX_REQUESTS, $probe->requests_made() );
		$this->assertGreaterThan( 8, $probe->requests_made(), 'The run actually probed things.' );
	}

	/** ---------------------------------------------------------------- storage */

	public function test_a_deep_run_is_stored_and_merged_over_the_live_placeholders() {
		$before = $this->health->all();
		$this->assertSame( 0, $before['deep_time'] );
		$this->assertSame( 'info', $this->row( $before['rows'], 'php_version' )['status'] );

		set_site_transient(
			'php_check_' . md5( PHP_VERSION ),
			array(
				'is_secure'           => true,
				'is_supported'        => true,
				'recommended_version' => '8.3',
			),
			WEEK_IN_SECONDS
		);
		$this->site();
		$this->health->run( true );
		$after = $this->health->all();

		$this->assertGreaterThan( 0, $after['deep_time'] );
		$ids = array_column( $after['rows'], 'id' );
		$this->assertSame( $ids, array_values( array_unique( $ids ) ), 'No duplicate rows: a deep result replaces its placeholder.' );
		$this->assertSame( 'pass', $this->row( $after['rows'], 'php_version' )['status'] );
		$this->assertNotEmpty(
			array_filter(
				$after['rows'],
				static function ( $r ) {
					return $r['deep'];
				}
			)
		);
	}

	public function test_corrupted_stored_rows_are_ignored_or_coerced() {
		update_option(
			State_Repository::OPTION,
			array(
				'checks' => array(
					'time' => 5,
					'rows' => array(
						'garbage',
						array(
							'id'          => array( 'x' ),
							'group'       => 'files',
							'title'       => 't',
							'summary'     => 's',
							'remediation' => 'r',
						),
						array(
							'id'          => 'ok_row',
							'group'       => 'files',
							'title'       => 'T',
							'summary'     => 'S',
							'remediation' => 'R',
							'status'      => 'catastrophic',
							'requires'    => 'root',
						),
					),
				),
			)
		);
		$this->reload_plugin();
		$rows = $this->plugin->health()->all()['rows'];
		$row  = $this->row( $rows, 'ok_row' );
		$this->assertSame( 'info', $row['status'], 'Unknown statuses fall back safely.' );
		$this->assertSame( '', $row['requires'] );
		$this->assertCount(
			1,
			array_filter(
				$rows,
				static function ( $r ) {
					return in_array( $r['id'], array( 'ok_row', 'x', 'Array' ), true );
				}
			),
			'Malformed rows are dropped.'
		);
	}

	public function test_summarize_counts_findings_by_severity_and_owner() {
		$sum = Health_Check::summarize(
			array(
				array(
					'status'   => 'fail',
					'requires' => 'server',
				),
				array(
					'status'   => 'warn',
					'requires' => 'server',
				),
				array(
					'status'   => 'warn',
					'requires' => 'manual',
				),
				array(
					'status'   => 'pass',
					'requires' => '',
				),
				array(
					'status'   => 'info',
					'requires' => 'manual',
				),
			)
		);
		$this->assertSame(
			array(
				'fail'   => 1,
				'warn'   => 2,
				'manual' => 1,
				'server' => 2,
			),
			$sum
		);
	}

	public function test_clearing_caches_removes_the_filesystem_result() {
		set_transient( \WP_Security_Lockdown\Modules\Update_Policy::FS_TRANSIENT, array( 'method' => 'direct' ), 100 );
		Health_Check::clear_caches();
		$this->assertFalse( get_transient( \WP_Security_Lockdown\Modules\Update_Policy::FS_TRANSIENT ) );
	}

	/** ---------------------------------------------------------------- security headers */

	private function audit( array $headers, $https = true ) {
		$rows = array();
		foreach ( Security_Headers_Audit::audit( $headers, $https ) as $row ) {
			$rows[ $row['id'] ] = $row;
		}
		return $rows;
	}

	public function test_a_well_configured_site_passes_every_header_check() {
		$rows = $this->audit(
			array(
				'x-content-type-options'    => 'nosniff',
				'x-frame-options'           => 'SAMEORIGIN',
				'referrer-policy'           => 'strict-origin-when-cross-origin',
				'strict-transport-security' => 'max-age=31536000',
				'permissions-policy'        => 'camera=()',
				'content-security-policy'   => "default-src 'self'",
			)
		);
		foreach ( array( 'x-content-type-options', 'clickjacking', 'referrer-policy', 'strict-transport-security', 'permissions-policy', 'content-security-policy', 'server', 'x-powered-by' ) as $name ) {
			$this->assertSame( 'pass', $rows[ 'header_' . $name ]['status'], $name );
		}
		$this->assertSame(
			array(
				'apache' => '',
				'nginx'  => '',
			),
			Security_Headers_Audit::snippets( array_values( $rows ) )
		);
	}

	public function test_missing_headers_are_reported_with_compatibility_notes() {
		$rows = $this->audit( array() );
		$this->assertSame( 'warn', $rows['header_x-content-type-options']['status'] );
		$this->assertSame( 'warn', $rows['header_clickjacking']['status'] );
		$this->assertSame( 'warn', $rows['header_strict-transport-security']['status'] );
		foreach ( array( 'clickjacking', 'strict-transport-security', 'permissions-policy', 'content-security-policy', 'referrer-policy' ) as $name ) {
			$this->assertMatchesRegularExpression( '/Compatibility|compat|break|hard to undo|first|blindly/i', $rows[ 'header_' . $name ]['remediation'], "$name must say what could break" );
		}
	}

	public function test_hsts_is_not_demanded_on_plain_http() {
		$http = $this->audit( array(), false );
		$this->assertSame( 'info', $http['header_strict-transport-security']['status'] );
		$this->assertStringContainsString( 'serve the whole site over HTTPS', $http['header_strict-transport-security']['remediation'] );
		$this->assertSame( array(), $http['header_strict-transport-security']['snippet'] );
	}

	public function test_a_weak_hsts_max_age_is_flagged() {
		$this->assertSame( 'warn', $this->audit( array( 'strict-transport-security' => 'max-age=300' ) )['header_strict-transport-security']['status'] );
		$this->assertSame( 'pass', $this->audit( array( 'strict-transport-security' => 'max-age=15552000; includeSubDomains' ) )['header_strict-transport-security']['status'] );
	}

	public function test_csp_is_never_recommended_for_blind_enforcement() {
		$none = $this->audit( array() )['header_content-security-policy'];
		$this->assertSame( 'info', $none['status'], 'Absence of a CSP is advice, not a failure.' );
		$this->assertStringContainsString( 'Report-Only', $none['remediation'] );
		$this->assertStringContainsString( 'not be switched on blindly', $none['remediation'] );
		$this->assertSame( array(), $none['snippet'], 'No CSP is ever put in the generated snippets.' );

		$report = $this->audit( array( 'content-security-policy-report-only' => "default-src 'self'" ) )['header_content-security-policy'];
		$this->assertStringContainsString( 'Report-Only', $report['summary'] );
	}

	public function test_clickjacking_accepts_csp_frame_ancestors() {
		$this->assertSame( 'pass', $this->audit( array( 'content-security-policy' => "frame-ancestors 'self'" ) )['header_clickjacking']['status'] );
	}

	public function test_software_disclosure_headers_are_flagged_as_server_configuration() {
		$rows = $this->audit(
			array(
				'server'       => 'Apache/2.4.58 (Ubuntu)',
				'x-powered-by' => 'PHP/8.1.34',
			)
		);
		$this->assertSame( 'warn', $rows['header_server']['status'] );
		$this->assertSame( 'warn', $rows['header_x-powered-by']['status'] );
		$this->assertStringContainsString( 'ServerTokens', $rows['header_server']['remediation'] );
		$this->assertStringContainsString( 'expose_php', $rows['header_x-powered-by']['remediation'] );
		$this->assertSame( 'pass', $this->audit( array( 'server' => 'nginx' ) )['header_server']['status'], 'A bare product name discloses no version.' );
	}

	public function test_weak_referrer_policies_are_flagged() {
		$this->assertSame( 'warn', $this->audit( array( 'referrer-policy' => 'unsafe-url' ) )['header_referrer-policy']['status'] );
		$this->assertSame( 'pass', $this->audit( array( 'referrer-policy' => 'same-origin' ) )['header_referrer-policy']['status'] );
	}

	public function test_the_generated_snippets_contain_only_safe_directives() {
		$rows     = array_values( $this->audit( array( 'server' => 'Apache/2.4.58' ) ) );
		$snippets = Security_Headers_Audit::snippets( $rows );
		foreach ( array( 'X-Content-Type-Options', 'X-Frame-Options', 'Strict-Transport-Security' ) as $header ) {
			$this->assertStringContainsString( $header, $snippets['apache'] );
			$this->assertStringContainsString( $header, $snippets['nginx'] );
		}
		$this->assertStringNotContainsString( 'Content-Security-Policy', $snippets['apache'] . $snippets['nginx'] );
		$this->assertStringNotContainsString( 'Permissions-Policy', $snippets['apache'] . $snippets['nginx'], 'Optional hardening is not auto-generated.' );
		$this->assertStringContainsString( '<IfModule mod_headers.c>', $snippets['apache'] );
		$this->assertStringContainsString( 'always;', $snippets['nginx'] );
	}

	public function test_untrusted_header_values_cannot_inject_markup_into_the_audit() {
		$rows = $this->audit(
			array(
				'server'       => "<script>alert(1)</script>\r\nX: y",
				'x-powered-by' => "\x00\x1b[31mPHP",
			)
		);
		foreach ( $rows as $row ) {
			$this->assertDoesNotMatchRegularExpression( '/[\x00-\x08\x0B-\x1F]/', $row['summary'] );
		}
		$this->assertLessThanOrEqual( 140, strlen( $rows['header_server']['summary'] ), 'Reflected header values are truncated.' );
	}
}
