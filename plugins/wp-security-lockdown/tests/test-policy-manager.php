<?php
/**
 * Policy manager: reports, display statuses, verification bookkeeping.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Policy_Manager;
use WP_Security_Lockdown\State_Repository;

class Test_Policy_Manager extends Test_Case {

	const CONTROLS = array(
		'comments',
		'xmlrpc',
		'rest_api',
		'login_limiter',
		'password_policy',
		'author_enumeration',
		'login_errors',
		'version_exposure',
		'discovery',
		'error_display',
		'updates',
		'file_editor',
	);

	public function set_up() {
		parent::set_up();
		remove_filter( 'automatic_updater_disabled', '__return_true' );
		$this->configure();
		$this->plugin->policy()->apply_all();
	}

	private function report( array $overrides = array() ) {
		return array_merge(
			array(
				'enabled'        => true,
				'state'          => Abstract_Module::STATE_ENFORCED,
				'failure_reason' => '',
				'manual_action'  => '',
				'verification'   => array(
					'status' => 'unverified',
					'method' => 'none',
				),
			),
			$overrides
		);
	}

	/** ---------------------------------------------------------------- display status truth table */

	/**
	 * @dataProvider status_cases
	 */
	public function test_display_status( array $report, $expected ) {
		$this->assertSame( $expected, Policy_Manager::display_status( $this->report( $report ) ) );
	}

	public function status_cases() {
		$v = static function ( $status, $method ) {
			return array(
				'verification' => array(
					'status' => $status,
					'method' => $method,
				),
			);
		};
		return array(
			'verified over http'                  => array( $v( 'verified', 'http_probe' ), Policy_Manager::VERIFIED_HTTP ),
			'verified in process'                 => array( $v( 'verified', 'in_process' ), Policy_Manager::VERIFIED_LOCAL ),
			'verified by self test'               => array( $v( 'verified', 'self_test' ), Policy_Manager::VERIFIED_LOCAL ),
			'enforced but never verified'         => array( $v( 'unverified', 'none' ), Policy_Manager::UNVERIFIED ),
			'enforced, verification failed'       => array( $v( 'failed', 'http_probe' ), Policy_Manager::NOT_WORKING ),
			'failed verification beats partial'   => array( array( 'state' => 'partial' ) + $v( 'failed', 'http_probe' ), Policy_Manager::NOT_WORKING ),
			'partial'                             => array( array( 'state' => 'partial' ), Policy_Manager::PARTIAL ),
			'partial even if verified'            => array( array( 'state' => 'partial' ) + $v( 'verified', 'http_probe' ), Policy_Manager::PARTIAL ),
			'failed state'                        => array( array( 'state' => 'failed' ), Policy_Manager::FAILED ),
			'failed state beats verified'         => array( array( 'state' => 'failed' ) + $v( 'verified', 'http_probe' ), Policy_Manager::FAILED ),
			'disabled by policy'                  => array(
				array(
					'enabled' => false,
					'state'   => 'disabled',
				),
				Policy_Manager::DISABLED,
			),
			'switched off even with old evidence' => array( array( 'enabled' => false ) + $v( 'verified', 'http_probe' ), Policy_Manager::DISABLED ),
			'monitor without findings'            => array( array( 'state' => 'monitor' ), Policy_Manager::MONITOR_OK ),
			'monitor with findings'               => array(
				array(
					'state'          => 'monitor',
					'failure_reason' => '2 findings',
				),
				Policy_Manager::MONITOR_WARN,
			),
		);
	}

	public function test_only_verified_statuses_mean_known_to_work() {
		$known = array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::VERIFIED_LOCAL, Policy_Manager::MONITOR_OK );
		foreach ( $this->status_cases() as $label => $case ) {
			$status = $case[1];
			if ( ! in_array( $status, $known, true ) ) {
				continue;
			}
			$report = $this->report( $case[0] );
			$this->assertSame( Abstract_Module::STATE_ENFORCED === $report['state'] || 'monitor' === $report['state'], true, $label );
			$this->assertNotSame( 'failed', $report['verification']['status'], $label );
		}
	}

	/** ---------------------------------------------------------------- summary */

	public function test_the_overall_verdict_cannot_be_greener_than_the_worst_control() {
		$make = function ( array $statuses ) {
			$reports = array();
			foreach ( $statuses as $i => $status ) {
				$reports[ 'c' . $i ] = array(
					'status'        => $status,
					'manual_action' => '',
				);
			}
			return Policy_Manager::summarize( $reports )['overall'];
		};
		$this->assertSame( 'ok', $make( array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::VERIFIED_LOCAL, Policy_Manager::MONITOR_OK, Policy_Manager::DISABLED ) ) );
		$this->assertSame( 'attention', $make( array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::UNVERIFIED ) ) );
		$this->assertSame( 'attention', $make( array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::PARTIAL ) ) );
		$this->assertSame( 'attention', $make( array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::MONITOR_WARN ) ) );
		$this->assertSame( 'at_risk', $make( array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::NOT_WORKING ) ) );
		$this->assertSame( 'at_risk', $make( array( Policy_Manager::UNVERIFIED, Policy_Manager::FAILED ) ) );
	}

	public function test_a_pending_manual_action_prevents_an_ok_verdict() {
		$summary = Policy_Manager::summarize(
			array(
				'a' => array(
					'status'        => Policy_Manager::VERIFIED_HTTP,
					'manual_action' => 'Do something',
				),
			)
		);
		$this->assertSame( 'attention', $summary['overall'] );
		$this->assertSame( 1, $summary['manual'] );
	}

	/** ---------------------------------------------------------------- reports */

	public function test_every_control_reports_every_documented_field() {
		$reports = $this->plugin->policy()->reports();
		$this->assertEqualsCanonicalizing( self::CONTROLS, array_keys( $reports ) );
		foreach ( $reports as $id => $report ) {
			foreach ( array( 'id', 'module', 'title', 'description', 'enabled', 'desired', 'state', 'enforcement', 'persists', 'failure_reason', 'warnings', 'manual_action', 'server_level', 'details', 'verification', 'status' ) as $key ) {
				$this->assertArrayHasKey( $key, $report, "$id.$key" );
			}
			$this->assertSame( $id, $report['id'] );
			$this->assertNotSame( '', $report['title'], $id );
			$this->assertNotSame( '', $report['description'], $id );
			$this->assertNotSame( '', $report['desired'], "$id must state the policy it is meant to achieve" );
			$this->assertIsArray( $report['enforcement'], $id );
			$this->assertIsBool( $report['enabled'] );
			$this->assertContains( $report['state'], array( 'enforced', 'partial', 'failed', 'disabled', 'monitor' ), $id );
		}
	}

	public function test_each_module_reports_exactly_the_controls_it_declares() {
		foreach ( $this->plugin->policy()->modules() as $module ) {
			$this->assertEqualsCanonicalizing( array_keys( $module->controls() ), array_keys( $module->report() ), $module->slug() );
		}
	}

	public function test_a_control_that_enforces_something_says_what_survives_deactivation() {
		$reports = $this->plugin->policy()->reports();
		$this->assertNotSame( '', $reports['comments']['persists'], 'The only persistent protection must be documented.' );
		foreach ( array_diff( array_keys( $reports ), array( 'comments' ) ) as $id ) {
			$this->assertSame( '', $reports[ $id ]['persists'], "$id stops immediately on deactivation" );
		}
	}

	public function test_registering_the_modules_twice_does_not_double_the_hooks() {
		global $wp_filter;
		$count  = static function () use ( &$wp_filter ) {
			$n = 0;
			foreach ( $wp_filter as $hook ) {
				foreach ( $hook->callbacks as $callbacks ) {
					$n += count( $callbacks );
				}
			}
			return $n;
		};
		$before = $count();
		$this->plugin->policy()->register_modules();
		$this->plugin->policy()->register_modules();
		$this->assertSame( $before, $count(), 'The same callbacks on the same objects are not added twice.' );
	}

	public function test_a_normal_request_attaches_a_small_bounded_number_of_hooks() {
		global $wp_filter;
		$mine = 0;
		foreach ( $wp_filter as $hook ) {
			foreach ( $hook->callbacks as $callbacks ) {
				foreach ( $callbacks as $callback ) {
					$function = $callback['function'];
					if ( is_array( $function ) && is_object( $function[0] ) && 0 === strpos( get_class( $function[0] ), 'WP_Security_Lockdown\\' ) && ! ( $function[0] instanceof \WP_UnitTestCase_Base ) ) {
						++$mine;
					}
				}
			}
		}
		$this->assertLessThan( 45, $mine, 'Hook registration is the per-request cost of the plugin; it must stay small.' );
		$this->assertGreaterThan( 10, $mine );
	}

	/** ---------------------------------------------------------------- verification bookkeeping */

	public function test_verification_is_stale_after_the_policy_changes() {
		$this->plugin->policy()->verify( false );
		$this->assertSame( Policy_Manager::VERIFIED_LOCAL, $this->plugin->policy()->reports()['comments']['status'] );

		$this->plugin->settings()->update( array( 'login' => array( 'max_attempts' => 9 ) ) );
		$report = $this->plugin->policy()->reports()['comments'];
		$this->assertSame( Policy_Manager::UNVERIFIED, $report['status'], 'Evidence gathered for another policy is not evidence for this one.' );
		$this->assertTrue( $report['verification']['stale'] );
		$this->assertStringContainsString( 'policy changed', $report['verification']['detail'] );
	}

	public function test_drifted_defaults_make_a_control_partial_while_the_protective_effect_stays_verified() {
		$this->plugin->policy()->verify( false );
		update_option( 'default_ping_status', 'open' ); // Someone changed a persistent default after the policy set it.

		$this->plugin->policy()->verify( false );
		$report = $this->plugin->policy()->reports()['comments'];
		$this->assertSame( 'verified', $report['verification']['status'], 'Comments really are closed, and the test proved it.' );
		$this->assertSame( Policy_Manager::PARTIAL, $report['status'], 'But the policy is not fully applied, and the badge says so rather than "Not working".' );
		$this->assertStringContainsString( 'default_ping_status', $report['failure_reason'] );
	}

	public function test_a_cheap_recheck_never_downgrades_still_valid_http_evidence() {
		$state = $this->plugin->state();
		$state->record_verification(
			array(
				'comments' => array(
					'status' => 'verified',
					'method' => 'http_probe',
					'detail' => 'real request',
				),
			),
			$this->plugin->settings()->fingerprint()
		);

		$this->plugin->policy()->verify( false ); // In-process only.
		$stored = $this->plugin->state()->verification()['comments'];
		$this->assertSame( 'http_probe', $stored['method'] );
		$this->assertSame( 'real request', $stored['detail'] );
	}

	public function test_a_cheap_recheck_always_records_a_failure() {
		$state = $this->plugin->state();
		$state->record_verification(
			array(
				'comments' => array(
					'status' => 'verified',
					'method' => 'http_probe',
					'detail' => 'real request',
				),
			),
			$this->plugin->settings()->fingerprint()
		);
		remove_filter( 'comments_open', '__return_false', 999 ); // The control just broke.

		$this->plugin->policy()->verify( false );
		$this->assertSame( 'failed', $this->plugin->state()->verification()['comments']['status'], 'Old HTTP evidence must never mask a regression the cheap check can see.' );
	}

	public function test_a_cheap_recheck_replaces_http_evidence_that_belongs_to_another_policy() {
		$this->plugin->state()->record_verification(
			array(
				'comments' => array(
					'status' => 'verified',
					'method' => 'http_probe',
					'detail' => 'old',
				),
			),
			'some-other-fingerprint'
		);
		$this->plugin->policy()->verify( false );
		$this->assertSame( 'in_process', $this->plugin->state()->verification()['comments']['method'] );
	}

	public function test_a_deep_verification_probes_over_http_and_records_the_method() {
		$this->mock_http(
			function ( $url ) {
				if ( false !== strpos( $url, 'xmlrpc.php' ) ) {
						return $this->http_response( 403, 'XML-RPC is disabled on this site.' );
				}
				if ( false !== strpos( $url, 'wp-comments-post.php' ) ) {
					return $this->http_response( 403, 'closed' );
				}
				if ( false !== strpos( $url, 'rest_route' ) ) {
					return $this->http_response( 401, '{"code":"rest_not_logged_in"}' );
				}
				if ( false !== strpos( $url, 'author=' ) ) {
					return $this->http_response( 404, 'not found' );
				}
				return $this->http_response( 200, '<html><head></head><body>ok</body></html>' );
			}
		);
		self::factory()->post->create( array( 'post_status' => 'publish' ) );
		self::factory()->user->create( array( 'role' => 'author' ) );
		$this->set_permalink_structure( '/%postname%/' );

		$results = $this->plugin->policy()->verify( true );
		foreach ( array( 'comments', 'xmlrpc', 'rest_api', 'version_exposure', 'discovery' ) as $id ) {
			$this->assertSame( 'verified', $results[ $id ]['status'], $id . ': ' . $results[ $id ]['detail'] );
			$this->assertSame( 'http_probe', $results[ $id ]['method'], $id );
		}
		$this->assertSame( 'self_test', $results['login_limiter']['method'] );
		$this->assertContains( 'verification_run', array_column( $this->plugin->logger()->entries( 20 ), 'e' ) );
	}

	public function test_without_a_network_the_http_controls_are_unverified_not_verified() {
		$this->mock_http(
			function () {
				return new \WP_Error( 'http_request_failed', 'no route to host' );
			}
		);
		$results = $this->plugin->policy()->verify( true );
		foreach ( array( 'xmlrpc', 'rest_api' ) as $id ) {
			$this->assertSame( 'unverified', $results[ $id ]['status'], $id );
			$this->assertStringContainsString( 'unavailable', $results[ $id ]['detail'], $id );
		}
		$this->assertNotSame( Policy_Manager::VERIFIED_HTTP, $this->plugin->policy()->reports()['xmlrpc']['status'] );
	}

	public function test_a_module_that_crashes_while_verifying_does_not_stop_the_others() {
		$manager = new Policy_Manager_With_Broken_Module( $this->plugin );
		$results = $manager->verify( false );
		$this->assertArrayHasKey( 'comments', $results );
		$this->assertSame( 'verified', $results['comments']['status'] );
	}

	public function test_disabled_controls_are_not_verified_and_never_counted() {
		$this->configure(
			array(
				'comments' => array( 'enabled' => false ),
				'login'    => array( 'limiter' => false ),
			)
		);
		$results = $this->plugin->policy()->verify( false );
		$this->assertArrayNotHasKey( 'comments', $results );
		$this->assertArrayNotHasKey( 'login_limiter', $results );
		$report = $this->plugin->policy()->reports()['comments'];
		$this->assertSame( Policy_Manager::DISABLED, $report['status'] );
		$this->assertSame( 'not_applicable', $report['verification']['status'] );
	}

	public function test_corrupted_stored_verification_is_coerced_not_trusted() {
		update_option(
			State_Repository::OPTION,
			array(
				'verification' => array(
					'comments' => array(
						'status'      => array( 'x' ),
						'method'      => '<script>',
						'detail'      => array( 'y' ),
						'time'        => 'soon',
						'fingerprint' => $this->plugin->settings()->fingerprint(),
					),
					'xmlrpc'   => 'a string',
				),
			)
		);
		$this->reload_plugin();
		$this->configure();
		$reports = $this->plugin->policy()->reports();
		$this->assertSame( 'unverified', $reports['comments']['verification']['status'] );
		$this->assertSame( 'none', $reports['comments']['verification']['method'] );
		$this->assertSame( '', $reports['comments']['verification']['detail'] );
		$this->assertSame( 0, $reports['comments']['verification']['time'] );
		$this->assertSame( Policy_Manager::UNVERIFIED, $reports['xmlrpc']['status'] );
	}

	/** ---------------------------------------------------------------- no false sense of security */

	public function test_nothing_is_verified_over_http_until_a_probe_really_ran() {
		foreach ( $this->plugin->policy()->reports() as $id => $report ) {
			$this->assertNotSame( Policy_Manager::VERIFIED_HTTP, $report['status'], "$id" );
		}
		foreach ( array( 'xmlrpc', 'rest_api', 'author_enumeration' ) as $id ) {
			$this->assertNotContains( $this->plugin->policy()->reports()[ $id ]['status'], array( Policy_Manager::VERIFIED_HTTP, Policy_Manager::VERIFIED_LOCAL ), "$id needs a real request before it may be called verified" );
		}
	}
}
