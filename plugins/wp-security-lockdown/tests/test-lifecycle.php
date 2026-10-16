<?php
/**
 * Activation, deactivation, uninstall and failure isolation.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Activator;
use WP_Security_Lockdown\Audit_Logger;
use WP_Security_Lockdown\Deactivator;
use WP_Security_Lockdown\Plugin;
use WP_Security_Lockdown\Policy_Manager;
use WP_Security_Lockdown\Rate_Limiter;
use WP_Security_Lockdown\Settings_Repository;
use WP_Security_Lockdown\State_Repository;

class Test_Lifecycle extends Test_Case {

	public function set_up() {
		parent::set_up();
		update_option( 'default_comment_status', 'open' );
		update_option( 'default_ping_status', 'open' );
		update_option( 'default_pingback_flag', '1' );
		wp_clear_scheduled_hook( Plugin::CRON_VERIFY );
	}

	private function reload() {
		Plugin::reset();
		$this->plugin = Plugin::instance();
	}

	public function test_compatibility_gate_refuses_old_php_and_wordpress() {
		$this->assertSame( array(), wp_security_lockdown_compatibility_errors() );
		$this->assertCount( 1, wp_security_lockdown_compatibility_errors( '7.3.33' ) );
		$this->assertCount( 1, wp_security_lockdown_compatibility_errors( null, '5.9' ) );
		$this->assertCount( 2, wp_security_lockdown_compatibility_errors( '7.0', '4.0' ) );
		$this->assertSame( array(), wp_security_lockdown_compatibility_errors( '7.4.0', '6.0' ), 'The documented minimums themselves are supported.' );
	}

	public function test_activation_applies_the_policy_records_originals_and_schedules_verification() {
		Activator::activate();
		$this->reload();

		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );
		$this->assertSame( 'closed', get_option( 'default_ping_status' ) );
		$this->assertSame( '0', get_option( 'default_pingback_flag' ) );

		$ledger = $this->plugin->rollback()->entries();
		$this->assertSame( array( 'default_comment_status', 'default_ping_status', 'default_pingback_flag' ), array_keys( $ledger ) );
		$this->assertSame( 'open', $ledger['default_comment_status']['original'] );
		$this->assertSame( '1', $ledger['default_pingback_flag']['original'] );

		$activation = $this->plugin->state()->get( 'activation' );
		$this->assertSame( 1, $activation['count'] );
		$this->assertSame( '', $activation['error'] );
		$this->assertNotFalse( wp_next_scheduled( Plugin::CRON_VERIFY ), 'HTTP verification is scheduled for when the plugin is actually active.' );
		$this->assertNotFalse( get_transient( Activator::NOTICE_TRANSIENT ) );
		$this->assertContains( 'activated', array_column( $this->plugin->logger()->entries( 50 ), 'e' ) );
	}

	public function test_activation_records_in_process_verification_but_never_claims_http_verification() {
		Activator::activate();
		$this->reload();

		$verification = $this->plugin->state()->verification();
		$this->assertSame( 'verified', $verification['comments']['status'] );
		$this->assertSame( 'unverified', $verification['xmlrpc']['status'], 'A filter being attached does not prove xmlrpc.php rejects requests.' );
		$this->assertSame( 'unverified', $verification['rest_api']['status'] );
		foreach ( $verification as $control => $result ) {
			$this->assertNotSame( 'http_probe', $result['method'], "$control cannot have been HTTP-verified during activation (the plugin is not active yet in other requests)" );
		}
	}

	public function test_repeated_activation_is_idempotent() {
		Activator::activate();
		$this->reload();
		$ledger = $this->plugin->rollback()->entries();
		$logged = count( $this->plugin->logger()->entries( 500 ) );

		Activator::activate();
		Activator::activate();
		$this->reload();

		$this->assertSame( $ledger, $this->plugin->rollback()->entries(), 'The recorded originals must not change or duplicate.' );
		$this->assertSame( 'open', $this->plugin->rollback()->entries()['default_comment_status']['original'] );
		$this->assertSame( 3, count( $this->plugin->rollback()->entries() ) );
		$this->assertSame( 3, $this->plugin->state()->get( 'activation' )['count'] );
		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );

		$events = array_count_values( array_column( $this->plugin->logger()->entries( 500 ), 'e' ) );
		$this->assertSame( 3, $events['option_applied'], 'Options are recorded once, not once per activation.' );
		$this->assertSame( 3, $events['activated'] );
		$this->assertGreaterThan( $logged, count( $this->plugin->logger()->entries( 500 ) ) );
	}

	public function test_activation_does_not_alter_any_unrelated_option() {
		$ignore   = array(
			Settings_Repository::OPTION,
			State_Repository::OPTION,
			Audit_Logger::OPTION,
			'default_comment_status',
			'default_ping_status',
			'default_pingback_flag',
			'cron',
			'recently_activated',
		);
		$snapshot = static function () use ( $ignore ) {
			$all = wp_load_alloptions( true );
			foreach ( $ignore as $key ) {
				unset( $all[ $key ] );
			}
			foreach ( array_keys( $all ) as $key ) {
				if ( 0 === strpos( $key, '_transient' ) || 0 === strpos( $key, '_site_transient' ) ) {
					unset( $all[ $key ] );
				}
			}
			ksort( $all );
			return $all;
		};
		$before   = $snapshot();
		Activator::activate();
		Activator::activate();
		$this->assertSame( $before, $snapshot(), 'Activation must change only the three discussion defaults it documents.' );
	}

	public function test_activation_never_overwrites_an_existing_policy() {
		update_option(
			Settings_Repository::OPTION,
			array(
				'rest'   => array( 'mode' => 'dashboard_only' ),
				'xmlrpc' => array( 'mode' => 'allow' ),
			)
		);
		Activator::activate();
		$this->reload();
		$this->assertSame( 'dashboard_only', $this->plugin->settings()->get( 'rest.mode' ) );
		$this->assertSame( 'allow', $this->plugin->settings()->get( 'xmlrpc.mode' ) );
	}

	public function test_activation_respects_a_policy_that_already_disabled_comments() {
		update_option( Settings_Repository::OPTION, array( 'comments' => array( 'enabled' => false ) ) );
		Activator::activate();
		$this->assertSame( 'open', get_option( 'default_comment_status' ), 'A control switched off must not be applied.' );
		$this->reload();
		$this->assertSame( array(), $this->plugin->rollback()->entries() );
	}

	public function test_a_broken_module_is_isolated_reported_and_does_not_stop_the_others() {
		$manager = new Policy_Manager_With_Broken_Module( $this->plugin );
		$manager->register_modules();

		$this->assertArrayHasKey( 'throwing', $manager->failures() );
		$this->assertNotFalse( has_filter( 'comments_open', '__return_false' ), 'The other modules still registered their protections.' );

		$logged = wp_json_encode( $this->plugin->logger()->entries( 20 ) );
		$this->assertStringContainsString( 'module_failed', $logged );
		$this->assertStringNotContainsString( 'secret detail', $logged, 'Exception messages can contain paths or data and are not logged.' );
		$this->assertArrayHasKey( 'throwing', $this->plugin->state()->get( 'module_failures' ) );
	}

	public function test_a_module_that_cannot_report_turns_its_controls_into_failures_not_a_fatal() {
		$manager = new Policy_Manager_With_Broken_Module( $this->plugin );
		$reports = $manager->reports();
		$this->assertNotEmpty( $reports, 'The dashboard keeps rendering the working modules.' );
		$this->assertArrayHasKey( 'comments', $reports );
	}

	public function test_deactivation_stops_background_work_but_keeps_settings_ledger_and_log() {
		Activator::activate();
		$this->reload();
		$limiter = new Rate_Limiter( 1, 60, 60 );
		$limiter->record_failure( str_repeat( 'a', 32 ) );

		Deactivator::deactivate();
		$this->reload();

		$this->assertFalse( wp_next_scheduled( Plugin::CRON_VERIFY ) );
		$this->assertSame(
			array(
				'tracked' => 0,
				'locked'  => 0,
			),
			( new Rate_Limiter( 1, 60, 60 ) )->snapshot(),
			'Lockouts must not outlive the plugin.'
		);

		$this->assertNotFalse( get_option( Settings_Repository::OPTION ), 'Policy settings are kept.' );
		$this->assertCount( 3, $this->plugin->rollback()->entries(), 'The change record is kept so originals stay recoverable.' );
		$this->assertSame( 'closed', get_option( 'default_comment_status' ), 'By default the persistent options stay as they are.' );
		$events = array_column( $this->plugin->logger()->entries( 500 ), 'e' );
		$this->assertContains( 'activated', $events, 'Deactivation never deletes the log.' );
		$this->assertContains( 'deactivated', $events );
	}

	public function test_deactivation_can_restore_the_originals_when_asked() {
		Activator::activate();
		$this->plugin->settings()->update( array( 'lifecycle' => array( 'rollback_on_deactivation' => true ) ) );
		$this->reload();

		Deactivator::deactivate();
		$this->assertSame( 'open', get_option( 'default_comment_status' ) );
		$this->assertSame( '1', get_option( 'default_pingback_flag' ) );
	}

	public function test_deactivation_rollback_never_overwrites_a_newer_change() {
		Activator::activate();
		$this->plugin->settings()->update( array( 'lifecycle' => array( 'rollback_on_deactivation' => true ) ) );
		update_option( 'default_pingback_flag', '5' ); // Changed by someone after activation.
		$this->reload();

		Deactivator::deactivate();
		$this->assertSame( '5', get_option( 'default_pingback_flag' ), 'A conflicting value is left alone and reported.' );
		$this->assertSame( 'open', get_option( 'default_comment_status' ), 'Non-conflicting options are still restored.' );
		$this->assertContains( 'rollback_conflict', array_column( $this->plugin->logger()->entries( 500 ), 'e' ) );
	}

	public function test_reactivation_after_deactivation_reapplies_without_losing_the_original() {
		Activator::activate();
		$this->reload();
		Deactivator::deactivate();
		update_option( 'default_comment_status', 'open' ); // The site went back to open meanwhile.
		$this->reload();

		Activator::activate();
		$this->reload();
		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );
		$this->assertSame( 'open', $this->plugin->rollback()->entries()['default_comment_status']['original'] );
	}

	public function test_uninstall_removes_configuration_and_temporary_data_only() {
		$post_id    = self::factory()->post->create( array( 'post_title' => 'Keep me' ) );
		$comment_id = self::factory()->comment->create( array( 'comment_post_ID' => $post_id ) );
		$user_id    = self::factory()->user->create();
		update_option( 'unrelated_option', 'keep' );

		Activator::activate();
		$this->reload();
		$this->plugin->logger()->info( 'event', 'a log line' );
		$this->plugin->logger()->flush();
		set_transient( 'wp_security_lockdown_xmlrpc_seen', 1, 100 );
		( new Rate_Limiter( 1, 60, 60 ) )->record_failure( str_repeat( 'b', 32 ) );

		if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
			define( 'WP_UNINSTALL_PLUGIN', 'wp-security-lockdown/wp-security-lockdown.php' );
		}
		include dirname( __DIR__ ) . '/uninstall.php';
		wp_cache_flush();

		$this->assertFalse( get_option( Settings_Repository::OPTION ), 'Policy settings are removed.' );
		$this->assertFalse( get_transient( 'wp_security_lockdown_xmlrpc_seen' ) );
		$this->assertSame(
			array(
				'tracked' => 0,
				'locked'  => 0,
			),
			( new Rate_Limiter( 1, 60, 60 ) )->snapshot()
		);
		$this->assertFalse( wp_next_scheduled( Plugin::CRON_VERIFY ) );

		$this->assertNotEmpty( get_option( Audit_Logger::OPTION ), 'Security logs are never deleted automatically.' );
		$this->assertNotEmpty( get_option( State_Repository::OPTION )['ledger'], 'The record of original values is kept.' );

		$this->assertNotNull( get_post( $post_id ), 'Site content must never be touched.' );
		$this->assertNotNull( get_comment( $comment_id ) );
		$this->assertNotFalse( get_userdata( $user_id ) );
		$this->assertSame( 'keep', get_option( 'unrelated_option' ) );
	}
}
