<?php
/**
 * Change ledger and conflict-aware rollback.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Rollback;

class Test_Rollback extends Test_Case {

	/** @var Rollback */
	private $rollback;

	public function set_up() {
		parent::set_up();
		$this->rollback = $this->plugin->rollback();
		update_option( 'default_comment_status', 'open' );
		update_option( 'default_ping_status', 'open' );
		update_option( 'default_pingback_flag', '1' );
	}

	public function test_claim_changes_the_option_and_records_the_original() {
		$result = $this->rollback->claim( 'default_comment_status', 'closed', 'comments' );
		$this->assertSame( Rollback::APPLIED, $result['status'] );
		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );

		$entry = $this->rollback->entries()['default_comment_status'];
		$this->assertSame( 'open', $entry['original'] );
		$this->assertSame( 'closed', $entry['applied'] );
		$this->assertTrue( $entry['existed'] );
		$this->assertTrue( $entry['changed'] );
		$this->assertSame( 'comments', $entry['control'] );
	}

	public function test_claiming_twice_changes_nothing_and_keeps_the_first_original() {
		$this->rollback->claim( 'default_comment_status', 'closed', 'comments' );
		$ledger_before = $this->rollback->entries();

		$again = $this->rollback->claim( 'default_comment_status', 'closed', 'comments' );
		$this->assertSame( Rollback::UNCHANGED, $again['status'] );
		$this->assertSame( $ledger_before, $this->rollback->entries(), 'Repeated enforcement must not alter the record.' );
	}

	public function test_reapplying_over_drift_keeps_the_pre_plugin_original() {
		$this->rollback->claim( 'default_ping_status', 'closed', 'comments' );
		update_option( 'default_ping_status', 'open' ); // Someone re-opens it.
		update_option( 'default_ping_status', 'weird' );

		$result = $this->rollback->claim( 'default_ping_status', 'closed', 'comments' );
		$this->assertSame( Rollback::REAPPLIED, $result['status'] );
		$this->assertSame( 'open', $this->rollback->entries()['default_ping_status']['original'], 'The original must stay the value from before the plugin ever touched it, not the drifted value.' );
	}

	public function test_release_restores_the_original_when_untouched_since() {
		$this->rollback->claim( 'default_comment_status', 'closed', 'comments' );
		$result = $this->rollback->release( 'default_comment_status' );

		$this->assertSame( Rollback::RESTORED, $result['status'] );
		$this->assertSame( 'open', get_option( 'default_comment_status' ) );
		$this->assertArrayNotHasKey( 'default_comment_status', $this->rollback->entries() );
	}

	public function test_a_newer_change_is_reported_as_a_conflict_and_not_overwritten() {
		$this->rollback->claim( 'default_pingback_flag', '0', 'comments' );
		update_option( 'default_pingback_flag', '5' ); // The administrator decided something else afterwards.

		$result = $this->rollback->release( 'default_pingback_flag' );
		$this->assertSame( Rollback::CONFLICT, $result['status'] );
		$this->assertSame( '5', get_option( 'default_pingback_flag' ), 'The newer administrator value must be preserved.' );
		$this->assertArrayHasKey( 'default_pingback_flag', $this->rollback->entries(), 'The record stays so the conflict can be resolved later.' );
		$this->assertSame( '1', $result['original'] );
	}

	public function test_force_restores_over_a_conflict_and_says_so() {
		$this->rollback->claim( 'default_pingback_flag', '0', 'comments' );
		update_option( 'default_pingback_flag', '5' );

		$result = $this->rollback->release( 'default_pingback_flag', true );
		$this->assertSame( Rollback::RESTORED_FORCED, $result['status'] );
		$this->assertSame( '1', get_option( 'default_pingback_flag' ) );
		$log = array_column( $this->plugin->logger()->entries( 50 ), 'e' );
		$this->assertContains( 'option_restored_forced', $log );
	}

	public function test_an_option_that_did_not_exist_is_deleted_on_release() {
		delete_option( 'wpsl_test_new_option' );
		$this->rollback->claim( 'wpsl_test_new_option', 'x', 'comments' );
		$this->assertSame( 'x', get_option( 'wpsl_test_new_option' ) );

		$this->rollback->release( 'wpsl_test_new_option' );
		$this->assertFalse( get_option( 'wpsl_test_new_option', false ), 'An option the plugin created must not be left behind.' );
	}

	public function test_a_value_that_was_already_correct_is_not_owned_by_the_plugin() {
		update_option( 'default_ping_status', 'closed' ); // The administrator already did this.
		$claim = $this->rollback->claim( 'default_ping_status', 'closed', 'comments' );
		$this->assertSame( Rollback::ALREADY, $claim['status'] );

		update_option( 'default_ping_status', 'closed' );
		$release = $this->rollback->release( 'default_ping_status' );
		$this->assertSame( Rollback::NOTHING, $release['status'] );
		$this->assertSame( 'closed', get_option( 'default_ping_status' ), 'Rolling back must not undo the administrator\'s own earlier choice.' );
	}

	public function test_releasing_something_never_managed_does_nothing() {
		$this->assertSame( Rollback::NOT_MANAGED, $this->rollback->release( 'blogname' )['status'] );
		$this->assertNotSame( '', get_option( 'blogname' ) );
	}

	public function test_scalar_equality_ignores_wordpress_string_storage() {
		$this->assertTrue( $this->rollback->equal( 0, '0' ) );
		$this->assertTrue( $this->rollback->equal( '1', 1 ) );
		$this->assertTrue( $this->rollback->equal( '', null ) );
		$this->assertFalse( $this->rollback->equal( 'open', 'closed' ) );
		$this->assertFalse( $this->rollback->equal( Rollback::ABSENT, '' ), 'An absent option is not an empty option.' );
	}

	public function test_policy_apply_all_then_rollback_returns_to_the_start_and_hands_the_control_back() {
		$before = array( get_option( 'default_comment_status' ), get_option( 'default_ping_status' ), get_option( 'default_pingback_flag' ) );
		$this->plugin->policy()->apply_all();
		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );

		$outcome = $this->plugin->policy()->rollback();
		$this->assertSame( array(), $outcome['conflicts'] );
		$this->assertSame( array( 'comments' ), $outcome['disabled'], 'A control whose settings were all handed back must not re-apply them.' );
		$this->assertSame( $before, array( get_option( 'default_comment_status' ), get_option( 'default_ping_status' ), get_option( 'default_pingback_flag' ) ) );
		$this->assertFalse( $this->plugin->settings()->control_enabled( 'comments' ) );
		$this->assertSame( array(), $this->rollback->entries() );
	}

	public function test_policy_rollback_with_a_conflict_keeps_the_control_enabled() {
		$this->plugin->policy()->apply_all();
		update_option( 'default_ping_status', 'something-else' );

		$outcome = $this->plugin->policy()->rollback();
		$this->assertSame( array( 'default_ping_status' ), $outcome['conflicts'] );
		$this->assertSame( array(), $outcome['disabled'] );
		$this->assertTrue( $this->plugin->settings()->control_enabled( 'comments' ), 'Not everything could be handed back, so the control keeps owning its remaining setting.' );
		$this->assertSame( 'something-else', get_option( 'default_ping_status' ) );
		$this->assertSame( 'open', get_option( 'default_comment_status' ), 'The non-conflicting options were restored.' );
	}

	public function test_turning_a_control_off_releases_its_options_and_turning_it_on_claims_them() {
		add_action( 'update_option_' . \WP_Security_Lockdown\Settings_Repository::OPTION, array( $this->plugin, 'on_settings_updated' ), 10, 2 );

		$this->plugin->settings()->update( array( 'comments' => array( 'enabled' => true ) ) );
		$this->plugin->policy()->apply_all();
		$this->assertSame( 'closed', get_option( 'default_comment_status' ) );

		$this->plugin->settings()->update( array( 'comments' => array( 'enabled' => false ) ) );
		$this->assertSame( 'open', get_option( 'default_comment_status' ), 'Disabling the control hands the setting back.' );

		$this->plugin->settings()->update( array( 'comments' => array( 'enabled' => true ) ) );
		$this->assertSame( 'closed', get_option( 'default_comment_status' ), 'Enabling it again takes the setting over again.' );
		$this->assertSame( 'open', $this->rollback->entries()['default_comment_status']['original'] );
	}

	public function test_saving_unrelated_settings_does_not_touch_persistent_options() {
		add_action( 'update_option_' . \WP_Security_Lockdown\Settings_Repository::OPTION, array( $this->plugin, 'on_settings_updated' ), 10, 2 );
		$this->plugin->policy()->apply_all();
		update_option( 'default_comment_status', 'open' ); // Admin deliberately re-opened it.

		$this->plugin->settings()->update( array( 'login' => array( 'max_attempts' => 7 ) ) );
		$this->assertSame( 'open', get_option( 'default_comment_status' ), 'Only an explicit apply may re-assert the policy over a changed value.' );
	}

	public function test_unrelated_options_are_never_touched() {
		$watched = array( 'blogname', 'admin_email', 'default_role', 'users_can_register', 'comment_registration', 'close_comments_for_old_posts', 'blogdescription', 'permalink_structure', 'show_avatars' );
		$before  = array();
		foreach ( $watched as $option ) {
			$before[ $option ] = get_option( $option );
		}
		$this->plugin->policy()->apply_all();
		$this->plugin->policy()->apply_all();
		$this->plugin->policy()->rollback();
		foreach ( $watched as $option ) {
			$this->assertSame( $before[ $option ], get_option( $option ), "$option must not be changed by the plugin" );
		}
	}

	public function test_describe_reports_the_state_of_each_entry_for_the_dashboard() {
		$this->rollback->claim( 'default_comment_status', 'closed', 'comments' );
		$this->rollback->claim( 'default_ping_status', 'closed', 'comments' );
		update_option( 'default_ping_status', 'open' );
		update_option( 'default_pingback_flag', '0' );
		$this->rollback->claim( 'default_pingback_flag', '0', 'comments' );

		$rows = array_column( $this->rollback->describe(), 'sync', 'option' );
		$this->assertSame( 'in_sync', $rows['default_comment_status'] );
		$this->assertSame( 'drifted', $rows['default_ping_status'] );
		$this->assertSame( 'untouched', $rows['default_pingback_flag'] );
	}
}
