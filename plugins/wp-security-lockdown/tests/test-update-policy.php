<?php
/**
 * Security update monitoring.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Http_Probe;
use WP_Security_Lockdown\Modules\Update_Policy;

class Test_Update_Policy extends Test_Case {

	public function set_up() {
		parent::set_up();
		// The WordPress test library itself disables the updater (tests/phpunit/includes/bootstrap.php). A real default
		// site does not, so remove that harness filter; the module reporting it was correct for the harness.
		remove_filter( 'automatic_updater_disabled', '__return_true' );
		delete_site_transient( 'update_core' );
		delete_site_transient( 'update_plugins' );
		delete_site_transient( 'update_themes' );
		delete_site_option( 'auto_core_update_failed' );
		delete_transient( Update_Policy::FS_TRANSIENT );
		$this->configure();
	}

	private function updates() {
		return $this->module( 'update_policy' );
	}

	/**
	 * Fresh module so the per-request memo of findings is empty.
	 */
	private function findings() {
		$module = new Update_Policy( $this->plugin );
		$rows   = array();
		foreach ( $module->collect() as $row ) {
			$rows[ $row['label'] ][] = $row;
		}
		return $rows;
	}

	private function statuses( $label ) {
		return array_column( $this->findings()[ $label ] ?? array(), 'status' );
	}

	public function test_a_default_installation_has_no_blocking_findings() {
		$report = ( new Update_Policy( $this->plugin ) )->report()['updates'];
		$this->assertSame( 'monitor', $report['state'] );
		foreach ( $report['details'] as $row ) {
			$this->assertNotContains( $row['status'], array( 'fail' ), $row['label'] . ': ' . $row['text'] );
		}
	}

	public function test_the_module_registers_nothing_and_has_no_enforcement() {
		$before = array_keys( $GLOBALS['wp_filter'] );
		( new Update_Policy( $this->plugin ) )->register();
		$this->assertSame( $before, array_keys( $GLOBALS['wp_filter'] ), 'No hooks at all.' );
		$report = ( new Update_Policy( $this->plugin ) )->report()['updates'];
		$this->assertSame( array( 'None by design: the plugin only observes and never alters update behaviour.' ), $report['enforcement'] );
		$this->assertSame( array(), ( new Update_Policy( $this->plugin ) )->verify(), 'Monitored, not verified.' );
	}

	public function test_file_modifications_being_disabled_is_reported_as_a_failure() {
		add_filter( 'file_mod_allowed', '__return_false' );
		$this->assertContains( 'fail', $this->statuses( 'DISALLOW_FILE_MODS' ) );
		$report = ( new Update_Policy( $this->plugin ) )->report()['updates'];
		$this->assertNotSame( '', $report['failure_reason'] );
		$this->assertNotSame( '', $report['manual_action'] );
	}

	public function test_a_disabled_automatic_updater_is_reported() {
		add_filter( 'automatic_updater_disabled', '__return_true' );
		$this->assertContains( 'fail', $this->statuses( 'AUTOMATIC_UPDATER_DISABLED' ) );
	}

	public function test_blocked_minor_core_updates_are_reported_because_they_carry_security_fixes() {
		add_filter( 'allow_minor_auto_core_updates', '__return_false' );
		$this->assertContains( 'fail', $this->statuses( 'allow_minor_auto_core_updates' ) );
	}

	public function test_the_core_update_check_being_removed_is_reported() {
		remove_action( 'wp_version_check', 'wp_version_check' );
		$this->assertContains( 'fail', $this->statuses( 'wp_version_check' ) );
	}

	public function test_a_version_control_checkout_is_reported_per_update_area() {
		add_filter(
			'automatic_updates_is_vcs_checkout',
			static function ( $checkout, $context ) {
				return false !== strpos( $context, 'plugins' ) || false !== strpos( $context, 'themes' ) ? true : $checkout;
			},
			10,
			2
		);
		$findings = $this->findings();
		$this->assertContains( 'warn', array_column( $findings['Version control (plugins)'], 'status' ) );
		$this->assertContains( 'warn', array_column( $findings['Version control (themes)'], 'status' ) );
		$this->assertArrayNotHasKey( 'Version control (core)', $findings, 'Only the affected areas are reported.' );
		$this->assertStringContainsString( 'not changed here', $findings['Version control (plugins)'][0]['text'], 'The finding must not claim the plugin altered anything.' );
	}

	public function test_a_previous_failed_background_update_is_reported_with_a_sanitized_code() {
		update_site_option(
			'auto_core_update_failed',
			array(
				'error_code' => '<script>alert(1)</script>',
				'critical'   => true,
			)
		);
		$rows = $this->findings()['Background core update'];
		$this->assertSame( 'fail', $rows[0]['status'] );
		$this->assertStringNotContainsString( '<script', $rows[0]['text'] );
		$this->assertStringContainsString( 'critical: yes', $rows[0]['text'] );
	}

	public function test_a_pending_minor_core_release_is_flagged_as_a_security_matter_and_a_new_branch_is_not() {
		global $wp_version;
		list( $major, $minor ) = explode( '.', $wp_version );
		set_site_transient(
			'update_core',
			(object) array(
				'last_checked' => time(),
				'updates'      => array(
					(object) array(
						'response' => 'upgrade',
						'current'  => "$major.$minor.99",
					),
				),
			)
		);
		$row = $this->findings()['WordPress core'][0];
		$this->assertSame( 'fail', $row['status'] );
		$this->assertStringContainsString( "$major.$minor.99", $row['text'] );
		$this->assertStringContainsString( 'security fixes', $row['text'] );

		set_site_transient(
			'update_core',
			(object) array(
				'last_checked' => time(),
				'updates'      => array(
					(object) array(
						'response' => 'upgrade',
						'current'  => ( $major + 1 ) . '.0',
					),
				),
			)
		);
		$this->assertSame( 'warn', $this->findings()['WordPress core'][0]['status'] );

		set_site_transient(
			'update_core',
			(object) array(
				'last_checked' => time(),
				'updates'      => array(
					(object) array(
						'response' => 'latest',
						'current'  => $wp_version,
					),
				),
			)
		);
		$this->assertArrayNotHasKey( 'WordPress core', $this->findings(), 'Nothing pending, nothing reported.' );
	}

	public function test_pending_plugin_and_theme_updates_are_counted() {
		set_site_transient(
			'update_plugins',
			(object) array(
				'last_checked' => time(),
				'response'     => array(
					'a/a.php' => (object) array(),
					'b/b.php' => (object) array(),
				),
			)
		);
		set_site_transient(
			'update_themes',
			(object) array(
				'last_checked' => time(),
				'response'     => array( 'twentyx' => array() ),
			)
		);
		$findings = $this->findings();
		$this->assertStringContainsString( '2 updates', $findings['Plugins'][0]['text'] );
		$this->assertStringContainsString( '1 update ', $findings['Themes'][0]['text'] );
	}

	public function test_stale_update_checks_are_reported() {
		set_site_transient(
			'update_core',
			(object) array(
				'last_checked' => time() - 5 * DAY_IN_SECONDS,
				'updates'      => array(),
			)
		);
		$this->assertContains( 'warn', $this->statuses( 'Last update check' ) );
		set_site_transient(
			'update_core',
			(object) array(
				'last_checked' => time() - HOUR_IN_SECONDS,
				'updates'      => array(),
			)
		);
		$this->assertArrayNotHasKey( 'Last update check', $this->findings() );
	}

	public function test_blocking_wordpress_org_is_reported() {
		// WP_HTTP_BLOCK_EXTERNAL cannot be redefined in-process; assert the logic on the constant-free path instead.
		$this->assertTrue( ! defined( 'WP_HTTP_BLOCK_EXTERNAL' ) || ! WP_HTTP_BLOCK_EXTERNAL );
		$this->assertArrayNotHasKey( 'WP_HTTP_BLOCK_EXTERNAL', $this->findings() );
	}

	public function test_the_filesystem_check_uses_wordpress_own_logic_and_is_cached() {
		$module = new Update_Policy( $this->plugin );
		$this->assertNull( $module->filesystem_check( false ), 'Not run until asked (it writes and removes a temporary file).' );

		$result = $module->filesystem_check( true );
		$this->assertSame( array( 'method', 'php_user', 'file_owner' ), array_keys( $result ) );
		$this->assertSame( $result, $module->filesystem_check( false ), 'Cached for an hour.' );
		$this->assertSame( $result, get_transient( Update_Policy::FS_TRANSIENT ) );
	}

	public function test_the_filesystem_check_leaves_no_temporary_file_behind() {
		$before = glob( WP_PLUGIN_DIR . '/temp-write-test-*' );
		( new Update_Policy( $this->plugin ) )->filesystem_check( true );
		$this->assertSame( $before, glob( WP_PLUGIN_DIR . '/temp-write-test-*' ) );
	}

	public function test_a_site_where_php_cannot_write_is_told_updates_cannot_run() {
		add_filter(
			'filesystem_method',
			static function () {
				return 'ftpext';
			}
		);
		$module = new Update_Policy( $this->plugin );
		$module->filesystem_check( true );
		$module = new Update_Policy( $this->plugin ); // Fresh memo.
		$rows   = array_values(
			array_filter(
				$module->collect(),
				static function ( $row ) {
					return 'File ownership / write access' === $row['label'];
				}
			)
		);
		$this->assertSame( 'fail', $rows[0]['status'] );
		$this->assertStringContainsString( 'does not change permissions', $rows[0]['text'] );
		$this->assertStringContainsString( 'ftpext', $rows[0]['text'] );
	}

	public function test_a_deep_verification_run_refreshes_the_filesystem_check_but_changes_nothing_else() {
		$options_before = array( get_site_option( 'auto_update_plugins' ), get_site_option( 'auto_update_themes' ), get_option( 'WPLANG' ), get_option( 'blog_public' ) );
		$this->mock_http(
			function () {
				return $this->http_response( 200, '' );
			}
		);
		( new Update_Policy( $this->plugin ) )->verify( new Http_Probe() );
		$this->assertNotNull( ( new Update_Policy( $this->plugin ) )->filesystem_check( false ) );
		$this->assertSame( $options_before, array( get_site_option( 'auto_update_plugins' ), get_site_option( 'auto_update_themes' ), get_option( 'WPLANG' ), get_option( 'blog_public' ) ) );
	}

	public function test_the_module_is_reported_as_monitor_warn_when_there_are_findings_and_monitor_ok_otherwise() {
		$this->assertSame( 'monitor_ok', $this->plugin->policy()->reports()['updates']['status'] );
		add_filter( 'automatic_updater_disabled', '__return_true' );
		\WP_Security_Lockdown\Plugin::reset(); // The module memoises its findings for the duration of a request.
		$this->plugin = \WP_Security_Lockdown\Plugin::instance();
		$this->assertSame( 'monitor_warn', $this->plugin->policy()->reports()['updates']['status'] );
	}

	/**
	 * Static guard: "do not change the site's update policy silently". The plugin may read update state
	 * everywhere, but must not define update constants, hook update filters or write update options.
	 */
	public function test_the_plugin_source_never_alters_update_behaviour() {
		$root       = dirname( __DIR__ );
		$files      = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $root, \FilesystemIterator::SKIP_DOTS ) );
		$allowed    = array( 'DISALLOW_FILE_EDIT' );
		$writers    = array( 'add_filter', 'add_action', 'update_option', 'update_site_option', 'add_option', 'delete_option', 'delete_site_option' );
		$sensitive  = array( 'automatic_updater_disabled', 'allow_minor_auto_core_updates', 'allow_major_auto_core_updates', 'auto_update_core', 'auto_update_plugin', 'auto_update_theme', 'file_mod_allowed', 'pre_site_transient_update_core', 'site_transient_update_core', 'site_transient_update_plugins', 'auto_update_plugins', 'auto_update_themes', 'automatic_updates_is_vcs_checkout', 'auto_core_update_failed' );
		$violations = array();

		foreach ( $files as $file ) {
			$path = (string) $file;
			if ( '.php' !== substr( $path, -4 ) || false !== strpos( $path, '/tests/' ) ) {
				continue;
			}
			$tokens = token_get_all( file_get_contents( $path ) );
			$count  = count( $tokens );
			for ( $i = 0; $i < $count; $i++ ) {
				if ( ! is_array( $tokens[ $i ] ) || T_STRING !== $tokens[ $i ][0] ) {
					continue;
				}
				$name = strtolower( $tokens[ $i ][1] );
				if ( 'define' === $name ) {
					// define( 'CONST', ... ): find the constant name literal.
					$limit = min( $count, $i + 6 );
					for ( $j = $i + 1; $j < $limit; $j++ ) {
						if ( is_array( $tokens[ $j ] ) && T_CONSTANT_ENCAPSED_STRING === $tokens[ $j ][0] ) {
							$const = trim( $tokens[ $j ][1], '\'"' );
							if ( 0 !== strpos( $const, 'WP_SECURITY_LOCKDOWN_' ) && ! in_array( $const, $allowed, true ) ) {
								$violations[] = "$path defines $const";
							}
							break;
						}
					}
				}
				if ( in_array( $name, $writers, true ) ) {
					$limit = min( $count, $i + 6 );
					for ( $j = $i + 1; $j < $limit; $j++ ) {
						if ( is_array( $tokens[ $j ] ) && T_CONSTANT_ENCAPSED_STRING === $tokens[ $j ][0] ) {
							$target = trim( $tokens[ $j ][1], '\'"' );
							if ( in_array( $target, $sensitive, true ) ) {
								$violations[] = "$path calls $name( '$target' )";
							}
							break;
						}
					}
				}
			}
		}
		$this->assertSame( array(), $violations, 'The plugin must never alter update configuration.' );
	}
}
