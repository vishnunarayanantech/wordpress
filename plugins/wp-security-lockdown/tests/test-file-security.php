<?php
/**
 * File editor protection, wp-config.php inspection and filesystem diagnostics.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Modules\File_Security;
use WP_Security_Lockdown\Wp_Config_Inspector;

class Test_File_Security extends Test_Case {

	/** @var string[] Temporary paths to remove. */
	private $cleanup = array();

	public function set_up() {
		parent::set_up();
		$this->configure();
	}

	public function tear_down() {
		foreach ( array_reverse( $this->cleanup ) as $path ) {
			if ( is_dir( $path ) ) {
				chmod( $path, 0755 );
				$this->remove_tree( $path );
			} elseif ( file_exists( $path ) ) {
				chmod( $path, 0644 );
				unlink( $path );
			}
		}
		parent::tear_down();
	}

	private function remove_tree( $dir ) {
		foreach ( new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $dir, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::CHILD_FIRST ) as $item ) {
			$item->isDir() ? rmdir( $item->getPathname() ) : unlink( $item->getPathname() );
		}
		rmdir( $dir );
	}

	private function fixture( $contents ) {
		$path = wp_tempnam( 'wpsl-config' );
		file_put_contents( $path, $contents );
		$this->cleanup[] = $path;
		return $path;
	}

	private function files() {
		return $this->module( 'file_security' );
	}

	private function find( array $rows, $id ) {
		foreach ( $rows as $row ) {
			if ( $row['id'] === $id ) {
				return $row;
			}
		}
		$this->fail( "No diagnostics row $id" );
	}

	/** ---------------------------------------------------------------- the editor control */

	public function test_the_code_editors_are_denied_but_updates_and_installs_are_untouched() {
		$admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		foreach ( array( 'edit_plugins', 'edit_themes', 'edit_files' ) as $cap ) {
			$this->assertFalse( user_can( $admin, $cap ), "$cap must be denied" );
		}
		foreach ( array( 'update_plugins', 'install_plugins', 'update_core', 'activate_plugins', 'edit_posts', 'manage_options' ) as $cap ) {
			$this->assertTrue( user_can( $admin, $cap ), "$cap must NOT be affected: this plugin never disables updates" );
		}
	}

	public function test_the_capability_filter_denies_independently_of_the_constant() {
		$module = $this->files();
		foreach ( array( 'edit_plugins', 'edit_themes', 'edit_files' ) as $cap ) {
			$this->assertSame( array( 'do_not_allow' ), $module->deny_editor_caps( array( $cap ), $cap ), "Even if wp-config.php said false, $cap is denied by the filter" );
		}
		$this->assertSame( array( 'edit_posts' ), $module->deny_editor_caps( array( 'edit_posts' ), 'edit_posts' ) );
		$this->assertSame( array( 'update_plugins' ), $module->deny_editor_caps( array( 'update_plugins' ), 'update_plugins' ) );
	}

	public function test_the_constant_is_defined_when_nothing_else_defined_it() {
		$this->assertTrue( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT );
		$this->assertFalse( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS, 'DISALLOW_FILE_MODS would block updates and must never be set by this plugin.' );
	}

	public function test_when_the_control_is_off_nothing_is_registered() {
		$this->configure( array( 'files' => array( 'file_editor' => false ) ) );
		$this->assertFalse( has_filter( 'map_meta_cap', array( $this->files(), 'deny_editor_caps' ) ) );
		$this->assertSame( 'disabled', $this->files()->report()['file_editor']['state'] );
		$this->assertSame( array(), $this->files()->verify() );
	}

	public function test_verification_passes_and_can_fail() {
		$this->assertSame( 'verified', $this->files()->verify()['file_editor']['status'] );
		$this->assertSame( 'in_process', $this->files()->verify()['file_editor']['method'] );
	}

	public function test_a_missing_filter_is_reported_as_failed() {
		$this->strip_plugin_hooks();
		$this->assertSame( 'failed', $this->files()->report()['file_editor']['state'] );
	}

	/** ---------------------------------------------------------------- wp-config.php inspection */

	/**
	 * @dataProvider config_cases
	 */
	public function test_wp_config_detection( $source, $defined, $literal, $value ) {
		$result = ( new Wp_Config_Inspector( $this->fixture( "<?php\n" . $source ) ) )->constant( 'DISALLOW_FILE_EDIT' );
		$this->assertSame( $defined, $result['defined'], 'defined' );
		$this->assertSame( $literal, $result['literal'], 'literal' );
		$this->assertSame( $value, $result['value'], 'value' );
	}

	public function config_cases() {
		return array(
			'plain true'                 => array( "define( 'DISALLOW_FILE_EDIT', true );", true, true, true ),
			'plain false'                => array( "define( 'DISALLOW_FILE_EDIT', false );", true, true, false ),
			'compact spacing'            => array( "define('DISALLOW_FILE_EDIT',true);", true, true, true ),
			'uppercase TRUE'             => array( "define( 'DISALLOW_FILE_EDIT', TRUE );", true, true, true ),
			'double quotes'              => array( 'define( "DISALLOW_FILE_EDIT", true );', true, true, true ),
			'integer one'                => array( "define( 'DISALLOW_FILE_EDIT', 1 );", true, true, true ),
			'integer zero'               => array( "define( 'DISALLOW_FILE_EDIT', 0 );", true, true, false ),
			'leading backslash'          => array( "\\define( 'DISALLOW_FILE_EDIT', true );", true, true, true ),
			'guarded by defined()'       => array( "if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) { define( 'DISALLOW_FILE_EDIT', true ); }", true, true, true ),
			'computed value'             => array( "define( 'DISALLOW_FILE_EDIT', ! WP_DEBUG );", true, false, null ),
			'constant value'             => array( "define( 'DISALLOW_FILE_EDIT', SOME_OTHER_CONSTANT );", true, false, null ),
			'line comment'               => array( "// define( 'DISALLOW_FILE_EDIT', true );", false, false, null ),
			'hash comment'               => array( "# define( 'DISALLOW_FILE_EDIT', true );", false, false, null ),
			'block comment'              => array( "/* define( 'DISALLOW_FILE_EDIT', true ); */", false, false, null ),
			'doc comment'                => array( "/** define( 'DISALLOW_FILE_EDIT', true ); */", false, false, null ),
			'inside a string'            => array( "\$x = \"define( 'DISALLOW_FILE_EDIT', true );\";", false, false, null ),
			'inside a heredoc'           => array( "\$x = <<<TXT\ndefine( 'DISALLOW_FILE_EDIT', true );\nTXT;\n", false, false, null ),
			'different constant'         => array( "define( 'DISALLOW_FILE_MODS', true );", false, false, null ),
			'prefix of another constant' => array( "define( 'DISALLOW_FILE_EDIT_X', true );", false, false, null ),
			'not defined at all'         => array( "\$table_prefix = 'wp_';", false, false, null ),
			'last definition wins'       => array( "define( 'DISALLOW_FILE_EDIT', false );\ndefine( 'DISALLOW_FILE_EDIT', true );", true, true, true ),
		);
	}

	public function test_secrets_in_wp_config_can_never_be_read_through_the_inspector() {
		$path = $this->fixture( "<?php\ndefine( 'DB_PASSWORD', 'hunter2-super-secret' );\ndefine( 'AUTH_KEY', 'abcdef' );\ndefine( 'DB_USER', 'root' );\ndefine( 'WP_DEBUG', true );\n" );
		$ins  = new Wp_Config_Inspector( $path );

		foreach ( array( 'DB_PASSWORD', 'AUTH_KEY', 'DB_USER', 'DB_NAME', 'NONCE_SALT' ) as $name ) {
			$result = $ins->constant( $name );
			$this->assertFalse( $result['defined'], "$name is not inspectable even though it appears in the file" );
			$this->assertNull( $result['value'] );
		}
		$this->assertStringNotContainsString( 'hunter2', wp_json_encode( $ins->constant( 'WP_DEBUG' ) ) );
		$this->assertTrue( $ins->constant( 'WP_DEBUG' )['value'], 'Allowlisted, non-secret constants work.' );
		foreach ( ( new \ReflectionClass( $ins ) )->getMethods( \ReflectionMethod::IS_PUBLIC ) as $method ) {
			$this->assertNotContains( $method->getName(), array( 'contents', 'raw', 'source', 'read' ), 'No public way to read the file.' );
		}
	}

	public function test_a_missing_empty_or_oversized_config_is_handled() {
		$this->assertFalse( ( new Wp_Config_Inspector( '/nonexistent/wp-config.php' ) )->readable() );
		$this->assertFalse( ( new Wp_Config_Inspector( '/nonexistent/wp-config.php' ) )->constant( 'DISALLOW_FILE_EDIT' )['defined'] );
		$this->assertFalse( ( new Wp_Config_Inspector( $this->fixture( '' ) ) )->constant( 'DISALLOW_FILE_EDIT' )['defined'] );

		$big = $this->fixture( "<?php\n" . str_repeat( '// padding ', Wp_Config_Inspector::MAX_BYTES / 8 ) . "\ndefine( 'DISALLOW_FILE_EDIT', true );" );
		$this->assertFalse( ( new Wp_Config_Inspector( $big ) )->constant( 'DISALLOW_FILE_EDIT' )['defined'], 'An enormous file is not parsed (resource bound).' );
	}

	public function test_a_file_that_is_not_php_cannot_break_the_parser() {
		foreach ( array( "\xff\xfe\x00binary", '<?php define(', "<?php\ndefine( 'DISALLOW_FILE_EDIT'", '<?php ))) ((( ;;; "unterminated' ) as $junk ) {
			$this->assertFalse( ( new Wp_Config_Inspector( $this->fixture( $junk ) ) )->constant( 'DISALLOW_FILE_EDIT' )['defined'] );
		}
	}

	public function test_the_inspector_never_modifies_the_file() {
		$path = $this->fixture( "<?php\ndefine( 'DISALLOW_FILE_EDIT', false );\n" );
		chmod( $path, 0444 );
		$before = array( filemtime( $path ), md5_file( $path ), fileperms( $path ) );
		$ins    = new Wp_Config_Inspector( $path );
		$ins->constant( 'DISALLOW_FILE_EDIT' );
		$ins->readable();
		$ins->locate();
		clearstatcache();
		$this->assertSame( $before, array( filemtime( $path ), md5_file( $path ), fileperms( $path ) ) );
	}

	public function test_the_report_tells_the_administrator_what_wp_config_says() {
		// The real wp-config.php of the test installation does not define the constant.
		$text = wp_json_encode( $this->files()->report()['file_editor']['details'] );
		$this->assertStringContainsString( 'DISALLOW_FILE_EDIT', $text );
		$this->assertStringContainsString( 'never edits wp-config.php', $text );
	}

	/** ---------------------------------------------------------------- diagnostics */

	public function test_wp_config_permissions_are_classified() {
		$config = ( new Wp_Config_Inspector() )->locate();
		$this->assertNotNull( $config );
		$original = fileperms( $config ) & 0777;
		try {
			foreach ( array(
				0600 => 'pass',
				0640 => 'pass',
				0660 => 'warn',
				0644 => 'fail',
				0666 => 'fail',
				0602 => 'fail',
			) as $mode => $expected ) {
				chmod( $config, $mode );
				clearstatcache();
				$row = $this->find( $this->files()->diagnostics( false ), 'wp_config_permissions' );
				$this->assertSame( $expected, $row['status'], sprintf( 'mode %04o', $mode ) );
				if ( 'pass' !== $expected ) {
					$this->assertNotSame( '', $row['remediation'] );
					$this->assertSame( 'server', $row['requires'] );
				}
			}
		} finally {
			chmod( $config, $original );
		}
	}

	public function test_world_writable_directories_are_reported_and_never_changed() {
		$uploads = wp_upload_dir( null, false )['basedir'];
		wp_mkdir_p( $uploads );
		$this->cleanup[] = $uploads . '/wpsl-perm-probe';
		wp_mkdir_p( $uploads . '/wpsl-perm-probe' );
		$original = fileperms( $uploads ) & 0777;
		chmod( $uploads, 0777 );
		try {
			clearstatcache();
			$row = $this->find( $this->files()->diagnostics( false ), 'directory_permissions' );
			$this->assertSame( 'fail', $row['status'] );
			$this->assertStringContainsString( 'uploads', $row['summary'] );
			clearstatcache();
			$this->assertSame( 0777, fileperms( $uploads ) & 0777, 'Diagnostics must never change permissions.' );
		} finally {
			chmod( $uploads, $original );
		}
		clearstatcache();
		$this->assertSame( 'pass', $this->find( $this->files()->diagnostics( false ), 'directory_permissions' )['status'] );
	}

	public function test_executable_files_in_uploads_are_found_and_listed_without_being_touched() {
		$uploads = wp_upload_dir( null, false )['basedir'];
		$dir     = $uploads . '/wpsl-scan/2026/10';
		wp_mkdir_p( $dir );
		$this->cleanup[] = $uploads . '/wpsl-scan';
		foreach ( array( 'shell.php', 'double.php.jpg', 'alt.phtml', 'archive.phar', 'fine.jpg', 'notes.txt' ) as $name ) {
			file_put_contents( $dir . '/' . $name, 'x' );
		}
		$before = scandir( $dir );

		$row = $this->find( $this->files()->diagnostics( true ), 'uploads_exec' );
		$this->assertSame( 'fail', $row['status'] );
		foreach ( array( 'shell.php', 'double.php.jpg', 'alt.phtml', 'archive.phar' ) as $name ) {
			$this->assertStringContainsString( $name, $row['summary'] );
		}
		$this->assertStringNotContainsString( 'fine.jpg', $row['summary'] );
		$this->assertSame( 'server', $row['requires'], 'Only the web server can stop PHP executing there.' );
		$this->assertSame( $before, scandir( $dir ), 'The scan only reads.' );
	}

	public function test_a_clean_uploads_directory_still_needs_a_server_rule_unless_one_is_detected() {
		$uploads = wp_upload_dir( null, false )['basedir'];
		wp_mkdir_p( $uploads );
		$this->cleanup[] = $uploads . '/.htaccess';
		@unlink( $uploads . '/.htaccess' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged

		$row = $this->find( $this->files()->diagnostics( true ), 'uploads_exec' );
		$this->assertSame( 'warn', $row['status'] );
		$this->assertStringContainsString( 'cannot enforce', $row['remediation'] );

		file_put_contents( $uploads . '/.htaccess', "<FilesMatch \"\\.php\$\">\nRequire all denied\n</FilesMatch>\n" );
		$row = $this->find( $this->files()->diagnostics( true ), 'uploads_exec' );
		$this->assertSame( 'pass', $row['status'] );
		$this->assertStringContainsString( 'heuristic', $row['summary'], 'Detection from PHP is never presented as proof.' );
	}

	public function test_the_uploads_scan_is_bounded() {
		$uploads = wp_upload_dir( null, false )['basedir'];
		$dir     = $uploads . '/wpsl-many';
		wp_mkdir_p( $dir );
		$this->cleanup[] = $dir;
		for ( $i = 0; $i < File_Security::SCAN_LIMIT + 25; $i++ ) {
			touch( $dir . '/f' . $i . '.jpg' );
		}
		$start = microtime( true );
		$row   = $this->find( $this->files()->diagnostics( true ), 'uploads_exec' );
		$this->assertStringContainsString( 'scan limit reached', $row['summary'] );
		$this->assertLessThan( 5, microtime( true ) - $start );
	}

	public function test_a_missing_uploads_directory_is_not_an_error() {
		add_filter(
			'upload_dir',
			static function ( $dirs ) {
				$dirs['basedir'] = '/nonexistent/uploads';
				return $dirs;
			}
		);
		$row = $this->find( $this->files()->diagnostics( true ), 'uploads_exec' );
		$this->assertSame( 'info', $row['status'] );
		$this->assertFalse( is_dir( '/nonexistent/uploads' ), 'Diagnostics must not create directories.' );
	}

	public function test_every_diagnostics_row_has_the_documented_shape() {
		foreach ( $this->files()->diagnostics( true ) as $row ) {
			foreach ( array( 'id', 'group', 'title', 'status', 'summary', 'remediation', 'requires' ) as $key ) {
				$this->assertArrayHasKey( $key, $row );
			}
			$this->assertContains( $row['status'], array( 'pass', 'warn', 'fail', 'info' ) );
			$this->assertContains( $row['requires'], array( '', 'manual', 'server' ) );
		}
	}
}
