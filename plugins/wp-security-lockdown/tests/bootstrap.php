<?php
/**
 * PHPUnit bootstrap: loads the WordPress test library, then this plugin.
 *
 * Requirements (see readme.txt, "Running the tests"):
 *   WP_TESTS_DIR                      directory that contains includes/ and data/ of the WordPress test library
 *   WP_TESTS_CONFIG_FILE_PATH         (optional) full path to a wp-tests-config.php for a THROWAWAY database
 *   WP_TESTS_PHPUNIT_POLYFILLS_PATH   (optional) directory of yoast/phpunit-polyfills if not installed via Composer
 *
 * WARNING: the WordPress test library DROPS the tables of the configured test database. Never point it
 * at a database that holds real data.
 *
 * @package WP_Security_Lockdown
 */

$wpsl_tests_dir = getenv( 'WP_TESTS_DIR' );
if ( ! $wpsl_tests_dir || ! is_dir( $wpsl_tests_dir . '/includes' ) ) {
	fwrite( STDERR, "WP_TESTS_DIR must point to the WordPress test library (a directory containing includes/ and data/).\n" );
	exit( 1 );
}

foreach ( array( 'WP_TESTS_CONFIG_FILE_PATH', 'WP_TESTS_PHPUNIT_POLYFILLS_PATH' ) as $wpsl_const ) {
	if ( getenv( $wpsl_const ) && ! defined( $wpsl_const ) ) {
		define( $wpsl_const, getenv( $wpsl_const ) );
	}
}

require_once $wpsl_tests_dir . '/includes/functions.php';

tests_add_filter(
	'muplugins_loaded',
	static function () {
		require dirname( __DIR__ ) . '/wp-security-lockdown.php';
	}
);

require $wpsl_tests_dir . '/includes/bootstrap.php';
require_once __DIR__ . '/class-test-case.php';
require_once __DIR__ . '/class-doubles.php';
