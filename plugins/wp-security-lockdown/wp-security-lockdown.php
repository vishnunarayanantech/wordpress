<?php
/**
 * Plugin Name:       WP Security Lockdown
 * Description:       Applies a maximum-security hardening policy (comments, XML-RPC, REST API, login protection, information disclosure, file editor) and reports which controls are configured, enforced and actually verified.
 * Version:           1.0.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            WP Security Lockdown contributors
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wp-security-lockdown
 *
 * @package WP_Security_Lockdown
 */

defined( 'ABSPATH' ) || exit;

// A second copy of the plugin (e.g. a renamed folder) must not redeclare anything.
if ( defined( 'WP_SECURITY_LOCKDOWN_VERSION' ) ) {
	return;
}

define( 'WP_SECURITY_LOCKDOWN_VERSION', '1.0.0' );
define( 'WP_SECURITY_LOCKDOWN_FILE', __FILE__ );
define( 'WP_SECURITY_LOCKDOWN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WP_SECURITY_LOCKDOWN_MIN_PHP', '7.4' );
define( 'WP_SECURITY_LOCKDOWN_MIN_WP', '6.0' );

/**
 * Prints notices. Used only on the inert code paths below, so it must not depend on any plugin class.
 *
 * @param string[] $messages Plain-text messages.
 * @return void
 */
function wp_security_lockdown_print_notice( array $messages ) {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	foreach ( $messages as $message ) {
		printf( '<div class="notice notice-warning"><p><strong>WP Security Lockdown:</strong> %s</p></div>', esc_html( $message ) );
	}
}

/**
 * Returns human-readable reasons why the plugin cannot run on this installation.
 *
 * @param string|null $php_version       PHP version to test (defaults to the running one; for tests).
 * @param string|null $wordpress_version WordPress version to test (defaults to the running one; for tests).
 * @return string[] Empty when the environment is supported.
 */
function wp_security_lockdown_compatibility_errors( $php_version = null, $wordpress_version = null ) {
	global $wp_version;

	$php_version       = null === $php_version ? PHP_VERSION : $php_version;
	$wordpress_version = null === $wordpress_version ? $wp_version : $wordpress_version;
	$errors            = array();
	if ( version_compare( $php_version, WP_SECURITY_LOCKDOWN_MIN_PHP, '<' ) ) {
		$errors[] = sprintf( 'PHP %1$s or newer is required (this server runs %2$s).', WP_SECURITY_LOCKDOWN_MIN_PHP, $php_version );
	}
	if ( version_compare( $wordpress_version, WP_SECURITY_LOCKDOWN_MIN_WP, '<' ) ) {
		$errors[] = sprintf( 'WordPress %1$s or newer is required (this site runs %2$s).', WP_SECURITY_LOCKDOWN_MIN_WP, $wordpress_version );
	}
	return $errors;
}

/**
 * Activation entry point. Refuses to activate on an unsupported environment, otherwise delegates.
 *
 * @param bool $network_wide Whether the plugin is being network-activated.
 * @return void
 */
function wp_security_lockdown_activate( $network_wide = false ) {
	$errors = wp_security_lockdown_compatibility_errors();
	if ( $errors ) {
		deactivate_plugins( plugin_basename( WP_SECURITY_LOCKDOWN_FILE ) );
		wp_die(
			esc_html( 'WP Security Lockdown cannot be activated: ' . implode( ' ', $errors ) ),
			'Plugin activation failed',
			array( 'back_link' => true )
		);
	}
	\WP_Security_Lockdown\Activator::activate( $network_wide );
}

/*
 * Emergency kill switch. Add `define( 'WP_SECURITY_LOCKDOWN_DISABLE', true );` to wp-config.php
 * to make the plugin completely inert without touching the filesystem. Nothing is registered, no
 * policy is enforced and no stored data is changed. Documented in readme.txt.
 */
if ( defined( 'WP_SECURITY_LOCKDOWN_DISABLE' ) && WP_SECURITY_LOCKDOWN_DISABLE ) {
	add_action(
		'admin_notices',
		static function () {
			wp_security_lockdown_print_notice( array( 'The plugin is switched off by WP_SECURITY_LOCKDOWN_DISABLE in wp-config.php. No protections from this plugin are active.' ) );
		}
	);
	return;
}

// Registered before the compatibility gate so that activation can be refused cleanly.
register_activation_hook( __FILE__, 'wp_security_lockdown_activate' );

$wp_security_lockdown_errors = wp_security_lockdown_compatibility_errors();
if ( $wp_security_lockdown_errors ) {
	// Unsupported environment: stay inert and explain why, instead of risking a fatal error.
	add_action(
		'admin_notices',
		static function () use ( $wp_security_lockdown_errors ) {
			wp_security_lockdown_print_notice( $wp_security_lockdown_errors );
		}
	);
	return;
}
unset( $wp_security_lockdown_errors );

/**
 * Class autoloader: WP_Security_Lockdown\Foo_Bar         => includes/class-foo-bar.php
 *                   WP_Security_Lockdown\Modules\Foo_Bar => modules/class-foo-bar.php
 *                   WP_Security_Lockdown\Admin\Foo_Bar   => admin/class-foo-bar.php
 *
 * @param string $class_name Fully qualified class name.
 * @return void
 */
function wp_security_lockdown_autoload( $class_name ) {
	$prefix = 'WP_Security_Lockdown\\';
	if ( 0 !== strpos( $class_name, $prefix ) ) {
		return;
	}

	$parts = explode( '\\', substr( $class_name, strlen( $prefix ) ) );
	$name  = array_pop( $parts );
	if ( ! preg_match( '/^[A-Za-z][A-Za-z0-9_]*$/', $name ) ) {
		return;
	}

	$folder = $parts ? strtolower( implode( '/', $parts ) ) : 'includes';
	if ( ! in_array( $folder, array( 'includes', 'modules', 'admin' ), true ) ) {
		return;
	}

	$file = WP_SECURITY_LOCKDOWN_DIR . $folder . '/class-' . strtolower( str_replace( '_', '-', $name ) ) . '.php';
	if ( is_file( $file ) ) {
		require_once $file;
	}
}
spl_autoload_register( 'wp_security_lockdown_autoload' );

register_deactivation_hook( __FILE__, array( 'WP_Security_Lockdown\\Deactivator', 'deactivate' ) );

/**
 * Boots the plugin. Priority 0 so that request-level protections (for example rejecting xmlrpc.php)
 * run before any other plugin's `plugins_loaded` callback.
 *
 * @return void
 */
function wp_security_lockdown_boot() {
	\WP_Security_Lockdown\Plugin::instance()->boot();
}
add_action( 'plugins_loaded', 'wp_security_lockdown_boot', 0 );
