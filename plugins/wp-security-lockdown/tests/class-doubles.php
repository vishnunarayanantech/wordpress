<?php
/**
 * Test doubles shared by several test files.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Abstract_Module;
use WP_Security_Lockdown\Plugin;
use WP_Security_Lockdown\Policy_Manager;

/**
 * A module that always throws, to prove one broken module cannot take the site down.
 */
class Throwing_Module extends Abstract_Module {
	public function slug() {
		return 'throwing';
	}
	public function controls() {
		return array();
	}
	public function register() {
		throw new \RuntimeException( 'boom: secret detail that must not be logged' );
	}
	public function report() {
		throw new \RuntimeException( 'report boom' );
	}
}

/**
 * Policy manager whose first module explodes.
 */
class Policy_Manager_With_Broken_Module extends Policy_Manager {
	private $plugin_ref;
	public function __construct( Plugin $plugin ) {
		parent::__construct( $plugin );
		$this->plugin_ref = $plugin;
	}
	public function modules() {
		$modules = parent::modules();
		if ( 'throwing' !== $modules[0]->slug() ) {
			array_unshift( $modules, new Throwing_Module( $this->plugin_ref ) );
			$property = new \ReflectionProperty( Policy_Manager::class, 'modules' );
			$property->setAccessible( true );
			$property->setValue( $this, $modules );
		}
		return $modules;
	}
}
