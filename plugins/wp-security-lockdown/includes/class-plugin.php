<?php
/**
 * Service container and bootstrap.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Wires the plugin together. Services are created lazily so a request that needs none of them
 * (for example an anonymous front-end page view) pays for as little as possible.
 */
final class Plugin {

	const CRON_VERIFY  = 'wp_security_lockdown_verify_event';
	const OPTION_GROUP = 'wp_security_lockdown';

	/**
	 * Shared instance.
	 *
	 * @var Plugin|null
	 */
	private static $instance = null;

	/**
	 * Whether boot() has run.
	 *
	 * @var bool
	 */
	private $booted = false;

	/**
	 * Settings repository, created lazily.
	 *
	 * @var Settings_Repository|null
	 */
	private $settings = null;

	/**
	 * State repository, created lazily.
	 *
	 * @var State_Repository|null
	 */
	private $state = null;

	/**
	 * Audit logger, created lazily.
	 *
	 * @var Audit_Logger|null
	 */
	private $logger = null;

	/**
	 * Rollback service, created lazily.
	 *
	 * @var Rollback|null
	 */
	private $rollback = null;

	/**
	 * Policy manager, created lazily.
	 *
	 * @var Policy_Manager|null
	 */
	private $policy = null;

	/**
	 * Diagnostics, created lazily.
	 *
	 * @var Health_Check|null
	 */
	private $health = null;

	/**
	 * Admin screen, created lazily.
	 *
	 * @var Admin\Admin|null
	 */
	private $admin = null;

	/**
	 * Returns the shared instance.
	 *
	 * @return Plugin
	 */
	public static function instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Replaces the shared instance (tests only).
	 *
	 * @return void
	 */
	public static function reset() {
		self::$instance = null;
	}

	/**
	 * Use Plugin::instance().
	 */
	private function __construct() {}

	/**
	 * Registers every runtime protection. Runs on `plugins_loaded` priority 0.
	 *
	 * @return void
	 */
	public function boot() {
		if ( $this->booted ) {
			return;
		}
		$this->booted = true;

		$this->settings();
		// Attaches cache invalidation before anything reads the option.

		add_action( 'init', array( $this, 'register_setting' ) );
		add_action( 'update_option_' . Settings_Repository::OPTION, array( $this, 'on_settings_updated' ), 10, 1 );
		add_action( self::CRON_VERIFY, array( $this, 'run_scheduled_verification' ) );

		$this->policy()->register_modules();

		if ( is_admin() ) {
			$this->admin()->register();
		}
	}

	/**
	 * Registers the option with the Settings API so that every write is sanitized, in every context.
	 *
	 * @return void
	 */
	public function register_setting() {
		register_setting(
			self::OPTION_GROUP,
			Settings_Repository::OPTION,
			array(
				'type'              => 'array',
				'sanitize_callback' => array( $this->settings(), 'sanitize_for_settings_api' ),
				'show_in_rest'      => false,
			)
		);
	}

	/**
	 * Reacts to a policy change: logs it, hands over / takes over persistent options for the controls
	 * that were switched, and refreshes the cheap verification so the dashboard is never blank.
	 *
	 * @param mixed $old_value Previous value (the new one is read back through the repository).
	 * @return void
	 */
	public function on_settings_updated( $old_value ) {
		$repo    = $this->settings();
		$before  = $repo->enabled_controls( is_array( $old_value ) ? $repo->sanitize( $old_value, Settings_Repository::defaults() ) : Settings_Repository::defaults() );
		$after   = $repo->enabled_controls( $repo->all() );
		$flipped = array_keys( array_diff_assoc( $after, $before ) );

		$sections = array();
		foreach ( $repo->all() as $section => $values ) {
			$old = is_array( $old_value ) && isset( $old_value[ $section ] ) ? $old_value[ $section ] : null;
			if ( $old !== $values ) {
				$sections[] = $section;
			}
		}
		$this->logger()->info( 'settings_updated', 'Policy settings were saved.', array( 'sections' => implode( ',', array_slice( $sections, 0, 8 ) ) ) );

		if ( $flipped ) {
			$this->policy()->reconcile( $flipped );
		}
		$this->policy()->verify( false );
	}

	/**
	 * Cron callback: the first HTTP verification after activation, when loopback requests can see
	 * the plugin as active.
	 *
	 * @return void
	 */
	public function run_scheduled_verification() {
		$probe = new Http_Probe();
		// One probe: the loopback preflight and the front page are fetched once for both runs.
		$this->policy()->verify( true, $probe );
		$this->health()->run( true, $probe );
	}

	/**
	 * Returns the settings repository.
	 *
	 * @return Settings_Repository
	 */
	public function settings() {
		if ( null === $this->settings ) {
			$this->settings = new Settings_Repository();
		}
		return $this->settings;
	}

	/**
	 * Returns the state repository.
	 *
	 * @return State_Repository
	 */
	public function state() {
		if ( null === $this->state ) {
			$this->state = new State_Repository();
		}
		return $this->state;
	}

	/**
	 * Returns the audit logger.
	 *
	 * @return Audit_Logger
	 */
	public function logger() {
		if ( null === $this->logger ) {
			$this->logger = new Audit_Logger();
		}
		return $this->logger;
	}

	/**
	 * Returns the rollback service.
	 *
	 * @return Rollback
	 */
	public function rollback() {
		if ( null === $this->rollback ) {
			$this->rollback = new Rollback( $this->state(), $this->logger() );
		}
		return $this->rollback;
	}

	/**
	 * Returns the policy manager.
	 *
	 * @return Policy_Manager
	 */
	public function policy() {
		if ( null === $this->policy ) {
			$this->policy = new Policy_Manager( $this );
		}
		return $this->policy;
	}

	/**
	 * Returns the diagnostics.
	 *
	 * @return Health_Check
	 */
	public function health() {
		if ( null === $this->health ) {
			$this->health = new Health_Check( $this );
		}
		return $this->health;
	}

	/**
	 * Returns the admin screen.
	 *
	 * @return Admin\Admin
	 */
	public function admin() {
		if ( null === $this->admin ) {
			$this->admin = new Admin\Admin( $this );
		}
		return $this->admin;
	}
}
