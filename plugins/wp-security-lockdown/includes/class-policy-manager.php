<?php
/**
 * Central registry and orchestrator for the hardening modules.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Owns the list of modules and is the single place that:
 *  - registers their runtime hooks (isolating failures so one broken module can never take the site down),
 *  - applies / releases persistent options through the ledger,
 *  - collects each control's report and verification into one display status.
 */
class Policy_Manager {

	/** Display statuses, from best to worst. */
	const VERIFIED_HTTP  = 'verified_http';
	const VERIFIED_LOCAL = 'verified_local';
	const MONITOR_OK     = 'monitor_ok';
	const UNVERIFIED     = 'unverified';
	const MONITOR_WARN   = 'monitor_warn';
	const PARTIAL        = 'partial';
	const NOT_WORKING    = 'not_working';
	const FAILED         = 'failed';
	const DISABLED       = 'disabled';

	/**
	 * Service container.
	 *
	 * @var Plugin
	 */
	private $plugin;

	/**
	 * Module instances, created lazily.
	 *
	 * @var Abstract_Module[]|null
	 */
	private $modules = null;

	/**
	 * Modules that threw while registering, in this request.
	 *
	 * @var array Modules that threw while registering, in this request.
	 */
	private $failures = array();

	/**
	 * Service container.
	 *
	 * @param Plugin $plugin Service container.
	 */
	public function __construct( Plugin $plugin ) {
		$this->plugin = $plugin;
	}

	/**
	 * The modules, in the order they are presented.
	 *
	 * @return Abstract_Module[]
	 */
	public function modules() {
		if ( null === $this->modules ) {
			$this->modules = array(
				new Modules\Comments_Hardening( $this->plugin ),
				new Modules\Xmlrpc_Hardening( $this->plugin ),
				new Modules\Rest_Api_Policy( $this->plugin ),
				new Modules\Login_Protection( $this->plugin ),
				new Modules\Information_Disclosure( $this->plugin ),
				new Modules\Update_Policy( $this->plugin ),
				new Modules\File_Security( $this->plugin ),
			);
		}
		return $this->modules;
	}

	/**
	 * Registers every module's runtime hooks. A module that throws is skipped and recorded.
	 *
	 * @return void
	 */
	public function register_modules() {
		foreach ( $this->modules() as $module ) {
			try {
				$module->register();
			} catch ( \Throwable $e ) {
				$this->record_failure( $module->slug(), $e );
			}
		}
	}

	/**
	 * Modules that failed to register during this request.
	 *
	 * @return array module slug => array( class, where ).
	 */
	public function failures() {
		return $this->failures;
	}

	/**
	 * Applies (or releases) the persistent options of controls, idempotently.
	 *
	 * @param string[]|null $only Control ids to process, or null for all.
	 * @return array[] Rollback result rows.
	 */
	public function reconcile( $only = null ) {
		$settings = $this->plugin->settings();
		$rollback = $this->plugin->rollback();
		$results  = array();

		foreach ( $this->modules() as $module ) {
			foreach ( $module->managed_options() as $control => $options ) {
				if ( null !== $only && ! in_array( $control, $only, true ) ) {
					continue;
				}
				if ( $settings->control_enabled( $control ) ) {
					foreach ( $options as $option => $desired ) {
						$results[] = $rollback->claim( $option, $desired, $control );
					}
				} else {
					foreach ( $rollback->release_control( $control ) as $result ) {
						$results[] = $result;
					}
				}
			}
		}
		return $results;
	}

	/**
	 * Applies the whole policy. Safe to call repeatedly.
	 *
	 * @return array[] Rollback result rows.
	 */
	public function apply_all() {
		return $this->reconcile( null );
	}

	/**
	 * Rolls back every persistent change the plugin made.
	 *
	 * Controls whose options were all handed back are switched off, so the policy no longer wants
	 * what was just undone. Controls with conflicts keep their setting and are reported.
	 *
	 * @param bool $force Overwrite values changed after the plugin set them.
	 * @return array {
	 *     @type array[]   $results   Per-option results.
	 *     @type string[]  $disabled  Controls that were switched off.
	 *     @type string[]  $conflicts Options that could not be restored safely.
	 * }
	 */
	public function rollback( $force = false ) {
		$rollback = $this->plugin->rollback();
		$owners   = array();
		foreach ( $rollback->entries() as $entry ) {
			if ( ! empty( $entry['control'] ) ) {
				$owners[ $entry['control'] ] = true;
			}
		}

		$results   = $rollback->release_all( $force );
		$conflicts = array();
		foreach ( $results as $result ) {
			if ( Rollback::CONFLICT === $result['status'] || Rollback::FAILED === $result['status'] ) {
				$conflicts[] = $result['option'];
			}
		}

		$remaining = array();
		foreach ( $rollback->entries() as $entry ) {
			if ( ! empty( $entry['control'] ) ) {
				$remaining[ $entry['control'] ] = true;
			}
		}

		$disabled = array();
		foreach ( array_keys( $owners ) as $control ) {
			if ( ! isset( $remaining[ $control ] ) && $this->plugin->settings()->disable_control( $control ) ) {
				$disabled[] = $control;
			}
		}

		$this->plugin->logger()->info(
			'rollback_run',
			'Rollback executed.',
			array(
				'restored'  => count( $results ) - count( $conflicts ),
				'conflicts' => count( $conflicts ),
				'forced'    => (bool) $force,
				'disabled'  => implode( ',', $disabled ),
			)
		);

		return array(
			'results'   => $results,
			'disabled'  => $disabled,
			'conflicts' => $conflicts,
		);
	}

	/**
	 * Every control's report, merged with the latest verification and a display status.
	 *
	 * @return array control id => report.
	 */
	public function reports() {
		$verification = $this->plugin->state()->verification();
		$fingerprint  = $this->plugin->settings()->fingerprint();
		$reports      = array();

		foreach ( $this->modules() as $module ) {
			try {
				$module_reports = $module->report();
			} catch ( \Throwable $e ) {
				$module_reports = array();
				foreach ( array_keys( $module->controls() ) as $control ) {
					$module_reports[ $control ] = array(
						'id'             => $control,
						'module'         => $module->slug(),
						'title'          => $control,
						'description'    => '',
						'enabled'        => true,
						'desired'        => '',
						'state'          => Abstract_Module::STATE_FAILED,
						'enforcement'    => array(),
						'persists'       => '',
						'failure_reason' => __( 'The control could not be inspected because the module raised an error.', 'wp-security-lockdown' ),
						'warnings'       => array(),
						'manual_action'  => '',
						'server_level'   => false,
						'details'        => array(),
					);
				}
				$this->record_failure( $module->slug(), $e );
			}//end try

			foreach ( (array) $module_reports as $id => $report ) {
				if ( ! is_array( $report ) || ! isset( $report['state'], $report['enabled'] ) ) {
					continue;
					// A malformed report must never take the dashboard down.
				}
				$report['verification'] = $this->normalize_verification( isset( $verification[ $id ] ) ? $verification[ $id ] : null, $fingerprint, $report );
				$report['status']       = self::display_status( $report );
				$reports[ $id ]         = $report;
			}
		}//end foreach

		// Surface modules that could not even register their hooks in this request.
		foreach ( $this->failures as $slug => $failure ) {
			foreach ( $reports as $id => $report ) {
				if ( $report['module'] === $slug && $report['enabled'] ) {
					$reports[ $id ]['state']          = Abstract_Module::STATE_FAILED;
					$reports[ $id ]['failure_reason'] = __( 'The module raised an error while registering and is not enforcing this control.', 'wp-security-lockdown' );
					$reports[ $id ]['status']         = self::FAILED;
				}
			}
		}
		return $reports;
	}

	/**
	 * Runs functional verification and stores the results.
	 *
	 * A cheap in-process re-check never replaces a still-valid HTTP verification with a weaker one,
	 * but it always records a failure.
	 *
	 * @param bool            $deep  Allow real HTTP requests.
	 * @param Http_Probe|null $probe Probe to use (created when needed).
	 * @return array control id => result.
	 */
	public function verify( $deep = false, ?Http_Probe $probe = null ) {
		if ( $deep && null === $probe ) {
			$probe = new Http_Probe();
		}

		$results = array();
		foreach ( $this->modules() as $module ) {
			try {
				$module_results = $module->verify( $deep ? $probe : null );
			} catch ( \Throwable $e ) {
				$module_results = array();
				foreach ( array_keys( $module->controls() ) as $control ) {
					if ( $this->plugin->settings()->control_enabled( $control ) ) {
						$module_results[ $control ] = array(
							'status' => Abstract_Module::UNVERIFIED,
							'method' => Abstract_Module::METHOD_NONE,
							'detail' => sprintf( 'Verification raised %s.', get_class( $e ) ),
						);
					}
				}
			}
			$results = array_merge( $results, $module_results );
		}

		$fingerprint = $this->plugin->settings()->fingerprint();
		if ( ! $deep ) {
			$stored = $this->plugin->state()->verification();
			foreach ( $results as $control => $result ) {
				$old = isset( $stored[ $control ] ) ? $stored[ $control ] : null;
				if ( $old
					&& Abstract_Module::VERIFIED === $old['status']
					&& Abstract_Module::METHOD_HTTP === $old['method']
					&& $old['fingerprint'] === $fingerprint
					&& Abstract_Module::VERIFIED === $result['status']
				) {
					unset( $results[ $control ] );
					// Keep the stronger, still-valid evidence.
				}
			}
		}

		$this->plugin->state()->record_verification( $results, $fingerprint );

		$tally = array(
			Abstract_Module::VERIFIED   => 0,
			Abstract_Module::UNVERIFIED => 0,
			Abstract_Module::FAILED     => 0,
		);
		foreach ( $results as $result ) {
			if ( isset( $tally[ $result['status'] ] ) ) {
				++$tally[ $result['status'] ];
			}
		}
		$this->plugin->logger()->info(
			'verification_run',
			$deep ? 'Verification run (including HTTP probes).' : 'Verification run (in-process).',
			array(
				'verified'   => $tally[ Abstract_Module::VERIFIED ],
				'unverified' => $tally[ Abstract_Module::UNVERIFIED ],
				'failed'     => $tally[ Abstract_Module::FAILED ],
				'requests'   => $probe ? $probe->requests_made() : 0,
			)
		);
		return $results;
	}

	/**
	 * Aggregates reports into counts and an overall verdict.
	 *
	 * @param array $reports Output of reports().
	 * @return array {
	 *     @type string $overall ok | attention | at_risk.
	 *     @type array  $counts  status => count (enabled controls only).
	 *     @type int    $manual  Controls that need a human or server-level action.
	 * }
	 */
	public static function summarize( array $reports ) {
		$counts = array();
		$manual = 0;
		foreach ( $reports as $report ) {
			$status            = $report['status'];
			$counts[ $status ] = isset( $counts[ $status ] ) ? $counts[ $status ] + 1 : 1;
			if ( self::DISABLED !== $status && '' !== $report['manual_action'] ) {
				++$manual;
			}
		}

		$bad = ( $counts[ self::FAILED ] ?? 0 ) + ( $counts[ self::NOT_WORKING ] ?? 0 );
		$meh = ( $counts[ self::PARTIAL ] ?? 0 ) + ( $counts[ self::UNVERIFIED ] ?? 0 ) + ( $counts[ self::MONITOR_WARN ] ?? 0 ) + $manual;

		$overall = 'ok';
		if ( $bad > 0 ) {
			$overall = 'at_risk';
		} elseif ( $meh > 0 ) {
			$overall = 'attention';
		}
		return array(
			'overall' => $overall,
			'counts'  => $counts,
			'manual'  => $manual,
		);
	}

	/**
	 * Collapses state + verification into the one badge the dashboard shows.
	 *
	 * "Verified" is the only status that means "known to be working"; everything else says why not.
	 *
	 * @param array $report Control report including `verification`.
	 * @return string One of the status constants.
	 */
	public static function display_status( array $report ) {
		if ( empty( $report['enabled'] ) || Abstract_Module::STATE_DISABLED === $report['state'] ) {
			return self::DISABLED;
		}
		if ( Abstract_Module::STATE_FAILED === $report['state'] ) {
			return self::FAILED;
		}
		if ( Abstract_Module::STATE_MONITOR === $report['state'] ) {
			return '' === $report['failure_reason'] ? self::MONITOR_OK : self::MONITOR_WARN;
		}
		if ( isset( $report['verification']['status'] ) && Abstract_Module::FAILED === $report['verification']['status'] ) {
			return self::NOT_WORKING;
		}
		if ( Abstract_Module::STATE_PARTIAL === $report['state'] ) {
			return self::PARTIAL;
		}
		$verification = isset( $report['verification'] ) ? $report['verification'] : array();
		if ( isset( $verification['status'] ) && Abstract_Module::VERIFIED === $verification['status'] ) {
			return Abstract_Module::METHOD_HTTP === $verification['method'] ? self::VERIFIED_HTTP : self::VERIFIED_LOCAL;
		}
		return self::UNVERIFIED;
	}

	/**
	 * Turns a stored verification record into what is valid for the current policy.
	 *
	 * @param array|null $stored      Stored record.
	 * @param string     $fingerprint Current policy fingerprint.
	 * @param array      $report      The control report.
	 * @return array
	 */
	private function normalize_verification( $stored, $fingerprint, array $report ) {
		if ( empty( $report['enabled'] ) || Abstract_Module::STATE_MONITOR === $report['state'] ) {
			return array(
				'status' => 'not_applicable',
				'method' => Abstract_Module::METHOD_NONE,
				'detail' => '',
				'time'   => 0,
				'stale'  => false,
			);
		}
		if ( ! is_array( $stored ) ) {
			return array(
				'status' => Abstract_Module::UNVERIFIED,
				'method' => Abstract_Module::METHOD_NONE,
				'detail' => __( 'Not verified yet.', 'wp-security-lockdown' ),
				'time'   => 0,
				'stale'  => false,
			);
		}
		if ( ! isset( $stored['fingerprint'] ) || $stored['fingerprint'] !== $fingerprint ) {
			return array(
				'status' => Abstract_Module::UNVERIFIED,
				'method' => Abstract_Module::METHOD_NONE,
				'detail' => __( 'The policy changed after this control was last verified. Run verification again.', 'wp-security-lockdown' ),
				'time'   => isset( $stored['time'] ) && is_numeric( $stored['time'] ) ? (int) $stored['time'] : 0,
				'stale'  => true,
			);
		}
		$status = isset( $stored['status'] ) && is_string( $stored['status'] ) && in_array( $stored['status'], array( Abstract_Module::VERIFIED, Abstract_Module::UNVERIFIED, Abstract_Module::FAILED ), true ) ? $stored['status'] : Abstract_Module::UNVERIFIED;
		$method = isset( $stored['method'] ) && is_string( $stored['method'] ) && in_array( $stored['method'], array( Abstract_Module::METHOD_HTTP, Abstract_Module::METHOD_SELF_TEST, Abstract_Module::METHOD_IN_PROCESS ), true ) ? $stored['method'] : Abstract_Module::METHOD_NONE;
		return array(
			'status' => $status,
			'method' => $method,
			'detail' => isset( $stored['detail'] ) && is_scalar( $stored['detail'] ) ? (string) $stored['detail'] : '',
			'time'   => isset( $stored['time'] ) && is_numeric( $stored['time'] ) ? (int) $stored['time'] : 0,
			'stale'  => false,
		);
	}

	/**
	 * Remembers that a module raised, without writing on every request.
	 *
	 * @param string     $slug Module slug.
	 * @param \Throwable $e    The error.
	 * @return void
	 */
	private function record_failure( $slug, \Throwable $e ) {
		$where                   = basename( $e->getFile() ) . ':' . $e->getLine();
		$this->failures[ $slug ] = array(
			'class' => get_class( $e ),
			'where' => $where,
		);

		$stored = $this->plugin->state()->get( 'module_failures' );
		if ( isset( $stored[ $slug ]['where'], $stored[ $slug ]['class'] ) && $where === $stored[ $slug ]['where'] && get_class( $e ) === $stored[ $slug ]['class'] ) {
			return;
			// Already known; do not write on every request.
		}
		$stored[ $slug ] = array(
			'class' => get_class( $e ),
			'where' => $where,
			'time'  => time(),
		);
		$this->plugin->state()->set( 'module_failures', $stored );
		// Class and location only: exception messages can contain paths or data.
		$this->plugin->logger()->error(
			'module_failed',
			'A module raised an error and was skipped.',
			array(
				'module'      => $slug,
				'error_class' => get_class( $e ),
				'where'       => $where,
			)
		);
	}
}
