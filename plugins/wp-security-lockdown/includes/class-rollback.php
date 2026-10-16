<?php
/**
 * Change ledger and conflict-aware rollback.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Tracks every persistent WordPress option this plugin changes, and can undo exactly those changes.
 *
 * Invariants:
 *  - Only options the plugin actually changed are recorded (no snapshot of the site configuration).
 *  - The original value is recorded once, the first time the plugin touches an option. Re-applying
 *    the policy never overwrites it, so repeated activation cannot "drift" the recorded original.
 *  - Applying is idempotent: when the option already holds the desired value nothing is written.
 *  - Restoring never overwrites a value that changed after the plugin set it unless the caller
 *    passes `$force` (an explicit, logged administrator decision). Otherwise the entry is reported
 *    as a conflict and left untouched.
 *
 * Ledger entry: option => array(
 *     control  => owning control id,
 *     existed  => bool   the option existed before the plugin changed it,
 *     original => scalar the value before the plugin changed it (null when !existed),
 *     applied  => scalar the value the plugin wrote,
 *     changed  => bool   whether the plugin actually wrote anything,
 *     time     => int    when the entry was created,
 * )
 */
class Rollback {

	const ABSENT = '__wp_security_lockdown_absent__';

	/** Result statuses. */
	const APPLIED         = 'applied';
	const ALREADY         = 'already_set';
	const UNCHANGED       = 'unchanged';
	const REAPPLIED       = 'reapplied';
	const RESTORED        = 'restored';
	const RESTORED_FORCED = 'restored_forced';
	const NOTHING         = 'nothing_to_restore';
	const CONFLICT        = 'conflict';
	const NOT_MANAGED     = 'not_managed';
	const FAILED          = 'failed';

	/**
	 * State storage.
	 *
	 * @var State_Repository
	 */
	private $state;

	/**
	 * Logger.
	 *
	 * @var Audit_Logger
	 */
	private $logger;

	/**
	 * State storage.
	 *
	 * @param State_Repository $state  State storage.
	 * @param Audit_Logger     $logger Logger.
	 */
	public function __construct( State_Repository $state, Audit_Logger $logger ) {
		$this->state  = $state;
		$this->logger = $logger;
	}

	/**
	 * Ledger entries.
	 *
	 * @return array
	 */
	public function entries() {
		return $this->state->ledger();
	}

	/**
	 * Makes an option hold `$desired`, recording its original value the first time.
	 *
	 * @param string $option  Option name.
	 * @param mixed  $desired Desired scalar value.
	 * @param string $control Owning control id.
	 * @return array Result: status, option, plus before/after values.
	 */
	public function claim( $option, $desired, $control ) {
		$ledger  = $this->state->ledger();
		$current = get_option( $option, self::ABSENT );
		$entry   = isset( $ledger[ $option ] ) && is_array( $ledger[ $option ] ) ? $ledger[ $option ] : null;

		if ( null === $entry ) {
			$entry = array(
				'control'  => (string) $control,
				'existed'  => self::ABSENT !== $current,
				'original' => self::ABSENT !== $current ? $current : null,
				'applied'  => $desired,
				'changed'  => false,
				'time'     => time(),
			);

			if ( $this->equal( $current, $desired ) ) {
				$status = self::ALREADY;
				// Nothing to write, so there is nothing to restore later.
			} else {
				update_option( $option, $desired );
				if ( ! $this->equal( get_option( $option, self::ABSENT ), $desired ) ) {
					$this->logger->error( 'option_apply_failed', 'A managed option could not be changed.', array( 'option' => $option ) );
					return $this->result( self::FAILED, $option, $current, $current );
				}
				$entry['changed'] = true;
				$status           = self::APPLIED;
			}

			$ledger[ $option ] = $entry;
			$this->state->set_ledger( $ledger );
			$this->logger->info(
				'option_' . $status,
				'Managed option recorded.',
				array(
					'option' => $option,
					'from'   => $this->display( $current ),
					'to'     => $this->display( $desired ),
				)
			);
			return $this->result( $status, $option, $current, $desired );
		}//end if

		// Already managed.
		if ( $this->equal( $current, $desired ) && $this->equal( $entry['applied'], $desired ) ) {
			return $this->result( self::UNCHANGED, $option, $current, $current );
		}

		if ( ! $this->equal( $current, $desired ) ) {
			update_option( $option, $desired );
			if ( ! $this->equal( get_option( $option, self::ABSENT ), $desired ) ) {
				return $this->result( self::FAILED, $option, $current, $current );
			}
			$entry['changed'] = true;
		}
		$entry['applied']  = $desired;
		$ledger[ $option ] = $entry;
		$this->state->set_ledger( $ledger );
		$this->logger->warning(
			'option_reapplied',
			'Policy re-applied over a value that had changed since it was first set.',
			array(
				'option' => $option,
				'from'   => $this->display( $current ),
				'to'     => $this->display( $desired ),
			)
		);
		return $this->result( self::REAPPLIED, $option, $current, $desired );
	}

	/**
	 * Restores one option to its recorded original, if (and only if) it is safe to do so.
	 *
	 * @param string $option Option name.
	 * @param bool   $force  Restore even if the value changed after the plugin set it.
	 * @return array Result.
	 */
	public function release( $option, $force = false ) {
		$ledger = $this->state->ledger();
		if ( ! isset( $ledger[ $option ] ) || ! is_array( $ledger[ $option ] ) ) {
			return $this->result( self::NOT_MANAGED, $option, null, null );
		}

		$entry   = $ledger[ $option ];
		$current = get_option( $option, self::ABSENT );

		if ( empty( $entry['changed'] ) ) {
			unset( $ledger[ $option ] );
			$this->state->set_ledger( $ledger );
			return $this->result( self::NOTHING, $option, $current, $current );
		}

		$in_sync = $this->equal( $current, $entry['applied'] );
		if ( ! $in_sync && ! $force ) {
			$result             = $this->result( self::CONFLICT, $option, $current, $current );
			$result['original'] = $entry['original'];
			$result['applied']  = $entry['applied'];
			$this->logger->warning(
				'rollback_conflict',
				'Not restored: the value was changed after the plugin set it.',
				array(
					'option'  => $option,
					'current' => $this->display( $current ),
					'applied' => $this->display( $entry['applied'] ),
				)
			);
			return $result;
		}

		if ( ! empty( $entry['existed'] ) ) {
			update_option( $option, $entry['original'] );
			$restored = get_option( $option, self::ABSENT );
		} else {
			delete_option( $option );
			$restored = get_option( $option, self::ABSENT );
		}
		$ok = ! empty( $entry['existed'] ) ? $this->equal( $restored, $entry['original'] ) : self::ABSENT === $restored;
		if ( ! $ok ) {
			$this->logger->error( 'rollback_failed', 'A managed option could not be restored.', array( 'option' => $option ) );
			return $this->result( self::FAILED, $option, $current, $restored );
		}

		unset( $ledger[ $option ] );
		$this->state->set_ledger( $ledger );
		$status = $in_sync ? self::RESTORED : self::RESTORED_FORCED;
		$this->logger->info(
			'option_' . $status,
			$in_sync ? 'Managed option restored.' : 'Managed option restored by explicit override of a newer change.',
			array(
				'option' => $option,
				'from'   => $this->display( $current ),
				'to'     => $this->display( $restored ),
			)
		);
		return $this->result( $status, $option, $current, $restored );
	}

	/**
	 * Releases every option owned by a control.
	 *
	 * @param string $control Control id.
	 * @param bool   $force   See release().
	 * @return array[] Results, one per option.
	 */
	public function release_control( $control, $force = false ) {
		$results = array();
		foreach ( $this->state->ledger() as $option => $entry ) {
			if ( isset( $entry['control'] ) && $entry['control'] === $control ) {
				$results[] = $this->release( $option, $force );
			}
		}
		return $results;
	}

	/**
	 * Releases every ledger entry.
	 *
	 * @param bool $force See release().
	 * @return array[] Results.
	 */
	public function release_all( $force = false ) {
		$results = array();
		foreach ( array_keys( $this->state->ledger() ) as $option ) {
			$results[] = $this->release( $option, $force );
		}
		return $results;
	}

	/**
	 * Describes each ledger entry against the option's current value, for the dashboard.
	 *
	 * @return array[] Each: option, control, original, applied, current, sync (in_sync|drifted|untouched).
	 */
	public function describe() {
		$rows = array();
		foreach ( $this->state->ledger() as $option => $entry ) {
			$current = get_option( $option, self::ABSENT );
			if ( empty( $entry['changed'] ) ) {
				$sync = 'untouched';
			} else {
				$sync = $this->equal( $current, $entry['applied'] ) ? 'in_sync' : 'drifted';
			}
			$rows[] = array(
				'option'   => (string) $option,
				'control'  => isset( $entry['control'] ) && is_string( $entry['control'] ) ? $entry['control'] : '',
				'existed'  => ! empty( $entry['existed'] ),
				'original' => $entry['original'] ?? null,
				'applied'  => $entry['applied'] ?? null,
				'current'  => self::ABSENT === $current ? null : $current,
				'absent'   => self::ABSENT === $current,
				'sync'     => $sync,
			);
		}
		return $rows;
	}

	/**
	 * Scalar-safe equality. WordPress stores scalars as strings, so '0' and 0 must compare equal.
	 *
	 * @param mixed $a First value.
	 * @param mixed $b Second value.
	 * @return bool
	 */
	public function equal( $a, $b ) {
		if ( self::ABSENT === $a || self::ABSENT === $b ) {
			return $a === $b;
		}
		if ( ( is_scalar( $a ) || null === $a ) && ( is_scalar( $b ) || null === $b ) ) {
			return (string) $a === (string) $b;
		}
		return $a === $b;
	}

	/**
	 * Builds a result row.
	 *
	 * @param string $status  Status constant.
	 * @param string $option  Option name.
	 * @param mixed  $before  Value before.
	 * @param mixed  $after   Value after.
	 * @return array
	 */
	private function result( $status, $option, $before, $after ) {
		return array(
			'status' => $status,
			'option' => (string) $option,
			'before' => self::ABSENT === $before ? null : $before,
			'after'  => self::ABSENT === $after ? null : $after,
		);
	}

	/**
	 * Short, log-safe rendering of an option value.
	 *
	 * @param mixed $value Value.
	 * @return string
	 */
	private function display( $value ) {
		if ( self::ABSENT === $value ) {
			return '(absent)';
		}
		return is_scalar( $value ) ? substr( (string) $value, 0, 60 ) : '(complex)';
	}
}
