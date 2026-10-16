<?php
/**
 * Bounded, expiring failed-login counters.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Counts failures per opaque key and locks a key temporarily after too many.
 *
 * Design constraints:
 *  - Never permanent: every lock and every counter carries an expiry timestamp, and the storage
 *    itself (transients) expires too, so a lock cannot outlive `lockout` seconds.
 *  - Bounded storage: keys are spread over SHARDS transients, each holding at most MAX_PER_SHARD
 *    entries (oldest evicted first). Worst case is SHARDS * MAX_PER_SHARD entries regardless of
 *    how many addresses attack. Eviction only ever forgives, it never blocks.
 *  - No personal data: callers pass keyed hashes, never IP addresses or user names.
 *  - Not atomic: counters use read-modify-write on transients. Under heavy concurrency a few
 *    failures can be missed (the limiter under-counts); it can never over-count. Documented in readme.txt.
 */
class Rate_Limiter {

	const SHARDS        = 64;
	const MAX_PER_SHARD = 100;
	const PREFIX        = 'wp_security_lockdown_rl_';

	/**
	 * Failures within the window that trigger a lock.
	 *
	 * @var int
	 */
	private $max_attempts;

	/**
	 * Seconds over which failures are counted.
	 *
	 * @var int
	 */
	private $window;

	/**
	 * Seconds a lock lasts.
	 *
	 * @var int
	 */
	private $lockout;

	/**
	 * Clock override (tests).
	 *
	 * @var callable|null Clock override for tests.
	 */
	private $clock;

	/**
	 * Failures within the window that trigger a lock.
	 *
	 * @param int           $max_attempts Failures within `window` that trigger a lock.
	 * @param int           $window       Seconds over which failures are counted.
	 * @param int           $lockout      Seconds a lock lasts.
	 * @param callable|null $clock        Returns the current Unix time (tests).
	 */
	public function __construct( $max_attempts, $window, $lockout, $clock = null ) {
		$this->max_attempts = max( 1, (int) $max_attempts );
		$this->window       = max( 1, (int) $window );
		$this->lockout      = max( 1, (int) $lockout );
		$this->clock        = $clock;
	}

	/**
	 * Seconds until a key may try again; 0 when it is not locked.
	 *
	 * @param string $key Opaque key.
	 * @return int
	 */
	public function remaining_lock( $key ) {
		$now   = $this->now();
		$shard = $this->load( $this->shard_name( $key ), $now );
		return ( isset( $shard[ $key ] ) && $shard[ $key ]['l'] > $now ) ? (int) ( $shard[ $key ]['l'] - $now ) : 0;
	}

	/**
	 * Records one failed attempt.
	 *
	 * @param string $key Opaque key.
	 * @return array {
	 *     @type bool $locked    Whether the key is locked after this call.
	 *     @type bool $new_lock  Whether THIS call created the lock.
	 *     @type int  $remaining Seconds of lock left (0 when not locked).
	 *     @type int  $count     Failures counted in the current window.
	 * }
	 */
	public function record_failure( $key ) {
		$now   = $this->now();
		$name  = $this->shard_name( $key );
		$shard = $this->load( $name, $now );
		$entry = isset( $shard[ $key ] ) ? $shard[ $key ] : array(
			'c' => 0,
			's' => $now,
			'l' => 0,
		);

		if ( $entry['l'] > $now ) {
			// Attempts made while locked are not counted: they must not extend the lock.
			return array(
				'locked'    => true,
				'new_lock'  => false,
				'remaining' => (int) ( $entry['l'] - $now ),
				'count'     => (int) $entry['c'],
			);
		}
		if ( ( $now - $entry['s'] ) >= $this->window ) {
			$entry = array(
				'c' => 0,
				's' => $now,
				'l' => 0,
			);
		}

		++$entry['c'];
		$new_lock = false;
		if ( $entry['c'] >= $this->max_attempts ) {
			$entry    = array(
				'c' => 0,
				's' => $now,
				'l' => $now + $this->lockout,
			);
			$new_lock = true;
		}

		$shard[ $key ] = $entry;
		$this->store( $name, $shard );

		return array(
			'locked'    => $new_lock,
			'new_lock'  => $new_lock,
			'remaining' => $new_lock ? $this->lockout : 0,
			'count'     => (int) $entry['c'],
		);
	}

	/**
	 * Forgets one key (counters and lock).
	 *
	 * @param string $key Opaque key.
	 * @return void
	 */
	public function clear( $key ) {
		$now   = $this->now();
		$name  = $this->shard_name( $key );
		$shard = $this->load( $name, $now );
		if ( isset( $shard[ $key ] ) ) {
			unset( $shard[ $key ] );
			$this->store( $name, $shard );
		}
	}

	/**
	 * Summary for the dashboard. Contains no addresses.
	 *
	 * @return array array( tracked => int, locked => int ).
	 */
	public function snapshot() {
		$now     = $this->now();
		$tracked = 0;
		$locked  = 0;
		for ( $i = 0; $i < self::SHARDS; $i++ ) {
			foreach ( $this->load( self::PREFIX . sprintf( '%02d', $i ), $now ) as $entry ) {
				++$tracked;
				if ( $entry['l'] > $now ) {
					++$locked;
				}
			}
		}
		return array(
			'tracked' => $tracked,
			'locked'  => $locked,
		);
	}

	/**
	 * Removes every counter and lock.
	 *
	 * @return void
	 */
	public static function clear_all() {
		for ( $i = 0; $i < self::SHARDS; $i++ ) {
			delete_transient( self::PREFIX . sprintf( '%02d', $i ) );
		}
	}

	/**
	 * Returns the current Unix time.
	 *
	 * @return int
	 */
	private function now() {
		return $this->clock ? (int) call_user_func( $this->clock ) : time();
	}

	/**
	 * Transient name of the shard that holds a key.
	 *
	 * @param string $key Opaque hex key.
	 * @return string
	 */
	private function shard_name( $key ) {
		return self::PREFIX . sprintf( '%02d', hexdec( substr( md5( $key ), 0, 4 ) ) % self::SHARDS );
	}

	/**
	 * Loads a shard and drops entries that are neither locked nor inside their window.
	 *
	 * @param string $name Transient name.
	 * @param int    $now  Current time.
	 * @return array
	 */
	private function load( $name, $now ) {
		$shard = get_transient( $name );
		if ( ! is_array( $shard ) ) {
			return array();
		}
		foreach ( $shard as $key => $entry ) {
			if ( ! is_array( $entry ) || ! isset( $entry['c'], $entry['s'], $entry['l'] ) ) {
				unset( $shard[ $key ] );
				continue;
			}
			if ( $entry['l'] <= $now && ( $now - $entry['s'] ) >= $this->window ) {
				unset( $shard[ $key ] );
			}
		}
		return $shard;
	}

	/**
	 * Saves a shard, enforcing the per-shard cap by evicting the oldest entries.
	 *
	 * @param string $name  Transient name.
	 * @param array  $shard Entries.
	 * @return void
	 */
	private function store( $name, array $shard ) {
		if ( count( $shard ) > self::MAX_PER_SHARD ) {
			uasort(
				$shard,
				static function ( $a, $b ) {
					return max( $b['s'], $b['l'] ) <=> max( $a['s'], $a['l'] );
					// Newest first.
				}
			);
			$shard = array_slice( $shard, 0, self::MAX_PER_SHARD, true );
		}
		if ( ! $shard ) {
			delete_transient( $name );
			return;
		}
		set_transient( $name, $shard, max( $this->window, $this->lockout ) + 60 );
	}
}
