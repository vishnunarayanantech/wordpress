<?php
/**
 * Rate limiter: counting, locking, expiry, bounded storage.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Rate_Limiter;

class Test_Rate_Limiter extends Test_Case {

	/** @var int Controllable clock. */
	private $now = 1000000;

	/**
	 * @return Rate_Limiter
	 */
	private function limiter( $max = 3, $window = 60, $lockout = 120 ) {
		return new Rate_Limiter(
			$max,
			$window,
			$lockout,
			function () {
				return $this->now;
			}
		);
	}

	private function key( $n = 1 ) {
		return substr( md5( 'k' . $n ), 0, 32 );
	}

	public function test_locks_on_the_threshold_failure_and_only_then() {
		$l = $this->limiter();
		$k = $this->key();
		$this->assertSame( 0, $l->remaining_lock( $k ) );
		$this->assertFalse( $l->record_failure( $k )['locked'] );
		$this->assertFalse( $l->record_failure( $k )['locked'] );
		$this->assertSame( 0, $l->remaining_lock( $k ), 'Below the threshold nothing is locked.' );

		$third = $l->record_failure( $k );
		$this->assertTrue( $third['locked'] );
		$this->assertTrue( $third['new_lock'] );
		$this->assertSame( 120, $l->remaining_lock( $k ) );
	}

	public function test_the_lock_expires_by_itself() {
		$l = $this->limiter();
		$k = $this->key();
		for ( $i = 0; $i < 3; $i++ ) {
			$l->record_failure( $k );
		}
		$this->now += 119;
		$this->assertSame( 1, $l->remaining_lock( $k ) );
		$this->now += 2;
		$this->assertSame( 0, $l->remaining_lock( $k ), 'No permanent lock: it must be gone after the lock time.' );
	}

	public function test_attempts_while_locked_do_not_extend_the_lock() {
		$l = $this->limiter();
		$k = $this->key();
		for ( $i = 0; $i < 3; $i++ ) {
			$l->record_failure( $k );
		}
		$this->now += 60;
		$again      = $l->record_failure( $k );
		$this->assertTrue( $again['locked'] );
		$this->assertFalse( $again['new_lock'] );
		$this->assertSame( 60, $l->remaining_lock( $k ), 'A persistent attacker must not be able to keep a victim behind the same address locked forever.' );
	}

	public function test_counter_starts_fresh_after_the_lock_and_after_the_window() {
		$l = $this->limiter();
		$k = $this->key();
		for ( $i = 0; $i < 3; $i++ ) {
			$l->record_failure( $k );
		}
		$this->now += 121;
		$this->assertFalse( $l->record_failure( $k )['locked'], 'After a lock expires one failure must not immediately re-lock.' );

		$k2 = $this->key( 2 );
		$l->record_failure( $k2 );
		$l->record_failure( $k2 );
		$this->now += 61; // The window passed: the earlier failures no longer count.
		$this->assertFalse( $l->record_failure( $k2 )['locked'] );
		$this->assertSame( 0, $l->remaining_lock( $k2 ) );
	}

	public function test_keys_are_independent_and_clear_works() {
		$l = $this->limiter();
		for ( $i = 0; $i < 3; $i++ ) {
			$l->record_failure( $this->key( 1 ) );
		}
		$this->assertGreaterThan( 0, $l->remaining_lock( $this->key( 1 ) ) );
		$this->assertSame( 0, $l->remaining_lock( $this->key( 2 ) ) );
		$l->clear( $this->key( 1 ) );
		$this->assertSame( 0, $l->remaining_lock( $this->key( 1 ) ) );
	}

	public function test_state_survives_a_new_limiter_instance_like_a_new_request() {
		$k = $this->key();
		$a = $this->limiter();
		for ( $i = 0; $i < 3; $i++ ) {
			$a->record_failure( $k );
		}
		$b = $this->limiter();
		$this->assertGreaterThan( 0, $b->remaining_lock( $k ), 'The lock must live in storage, not in the object.' );
	}

	public function test_storage_is_bounded() {
		$l = $this->limiter( 10 );
		// Many distinct keys landing in the same shard must be capped.
		$shard_of = static function ( $key ) {
			return hexdec( substr( md5( $key ), 0, 4 ) ) % Rate_Limiter::SHARDS;
		};
		$target   = $shard_of( $this->key( 1 ) );
		$in_same  = 0;
		for ( $n = 1; $in_same < Rate_Limiter::MAX_PER_SHARD + 40; $n++ ) {
			$k = $this->key( $n );
			if ( $shard_of( $k ) === $target ) {
				$l->record_failure( $k );
				++$in_same;
			}
			$this->now += 0;
		}
		$stored = get_transient( Rate_Limiter::PREFIX . sprintf( '%02d', $target ) );
		$this->assertIsArray( $stored );
		$this->assertLessThanOrEqual( Rate_Limiter::MAX_PER_SHARD, count( $stored ), 'One shard may never grow past its cap.' );
		$this->assertLessThanOrEqual( Rate_Limiter::SHARDS * Rate_Limiter::MAX_PER_SHARD, $l->snapshot()['tracked'] );
	}

	public function test_stale_entries_are_pruned_on_write() {
		$l = $this->limiter();
		$l->record_failure( $this->key( 1 ) );
		$this->now += 10000;
		$l->record_failure( $this->key( 2 ) );
		$this->assertSame( 0, $l->snapshot()['locked'] );
		$this->assertSame( 1, $l->snapshot()['tracked'], 'The expired entry must be gone.' );
	}

	public function test_no_personal_data_in_storage() {
		$l = $this->limiter();
		$l->record_failure( \WP_Security_Lockdown\Client_IP::bucket_key( '203.0.113.77' ) );
		global $wpdb;
		$rows = $wpdb->get_col( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( '_transient_' . Rate_Limiter::PREFIX ) . '%' ) );
		$this->assertNotEmpty( $rows );
		foreach ( $rows as $row ) {
			$this->assertStringNotContainsString( '203.0.113.77', $row );
		}
	}

	public function test_clear_all_removes_everything() {
		$l = $this->limiter();
		for ( $i = 0; $i < 3; $i++ ) {
			$l->record_failure( $this->key( 1 ) );
		}
		Rate_Limiter::clear_all();
		$this->assertSame(
			array(
				'tracked' => 0,
				'locked'  => 0,
			),
			$l->snapshot()
		);
	}

	public function test_corrupted_storage_is_ignored() {
		$k = $this->key();
		foreach ( array( 'garbage', 5, array( 'x' => 'not-an-entry' ), array( $k => array( 'c' => 1 ) ) ) as $bad ) {
			foreach ( range( 0, Rate_Limiter::SHARDS - 1 ) as $i ) {
				set_transient( Rate_Limiter::PREFIX . sprintf( '%02d', $i ), $bad, 100 );
			}
			$l = $this->limiter();
			$this->assertSame( 0, $l->remaining_lock( $k ) );
			$this->assertFalse( $l->record_failure( $k )['locked'] );
		}
	}
}
