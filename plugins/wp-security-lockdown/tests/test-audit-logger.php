<?php
/**
 * Audit logger: bounded, redacted, resilient.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Audit_Logger;

class Test_Audit_Logger extends Test_Case {

	public function test_the_log_is_a_bounded_ring_buffer_that_keeps_the_newest_entries() {
		$logger = new Audit_Logger();
		for ( $i = 1; $i <= Audit_Logger::MAX_ENTRIES + 150; $i++ ) {
			$logger->info( 'event', 'entry ' . $i );
		}
		$logger->flush();

		$stored = get_option( Audit_Logger::OPTION );
		$this->assertCount( Audit_Logger::MAX_ENTRIES, $stored, 'Unbounded growth would be a database-bloat bug.' );
		$this->assertSame( 'entry ' . ( Audit_Logger::MAX_ENTRIES + 150 ), end( $stored )['m'] );
		$this->assertSame( 'entry 151', reset( $stored )['m'], 'Only the oldest entries are overwritten.' );
	}

	public function test_the_bound_holds_across_many_flushes() {
		for ( $round = 0; $round < 5; $round++ ) {
			$logger = new Audit_Logger();
			for ( $i = 0; $i < 90; $i++ ) {
				$logger->info( 'event', 'round ' . $round . ' #' . $i );
			}
			$logger->flush();
		}
		$this->assertCount( Audit_Logger::MAX_ENTRIES, get_option( Audit_Logger::OPTION ) );
	}

	public function test_entries_are_buffered_and_written_once() {
		$writes = 0;
		add_filter(
			'pre_update_option_' . Audit_Logger::OPTION,
			static function ( $value ) use ( &$writes ) {
				++$writes;
				return $value;
			}
		);
		$logger = new Audit_Logger();
		for ( $i = 0; $i < 25; $i++ ) {
			$logger->info( 'event', 'burst ' . $i );
		}
		$this->assertSame( 0, $writes, 'Logging must not write to the database per event.' );
		$logger->flush();
		$this->assertSame( 1, $writes );
		$this->assertNotFalse( has_action( 'shutdown', array( $logger, 'flush' ) ), 'The buffer is flushed automatically at the end of the request.' );
	}

	public function test_the_log_is_not_autoloaded() {
		global $wpdb;
		$logger = new Audit_Logger();
		$logger->info( 'event', 'x' );
		$logger->flush();
		$autoload = $wpdb->get_var( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", Audit_Logger::OPTION ) );
		$this->assertContains( $autoload, array( 'no', 'off', 'auto-off' ), 'A log that grows must not be loaded on every request.' );
	}

	public function test_sensitive_looking_context_keys_are_redacted() {
		$logger = new Audit_Logger();
		$logger->info(
			'event',
			'x',
			array(
				'password'    => 'hunter2',
				'user_pass'   => 'hunter2',
				'auth_cookie' => 'abc',
				'api_token'   => 'tok',
				'secret'      => 's',
				'nonce'       => 'n',
				'salt'        => 'z',
				'option'      => 'default_comment_status',
			)
		);
		$entry = $logger->entries( 1 )[0];
		foreach ( array( 'password', 'user_pass', 'auth_cookie', 'api_token', 'secret', 'nonce', 'salt' ) as $key ) {
			$this->assertSame( '[redacted]', $entry['c'][ $key ], "$key must never be stored" );
		}
		$this->assertSame( 'default_comment_status', $entry['c']['option'] );
		$this->assertStringNotContainsString( 'hunter2', wp_json_encode( get_option( Audit_Logger::OPTION ) ) );
	}

	public function test_only_small_scalar_context_is_kept() {
		$logger  = new Audit_Logger();
		$context = array(
			'array'  => array( 'a' ),
			'object' => new \stdClass(),
			'null'   => null,
			'int'    => 7,
			'bool'   => true,
			'long'   => str_repeat( 'x', 5000 ),
		);
		for ( $i = 0; $i < 20; $i++ ) {
			$context[ 'k' . $i ] = $i;
		}
		$logger->info( 'event', 'x', $context );
		$entry = $logger->entries( 1 )[0]['c'];
		$this->assertArrayNotHasKey( 'array', $entry );
		$this->assertArrayNotHasKey( 'object', $entry );
		$this->assertArrayNotHasKey( 'null', $entry );
		$this->assertLessThanOrEqual( Audit_Logger::MAX_CONTEXT, count( $entry ) );
		foreach ( $entry as $value ) {
			if ( is_string( $value ) ) {
				$this->assertLessThanOrEqual( Audit_Logger::MAX_VALUE, strlen( $value ) );
			}
		}
	}

	public function test_messages_and_events_are_sanitized_and_capped() {
		$logger = new Audit_Logger();
		$logger->warning( "Bad Event!\n<script>", "line1\nline2\x00\x1b[31m" . str_repeat( 'm', 1000 ) );
		$entry = $logger->entries( 1 )[0];
		$this->assertMatchesRegularExpression( '/^[a-z0-9_]+$/', $entry['e'] );
		$this->assertDoesNotMatchRegularExpression( '/[\x00-\x1F]/', $entry['m'] );
		$this->assertLessThanOrEqual( Audit_Logger::MAX_MESSAGE, mb_strlen( $entry['m'] ) );
		$this->assertSame( 'warning', $entry['l'] );
	}

	public function test_an_unknown_level_falls_back_to_info() {
		$logger = new Audit_Logger();
		$logger->log( 'catastrophic', 'event', 'x' );
		$this->assertSame( 'info', $logger->entries( 1 )[0]['l'] );
	}

	public function test_entries_are_newest_first_and_limited() {
		$logger = new Audit_Logger();
		foreach ( array( 'first', 'second', 'third' ) as $message ) {
			$logger->info( 'event', $message );
		}
		$entries = $logger->entries( 2 );
		$this->assertSame( array( 'third', 'second' ), array_column( $entries, 'm' ) );
	}

	public function test_a_corrupted_stored_log_cannot_break_logging_or_reading() {
		foreach ( array( 'garbage', 42, true, array( 'not-an-entry', 5, null ) ) as $bad ) {
			update_option( Audit_Logger::OPTION, $bad );
			$logger = new Audit_Logger();
			$logger->info( 'event', 'after corruption' );
			$logger->flush();
			$entries = $logger->entries( 5 );
			$this->assertSame( 'after corruption', $entries[0]['m'] );
		}
	}

	public function test_the_retention_limit_filter_is_clamped() {
		add_filter( 'wp_security_lockdown_log_max_entries', '__return_zero' );
		$this->assertSame( 50, ( new Audit_Logger() )->max_entries() );
		remove_all_filters( 'wp_security_lockdown_log_max_entries' );
		add_filter(
			'wp_security_lockdown_log_max_entries',
			static function () {
				return 10000000;
			}
		);
		$this->assertSame( 1000, ( new Audit_Logger() )->max_entries(), 'A filter cannot turn the bounded log into an unbounded one.' );
	}
}
