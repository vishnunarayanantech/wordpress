<?php
/**
 * Plugin-owned runtime state: change ledger, verification results, activation record.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Persists everything the plugin needs to remember between requests that is NOT administrator
 * configuration (that lives in Settings_Repository). Stored in a single non-autoloaded option.
 */
class State_Repository {

	const OPTION = 'wp_security_lockdown_state';

	/**
	 * Per-request cache of the stored state.
	 *
	 * @var array|null
	 */
	private $cache = null;

	/**
	 * Returns the full state with every expected key present.
	 *
	 * @return array Full state with all expected keys present.
	 */
	public function all() {
		if ( null === $this->cache ) {
			$stored      = get_option( self::OPTION, array() );
			$stored      = is_array( $stored ) ? $stored : array();
			$this->cache = $stored + array(
				'ledger'          => array(),
				'verification'    => array(),
				'checks'          => array(),
				'activation'      => array(),
				'module_failures' => array(),
				'proxy_degraded'  => array(),
			);
			foreach ( array( 'ledger', 'verification', 'checks', 'activation', 'module_failures', 'proxy_degraded' ) as $key ) {
				if ( ! is_array( $this->cache[ $key ] ) ) {
					$this->cache[ $key ] = array();
				}
			}
		}
		return $this->cache;
	}

	/**
	 * Reads one top-level key.
	 *
	 * @param string $key Key.
	 * @return array
	 */
	public function get( $key ) {
		$all = $this->all();
		return isset( $all[ $key ] ) ? $all[ $key ] : array();
	}

	/**
	 * Replaces one top-level key and saves.
	 *
	 * @param string $key   Key.
	 * @param array  $value New value.
	 * @return void
	 */
	public function set( $key, array $value ) {
		$all         = $this->all();
		$all[ $key ] = $value;
		$this->cache = $all;
		update_option( self::OPTION, $all, false );
	}

	/**
	 * Change ledger: option name => entry (see Rollback).
	 *
	 * @return array
	 */
	public function ledger() {
		return $this->get( 'ledger' );
	}

	/**
	 * Replaces the change ledger.
	 *
	 * @param array $ledger New ledger.
	 * @return void
	 */
	public function set_ledger( array $ledger ) {
		$this->set( 'ledger', $ledger );
	}

	/**
	 * Stored verification results: control id => result.
	 *
	 * @return array
	 */
	public function verification() {
		return $this->get( 'verification' );
	}

	/**
	 * Merges verification results, stamping each with the policy fingerprint.
	 *
	 * @param array  $results     Control id => array( status, method, detail ).
	 * @param string $fingerprint Settings_Repository::fingerprint() at verification time.
	 * @return void
	 */
	public function record_verification( array $results, $fingerprint ) {
		$stored = $this->verification();
		foreach ( $results as $control => $result ) {
			$stored[ $control ] = array(
				'status'      => isset( $result['status'] ) ? (string) $result['status'] : 'unverified',
				'method'      => isset( $result['method'] ) ? (string) $result['method'] : 'none',
				'detail'      => isset( $result['detail'] ) ? substr( (string) $result['detail'], 0, 400 ) : '',
				'time'        => time(),
				'fingerprint' => (string) $fingerprint,
			);
		}
		$this->set( 'verification', $stored );
	}

	/**
	 * Records that a request was attributed to a shared proxy address (login limiter fails open).
	 *
	 * @param string $reason Reason code.
	 * @param string $scope  Identifies the proxy configuration in force. A record made under one
	 *                       configuration is not blamed on a later one (see Login_Protection).
	 * @return void
	 */
	public function note_proxy_degraded( $reason, $scope = '' ) {
		$seen = $this->get( 'proxy_degraded' );
		// At most one write per hour: this runs on login attempts and must stay cheap.
		if ( isset( $seen['time'] ) && ( time() - (int) $seen['time'] ) < HOUR_IN_SECONDS && ( $seen['reason'] ?? '' ) === $reason && ( $seen['scope'] ?? '' ) === $scope ) {
			return;
		}
		$this->set(
			'proxy_degraded',
			array(
				'time'   => time(),
				'reason' => (string) $reason,
				'scope'  => (string) $scope,
			)
		);
	}
}
