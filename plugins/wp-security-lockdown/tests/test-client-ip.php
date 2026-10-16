<?php
/**
 * Client IP resolution and CIDR matching.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown\Tests;

use WP_Security_Lockdown\Client_IP;

class Test_Client_IP extends Test_Case {

	public function test_remote_addr_is_used_by_default() {
		$client = ( new Client_IP() )->resolve( array( 'REMOTE_ADDR' => '203.0.113.9' ) );
		$this->assertSame( '203.0.113.9', $client['ip'] );
		$this->assertFalse( $client['via_proxy'] );
		$this->assertFalse( $client['degraded'] );
	}

	public function test_client_supplied_headers_are_ignored_when_nothing_is_trusted() {
		$server = array(
			'REMOTE_ADDR'           => '203.0.113.9',
			'HTTP_X_FORWARDED_FOR'  => '1.2.3.4',
			'HTTP_CF_CONNECTING_IP' => '5.6.7.8',
		);
		$client = ( new Client_IP() )->resolve( $server );
		$this->assertSame( '203.0.113.9', $client['ip'], 'A public client sending forwarding headers is just trying to spoof.' );
		$this->assertFalse( $client['degraded'], 'A public peer is the real client, so the address is fine to count.' );
	}

	public function test_header_is_ignored_when_the_peer_is_not_a_trusted_proxy() {
		$resolver = new Client_IP( array( '10.0.0.0/8' ), 'X-Forwarded-For' );
		$client   = $resolver->resolve(
			array(
				'REMOTE_ADDR'          => '198.51.100.20',
				'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
			)
		);
		$this->assertSame( '198.51.100.20', $client['ip'] );
		$this->assertFalse( $client['via_proxy'] );
	}

	public function test_header_requires_both_a_header_name_and_a_trusted_proxy() {
		$server = array(
			'REMOTE_ADDR'          => '10.0.0.5',
			'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
		);
		$this->assertTrue( ( new Client_IP( array( '10.0.0.0/8' ), '' ) )->resolve( $server )['degraded'], 'Trusted proxy but no header configured.' );
		$this->assertSame( '1.2.3.4', ( new Client_IP( array( '10.0.0.0/8' ), 'X-Forwarded-For' ) )->resolve( $server )['ip'] );
		$this->assertTrue( ( new Client_IP( array(), 'X-Forwarded-For' ) )->resolve( $server )['degraded'], 'Header configured but no trusted proxy.' );
	}

	public function test_x_forwarded_for_is_read_right_to_left_skipping_trusted_proxies() {
		$resolver = new Client_IP( array( '10.0.0.0/8', '192.0.2.0/24' ), 'X-Forwarded-For' );
		$client   = $resolver->resolve(
			array(
				'REMOTE_ADDR'          => '10.0.0.1',
				// The left-most entries are client-controlled; only the right-most untrusted hop counts.
				'HTTP_X_FORWARDED_FOR' => '9.9.9.9, 198.51.100.7, 192.0.2.50, 10.0.0.2',
			)
		);
		$this->assertSame( '198.51.100.7', $client['ip'] );
		$this->assertTrue( $client['via_proxy'] );
	}

	public function test_a_spoofed_entry_cannot_impersonate_another_client() {
		$resolver = new Client_IP( array( '10.0.0.1' ), 'X-Forwarded-For' );
		$a        = $resolver->resolve(
			array(
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.50, 198.51.100.7',
			)
		);
		$this->assertSame( '198.51.100.7', $a['ip'], 'The victim address 203.0.113.50 was written by the attacker, not by our proxy.' );
	}

	public function test_malformed_forwarding_data_is_never_guessed() {
		$resolver = new Client_IP( array( '10.0.0.1' ), 'X-Forwarded-For' );
		$client   = $resolver->resolve(
			array(
				'REMOTE_ADDR'          => '10.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '198.51.100.7, <script>',
			)
		);
		$this->assertTrue( $client['degraded'] );
		$this->assertSame( 'proxy_header_unusable', $client['reason'] );
	}

	public function test_all_hops_trusted_attributes_to_the_leftmost() {
		$resolver = new Client_IP( array( '10.0.0.0/8' ), 'X-Forwarded-For' );
		$this->assertSame(
			'10.1.1.1',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'          => '10.0.0.1',
					'HTTP_X_FORWARDED_FOR' => '10.1.1.1, 10.0.0.2',
				)
			)['ip']
		);
	}

	public function test_single_value_headers() {
		$resolver = new Client_IP( array( '10.0.0.0/8' ), 'CF-Connecting-IP' );
		$this->assertSame(
			'198.51.100.9',
			$resolver->resolve(
				array(
					'REMOTE_ADDR'           => '10.0.0.3',
					'HTTP_CF_CONNECTING_IP' => '198.51.100.9',
				)
			)['ip']
		);
		$bad = $resolver->resolve(
			array(
				'REMOTE_ADDR'           => '10.0.0.3',
				'HTTP_CF_CONNECTING_IP' => 'garbage',
			)
		);
		$this->assertTrue( $bad['degraded'] );
	}

	public function test_private_peer_with_forwarding_headers_but_no_trust_is_degraded() {
		$client = ( new Client_IP() )->resolve(
			array(
				'REMOTE_ADDR'          => '127.0.0.1',
				'HTTP_X_FORWARDED_FOR' => '203.0.113.9',
			)
		);
		$this->assertTrue( $client['degraded'] );
		$this->assertSame( 'unconfigured_proxy', $client['reason'] );
		$this->assertFalse( ( new Client_IP() )->resolve( array( 'REMOTE_ADDR' => '127.0.0.1' ) )['degraded'], 'Local traffic with no forwarding headers is simply local.' );
	}

	public function test_invalid_remote_addr_yields_no_client() {
		foreach ( array( array(), array( 'REMOTE_ADDR' => '' ), array( 'REMOTE_ADDR' => 'not an ip' ), array( 'REMOTE_ADDR' => array( '1.2.3.4' ) ) ) as $server ) {
			$this->assertNull( ( new Client_IP() )->resolve( $server )['ip'] );
		}
	}

	/**
	 * @dataProvider cidr_cases
	 */
	public function test_cidr_matching( $ip, $cidr, $expected ) {
		$this->assertSame( $expected, Client_IP::ip_in_cidr( $ip, $cidr ), "$ip in $cidr" );
	}

	public function cidr_cases() {
		return array(
			'exact ipv4'               => array( '203.0.113.5', '203.0.113.5', true ),
			'other ipv4'               => array( '203.0.113.6', '203.0.113.5', false ),
			'/24 inside'               => array( '198.51.100.200', '198.51.100.0/24', true ),
			'/24 outside'              => array( '198.51.101.1', '198.51.100.0/24', false ),
			'/20 boundary inside'      => array( '10.0.15.255', '10.0.0.0/20', true ),
			'/20 boundary outside'     => array( '10.0.16.0', '10.0.0.0/20', false ),
			'/0 matches everything'    => array( '8.8.8.8', '0.0.0.0/0', true ),
			'/32'                      => array( '1.2.3.4', '1.2.3.4/32', true ),
			'ipv6 /32 inside'          => array( '2001:db8:1234::1', '2001:db8::/32', true ),
			'ipv6 /32 outside'         => array( '2001:db9::1', '2001:db8::/32', false ),
			'ipv6 exact'               => array( '::1', '::1', true ),
			'family mismatch'          => array( '10.0.0.1', '2001:db8::/32', false ),
			'ipv4-mapped matches ipv4' => array( '::ffff:10.0.0.1', '10.0.0.0/8', true ),
			'prefix too long'          => array( '10.0.0.1', '10.0.0.0/33', false ),
			'garbage prefix'           => array( '10.0.0.1', '10.0.0.0/abc', false ),
			'garbage ip'               => array( 'nope', '10.0.0.0/8', false ),
			'negative-looking prefix'  => array( '10.0.0.1', '10.0.0.0/-1', false ),
		);
	}

	public function test_normalize_entry() {
		$this->assertSame( '203.0.113.5', Client_IP::normalize_entry( ' 203.0.113.5 ' ) );
		$this->assertSame( '2001:db8::/32', Client_IP::normalize_entry( '2001:DB8::/32' ) );
		foreach ( array( '', 'abc', '1.2.3.4/33', '1.2.3.4/', '::1/129', '1.2.3.4/8/8', '300.1.1.1' ) as $bad ) {
			$this->assertFalse( Client_IP::normalize_entry( $bad ), "'$bad' must be rejected" );
		}
	}

	public function test_bucket_keys() {
		$a = Client_IP::bucket_key( '203.0.113.5' );
		$this->assertSame( 32, strlen( $a ) );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $a );
		$this->assertStringNotContainsString( '203', $a, 'The raw address must not appear in the storage key.' );
		$this->assertNotSame( $a, Client_IP::bucket_key( '203.0.113.6' ) );
		$this->assertSame( Client_IP::bucket_key( '2001:db8:aaaa:bbbb::1' ), Client_IP::bucket_key( '2001:db8:aaaa:bbbb:ffff:ffff:ffff:ffff' ), 'IPv6 is bucketed by /64.' );
		$this->assertNotSame( Client_IP::bucket_key( '2001:db8:aaaa:bbbb::1' ), Client_IP::bucket_key( '2001:db8:aaaa:cccc::1' ) );
		$this->assertSame( Client_IP::bucket_key( '10.0.0.1' ), Client_IP::bucket_key( '::ffff:10.0.0.1' ), 'The mapped and plain forms of one host share a bucket.' );
	}

	public function test_private_or_reserved() {
		foreach ( array( '127.0.0.1', '10.1.2.3', '192.168.0.9', '172.16.5.5', '169.254.1.1', '::1', 'fe80::1', 'fc00::1', '100.64.0.1', '100.127.255.254' ) as $ip ) {
			$this->assertTrue( Client_IP::is_private_or_reserved( $ip ), "$ip is a private / shared / reserved address" );
		}
		foreach ( array( '8.8.8.8', '1.1.1.1', '100.63.255.255', '100.128.0.1', '2606:4700:4700::1111' ) as $ip ) {
			$this->assertFalse( Client_IP::is_private_or_reserved( $ip ), "$ip is a public address" );
		}
		$this->assertFalse( Client_IP::is_private_or_reserved( 'bad' ) );
		$this->assertFalse( Client_IP::is_private_or_reserved( null ) );
	}

	public function test_a_proxy_in_shared_address_space_is_detected_as_unconfigured() {
		$client = ( new Client_IP() )->resolve(
			array(
				'REMOTE_ADDR'          => '100.64.3.4',
				'HTTP_X_FORWARDED_FOR' => '8.8.4.4',
			)
		);
		$this->assertTrue( $client['degraded'], 'A load balancer in 100.64.0.0/10 must not make all visitors share one lockout bucket.' );
	}
}
