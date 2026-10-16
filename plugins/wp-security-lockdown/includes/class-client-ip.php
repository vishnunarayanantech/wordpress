<?php
/**
 * Client IP resolution and CIDR helpers.
 *
 * @package WP_Security_Lockdown
 */

namespace WP_Security_Lockdown;

defined( 'ABSPATH' ) || exit;

/**
 * Determines which network address a request should be attributed to.
 *
 * Rules:
 *  - `REMOTE_ADDR` is the only value a client cannot forge, so it is the default.
 *  - A forwarded-for header is honoured only when BOTH a header name and at least one trusted proxy
 *    range are configured AND the connecting peer (`REMOTE_ADDR`) is inside a trusted range.
 *  - `X-Forwarded-For` is parsed right-to-left, skipping trusted proxies; the first untrusted hop
 *    is the client. Entries to its left are client-controlled and are never read.
 */
class Client_IP {

	/**
	 * Trusted proxy IPs / CIDR ranges.
	 *
	 * @var string[] Trusted proxy IPs / CIDR ranges.
	 */
	private $trusted_proxies;

	/**
	 * Forwarded-for header name (a key of Settings_Repository::PROXY_HEADERS) or ''.
	 *
	 * @var string Header name (key of Settings_Repository::PROXY_HEADERS) or ''.
	 */
	private $header;

	/**
	 * Trusted proxy IPs / CIDR ranges.
	 *
	 * @param string[] $trusted_proxies Normalized IPs / CIDR ranges of reverse proxies you operate.
	 * @param string   $header          Forwarded-for header name, or '' to ignore all such headers.
	 */
	public function __construct( array $trusted_proxies = array(), $header = '' ) {
		$this->trusted_proxies = $trusted_proxies;
		$this->header          = isset( Settings_Repository::PROXY_HEADERS[ $header ] ) ? $header : '';
	}

	/**
	 * Attributes a request to a client address.
	 *
	 * @param array $server A $_SERVER-like array.
	 * @return array {
	 *     @type string|null $ip        Client IP, or null when it cannot be determined.
	 *     @type string|null $peer      The connecting peer (REMOTE_ADDR) when valid.
	 *     @type bool        $via_proxy True when a trusted proxy header supplied the client IP.
	 *     @type bool        $degraded  True when `ip` cannot be trusted to identify ONE client, i.e. it
	 *                                  is probably a shared proxy address. Callers must not punish it.
	 *     @type string|null $reason    unconfigured_proxy | proxy_header_unusable | null.
	 * }
	 */
	public function resolve( array $server ) {
		$peer   = isset( $server['REMOTE_ADDR'] ) && is_string( $server['REMOTE_ADDR'] ) ? trim( $server['REMOTE_ADDR'] ) : '';
		$result = array(
			'ip'        => null,
			'peer'      => null,
			'via_proxy' => false,
			'degraded'  => false,
			'reason'    => null,
		);

		if ( ! self::is_valid_ip( $peer ) ) {
			return $result;
		}
		$result['peer'] = $peer;
		$result['ip']   = $peer;

		$trusted_peer = $this->trusted_proxies && self::matches_any( $peer, $this->trusted_proxies );

		if ( '' !== $this->header && $trusted_peer ) {
			$client = $this->client_from_header( $server, Settings_Repository::PROXY_HEADERS[ $this->header ] );
			if ( null !== $client ) {
				$result['ip']        = $client;
				$result['via_proxy'] = true;
			} else {
				// A proxy we trust did not tell us who the client is: all users share its address.
				$result['degraded'] = true;
				$result['reason']   = 'proxy_header_unusable';
			}
			return $result;
		}

		/*
		 * Forwarding headers from a private/loopback peer that we were not told to trust almost
		 * certainly mean "behind a reverse proxy nobody configured". The peer address then
		 * identifies the proxy, not the visitor. (A public peer sending such headers is just a
		 * client trying to spoof; it is attributed to its real address.)
		 */
		if ( $this->has_forwarding_headers( $server ) && self::is_private_or_reserved( $peer ) ) {
			$result['degraded'] = true;
			$result['reason']   = 'unconfigured_proxy';
		}
		return $result;
	}

	/**
	 * Whether the connecting peer is a private / loopback / reserved address.
	 *
	 * @param string|null $ip IP address.
	 * @return bool
	 */
	public static function is_private_or_reserved( $ip ) {
		if ( ! is_string( $ip ) || ! self::is_valid_ip( $ip ) ) {
			return false;
		}
		if ( false === filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return true;
		}
		// PHP does not call RFC 6598 shared address space private, but carrier-grade NAT and many cloud
		// load balancers live there, so a peer in it is a proxy, not a visitor.
		return self::ip_in_cidr( $ip, '100.64.0.0/10' );
	}

	/**
	 * Validates a single IPv4 / IPv6 address.
	 *
	 * @param mixed $ip Candidate.
	 * @return bool
	 */
	public static function is_valid_ip( $ip ) {
		return is_string( $ip ) && false !== filter_var( $ip, FILTER_VALIDATE_IP );
	}

	/**
	 * Validates and normalizes an allowlist / proxy entry (single IP or CIDR).
	 *
	 * @param string $entry Raw entry.
	 * @return string|false Lower-case normalized entry, or false when invalid.
	 */
	public static function normalize_entry( $entry ) {
		$entry = strtolower( trim( (string) $entry ) );
		if ( '' === $entry ) {
			return false;
		}
		if ( false === strpos( $entry, '/' ) ) {
			return self::is_valid_ip( $entry ) ? $entry : false;
		}

		list( $net, $bits ) = explode( '/', $entry, 2 );
		$bin                = self::to_binary( $net );
		if ( false === $bin || '' === $bits || ! ctype_digit( $bits ) ) {
			return false;
		}
		if ( (int) $bits > strlen( $bin ) * 8 ) {
			return false;
		}
		return $net . '/' . (int) $bits;
	}

	/**
	 * Whether an address falls inside a single IP / CIDR entry.
	 *
	 * @param string $ip   Address to test.
	 * @param string $cidr Single IP or CIDR range.
	 * @return bool
	 */
	public static function ip_in_cidr( $ip, $cidr ) {
		$ip_bin = self::to_binary( $ip );
		if ( false === $ip_bin ) {
			return false;
		}

		$bits = null;
		$net  = $cidr;
		if ( false !== strpos( $cidr, '/' ) ) {
			list( $net, $bits ) = explode( '/', $cidr, 2 );
			if ( '' === $bits || ! ctype_digit( $bits ) ) {
				return false;
			}
			$bits = (int) $bits;
		}

		$net_bin = self::to_binary( $net );
		if ( false === $net_bin || strlen( $net_bin ) !== strlen( $ip_bin ) ) {
			return false;
			// Different address families never match.
		}

		$max  = strlen( $net_bin ) * 8;
		$bits = null === $bits ? $max : $bits;
		if ( $bits > $max ) {
			return false;
		}

		$whole = intdiv( $bits, 8 );
		if ( $whole > 0 && substr( $ip_bin, 0, $whole ) !== substr( $net_bin, 0, $whole ) ) {
			return false;
		}
		$rest = $bits % 8;
		if ( 0 === $rest ) {
			return true;
		}
		$mask = ( 0xFF << ( 8 - $rest ) ) & 0xFF;
		return ( ord( $ip_bin[ $whole ] ) & $mask ) === ( ord( $net_bin[ $whole ] ) & $mask );
	}

	/**
	 * Whether an address matches any entry in a list.
	 *
	 * @param string   $ip   Address to test.
	 * @param string[] $entries IPs / CIDR ranges.
	 * @return bool
	 */
	public static function matches_any( $ip, array $entries ) {
		foreach ( $entries as $entry ) {
			if ( self::ip_in_cidr( $ip, $entry ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the key under which failures are counted for an address.
	 *
	 * IPv6 addresses are grouped by /64 (one subscriber typically controls a whole /64), IPv4 by
	 * the exact address. The raw address is never used as a storage key: it is keyed-hashed.
	 *
	 * @param string $ip Client address.
	 * @return string 32 hex characters.
	 */
	public static function bucket_key( $ip ) {
		$bin = self::to_binary( $ip );
		if ( false === $bin ) {
			$material = 'x:' . $ip;
		} elseif ( 16 === strlen( $bin ) ) {
			$material = '6:' . bin2hex( substr( $bin, 0, 8 ) );
		} else {
			$material = '4:' . bin2hex( $bin );
		}
		return substr( hash_hmac( 'sha256', $material, wp_salt( 'auth' ) ), 0, 32 );
	}

	/**
	 * Converts an address to its packed binary form; IPv4-mapped IPv6 collapses to IPv4.
	 *
	 * @param string $ip Address.
	 * @return string|false
	 */
	private static function to_binary( $ip ) {
		if ( ! self::is_valid_ip( $ip ) ) {
			return false;
		}
		$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- inet_pton warns on malformed input; validated above.
		if ( false === $bin ) {
			return false;
		}
		if ( 16 === strlen( $bin ) && "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $bin, 0, 12 ) ) {
			return substr( $bin, 12 );
		}
		return $bin;
	}

	/**
	 * Whether any known forwarding header is present.
	 *
	 * @param array $server $_SERVER-like array.
	 * @return bool
	 */
	private function has_forwarding_headers( array $server ) {
		foreach ( Settings_Repository::PROXY_HEADERS as $key ) {
			if ( ! empty( $server[ $key ] ) ) {
				return true;
			}
		}
		return ! empty( $server['HTTP_FORWARDED'] );
	}

	/**
	 * Extracts the client address from a trusted proxy's header.
	 *
	 * @param array  $server     $_SERVER-like array.
	 * @param string $server_key Key such as HTTP_X_FORWARDED_FOR.
	 * @return string|null Null when the header is absent or unusable.
	 */
	private function client_from_header( array $server, $server_key ) {
		if ( empty( $server[ $server_key ] ) || ! is_string( $server[ $server_key ] ) ) {
			return null;
		}

		if ( 'HTTP_X_FORWARDED_FOR' !== $server_key ) {
			$value = trim( $server[ $server_key ] );
			return self::is_valid_ip( $value ) ? $value : null;
		}

		// Right-to-left: skip our own proxies; the first untrusted hop is the client.
		$hops = array_map( 'trim', explode( ',', $server[ $server_key ] ) );
		for ( $i = count( $hops ) - 1; $i >= 0; $i-- ) {
			if ( ! self::is_valid_ip( $hops[ $i ] ) ) {
				return null;
				// Malformed hop: do not guess.
			}
			if ( ! self::matches_any( $hops[ $i ], $this->trusted_proxies ) ) {
				return $hops[ $i ];
			}
		}
		return $hops[0];
		// Every hop was a trusted proxy: attribute to the leftmost.
	}
}
