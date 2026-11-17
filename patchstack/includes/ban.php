<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to determine if the IP address of the
 * user is banned. Along with that we check the IP address whitelist.
 */
class P_Ban extends P_Core {

	/**
	 * Add the actions required for determining the ban.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		if ( $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		add_action( 'init', [ $this, 'ip_ban' ], ~PHP_INT_MAX + 1 );
	}

	/**
	 * Determine if the IP address of the user is blocked.
	 *
	 * @return void
	 */
	public function ip_ban() {
		if ( ! is_user_logged_in() && $this->is_ip_blocked( $this->get_ip() ) ) {
			$this->plugin->firewall_base->display_error_page( 22 );
		}
	}

	/**
	 * Check IP ban.
	 *
	 * @param string $ip The IP address of the user.
	 * @return boolean Whether or not the user is blocked.
	 */
	public function is_ip_blocked( $ip ) {
		return $this->matches_rules( $ip, $this->get_option( 'patchstack_ip_block_list', '' ) );
	}

	/**
	 * Check IP whitelist for login protection.
	 *
	 * @param string $ip The IP address of the user.
	 * @return boolean Whether or not the user is whitelisted.
	 */
	public function is_ip_whitelisted( $ip ) {
		return $this->matches_rules( $ip, $this->get_option( 'patchstack_login_whitelist', '' ) );
	}

	private function matches_rules( $ip, $rules ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! is_string( $rules ) || $rules === '' ) {
			return false;
		}
		foreach ( explode( "\n", $rules ) as $rule ) {
			$rule = trim( $rule );
			if ( strpos( $rule, '*' ) !== false ) {
				$match = $this->check_wildcard_rule( $ip, $rule );
			} elseif ( strpos( $rule, '-' ) !== false ) {
				$match = $this->check_range_rule( $ip, $rule );
			} elseif ( strpos( $rule, '/' ) !== false ) {
				$match = $this->check_subnet_mask_rule( $ip, $rule );
			} else {
				$match = inet_pton( $ip ) === @inet_pton( $rule );
			}
			if ( $match ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * CIDR notation IP block check.
	 *
	 * @param string $ip The IP address of the user.
	 * @param string $range The range to check.
	 * @return boolean Whether or not the IP is in the range.
	 */
	public function check_subnet_mask_rule( $ip, $range ) {
		$parts = explode( '/', $range, 2 );
		if ( count( $parts ) !== 2 || ! ctype_digit( $parts[1] ) ) {
			return false;
		}
		$network = @inet_pton( $parts[0] );
		$address = @inet_pton( $ip );
		$bits = (int) $parts[1];
		if ( $network === false || $address === false || strlen( $network ) !== strlen( $address ) || $bits > strlen( $address ) * 8 ) {
			return false;
		}
		$bytes = (int) ( $bits / 8 );
		$remainder = $bits % 8;
		return substr( $network, 0, $bytes ) === substr( $address, 0, $bytes )
			&& ( ! $remainder || ( ord( $network[$bytes] ) >> ( 8 - $remainder ) ) === ( ord( $address[$bytes] ) >> ( 8 - $remainder ) ) );
	}

	/**
	 * Wildcard IP block check.
	 *
	 * @param string $ip The IP address of the user.
	 * @param string $rule The wildcard range to check against.
	 * @return boolean Whether or not the IP is in the wilcard range.
	 */
	public function check_wildcard_rule( $ip, $rule ) {
		$pattern = str_replace( '\*', '[0-9a-f:.]*', preg_quote( $rule, '~' ) );
		return filter_var( $ip, FILTER_VALIDATE_IP ) && preg_match( '~^' . $pattern . '$~iD', $ip ) === 1;
	}

	/**
	 * IP range block check.
	 *
	 * @param string|array $ip The IP address of the user.
	 * @param string       $rule The range to check against.
	 * @return boolean Whether or not the IP is in the range.
	 */
	public function check_range_rule( $ip, $rule ) {
		$parts = explode( '-', $rule, 2 );
		if ( count( $parts ) !== 2 ) {
			return false;
		}
		$start = @inet_pton( trim( $parts[0] ) );
		$end = @inet_pton( trim( $parts[1] ) );
		$address = @inet_pton( is_array( $ip ) ? reset( $ip ) : $ip );
		return $start !== false && $end !== false && $address !== false
			&& strlen( $start ) === strlen( $address ) && strlen( $end ) === strlen( $address )
			&& strcmp( $address, $start ) >= 0 && strcmp( $address, $end ) <= 0;
	}
}
