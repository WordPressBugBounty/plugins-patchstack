<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to hide the login page, if it's enabled.
 */
class P_Hide_Login extends P_Core {
	/**
	 * Add the actions required to hide the login page.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		if ( $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		// Update the renamed login page if it's set to our hardcoded one. Write with the
		// same scope it is read back with below, otherwise this would rewrite every request.
		if ( (int) get_option( 'patchstack_mv_wp_login', 0 ) == 0 && get_option( 'patchstack_rename_wp_login' ) == 'swlogin' ) {
			update_option( 'patchstack_rename_wp_login', md5( wp_generate_password( 32, true, true ) ) );
		}

		// No need to continue if it is not enabled.
		if ( ! get_option( 'patchstack_mv_wp_login' ) || ! get_option( 'patchstack_rename_wp_login' ) ) {
			return;
		}

		// Register the filters and actions for the functionality.
		add_action( 'init', [ $this, 'init' ], ~PHP_INT_MAX + 1 );
		add_action( 'login_init', [ $this, 'guard_login' ], ~PHP_INT_MAX + 1 );
		add_action( 'wp_logout', [ $this, 'wp_logout' ] );
	}

	/**
	 * Route custom login visits while leaving WordPress login actions intact.
	 *
	 * @return void
	 */
	public function init() {
		$logged_in = is_user_logged_in();
		if ( $logged_in && is_admin() ) {
			return;
		}

		if ( isset( $GLOBALS['pagenow'] ) && $GLOBALS['pagenow'] === 'wp-login.php' ) {
			return;
		}

		// Guests visiting the custom URL receive ten minutes of access to the login page.
		$slug = get_option( 'patchstack_rename_wp_login' );
		if ( isset( $_SERVER['REQUEST_URI'] ) && strpos( $_SERVER['REQUEST_URI'], $slug ) !== false ) {
			if ( $logged_in ) {
				$path = untrailingslashit( (string) wp_parse_url( $_SERVER['REQUEST_URI'], PHP_URL_PATH ) );
				$login_path = untrailingslashit( (string) wp_parse_url( home_url( '/' . $slug ), PHP_URL_PATH ) );
				$core_login_path = untrailingslashit( (string) wp_parse_url( site_url( '/' . $slug ), PHP_URL_PATH ) );
				if ( $path !== $login_path && $path !== $core_login_path ) {
					return;
				}
			} else {
				$this->whitelist_ip();
			}

			// Supported by a number of popular caching plugins.
			if ( ! defined( 'DONOTCACHEPAGE' ) ) {
				define( 'DONOTCACHEPAGE', true );
			}

			// Because WP Fastest Cache just has to be special...
			if ( function_exists( 'wpfc_exclude_current_page' ) ) {
				@wpfc_exclude_current_page();
			}

			// No caching.
			send_nosniff_header();
			nocache_headers();

			wp_safe_redirect( $logged_in ? admin_url() : site_url( 'wp-login.php', 'login' ), $logged_in ? 302 : 307 );
			exit;
		}
	}

	public function guard_login() {
		// wp-login.php normalizes unsupported actions to login before firing login_init.
		global $action;
		if ( ! is_user_logged_in() && ! $this->is_whitelisted()
			&& ! in_array( $action, [ 'confirm_admin_email', 'postpass', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register', 'checkemail', 'confirmaction' ], true ) ) {
			$this->plugin->firewall_base->display_error_page( 'login' );
		}
	}

	/**
	 * If the user is logging out, whitelist them again so they don't see a blocked page.
	 * 
	 * @return void
	 */
	public function wp_logout() {
		$this->whitelist_ip();
	}

	/**
	 * Determine if the IP address is whitelisted.
	 * 
	 * @return boolean
	 */
	private function is_whitelisted() {
		// Process the whitelist, and remove old ones.
		$whitelist = get_option( 'patchstack_rename_wp_login_whitelist', [] );
		$new_whitelist = [];
		$allow = false;

		// Only continue if there are actually any whitelist entries.
		if ( is_array( $whitelist ) && count( $whitelist ) != 0 ){
			$ip = $this->get_ip();
			foreach ( $whitelist as $entry ) {

				// Determine if the whitelist entry is still valid.
				if ( ( time() - $entry[1] ) <= 600 ) {
					array_push( $new_whitelist, $entry );

					// Determine if the IP address matches.
					if ( $ip === $entry[0] ) {
						$allow = true;
					}
				}
			}

			update_option( 'patchstack_rename_wp_login_whitelist', $new_whitelist );
		}

		return $allow;
	}

	/**
	 * Whitelist the current IP address, or extend the time.
	 * 
	 * @return void
	 */
	private function whitelist_ip() {
		$whitelist = get_option( 'patchstack_rename_wp_login_whitelist', [] );
		$new_whitelist = [];

		// If the IP address is already whitelisted, reset the timestamp.
		if ( is_array( $whitelist ) && count( $whitelist ) != 0 ) {
			$ip = $this->get_ip();
			$whitelisted = false;
			foreach ( $whitelist as $entry ) {
				// Determine if we should extend the whitelist time or ignore if already whitelisted.
				if ( $ip === $entry[0] ) {
					$new_whitelist[] = [ $ip, time() ];
					$whitelisted = true;
				} else {
					$new_whitelist[] = $entry;
				}
			}

			// Whitelist the IP address.
			if ( ! $whitelisted ) {
				$new_whitelist[] = [ $ip, time() ];
			}

			update_option( 'patchstack_rename_wp_login_whitelist', $new_whitelist );
		} else {
			update_option( 'patchstack_rename_wp_login_whitelist', [ [ $this->get_ip(), time() ] ] );
		}
	}
}
