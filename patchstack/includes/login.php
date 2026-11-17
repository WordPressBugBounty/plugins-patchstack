<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to alter anything related to the login page.
 */
class P_Login extends P_Core {
	private $local_2fa = false;
	private $needs_2fa = false;
	private $pending_profile_change;


	/**
	 * Validated request or not.
	 * 
	 * @param boolean
	 */
	private $validated = false;
	private $captcha_loaded = false;

	/**
	 * Add the actions required to interact with the login process.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		add_action( 'wp_scheduled_delete', [ $this, 'expire_login_records' ] );
		$free = $this->get_option( 'patchstack_license_free', 0 ) == 1;
		$this->local_2fa = ! $free && $this->get_option( 'patchstack_login_2fa', 0 );
		if ( is_multisite() ) {
			// Whether any site of a network enforces 2FA is remembered; these settings decide it.
			foreach ( [ 'updated_option', 'added_option', 'deleted_option' ] as $hook ) {
				add_action( $hook, [ $this, 'forget_network_2fa' ], 10, 1 );
			}
		}
		if ( $this->local_2fa || is_multisite() ) {
			add_filter( 'authenticate', [ $this, 'tfa_authenticate' ], 30, 3 );
			add_action( 'login_form', [ $this, 'tfa_login_form' ] );
			add_action( 'woocommerce_login_form', [ $this, 'tfa_woocommerce_login_form' ] );
		}
		if ( $free ) {
			return;
		}

		// Forms are processed before they are rendered, so the checks cannot wait for a form
		// to register them. The CAPTCHA settings are not autoloaded,
		// so they are read when one of these hooks first runs and not on every request.
		foreach ( [ 'login_form', 'register_form', 'lostpassword_form', 'woocommerce_login_form', 'woocommerce_register_form', 'woocommerce_lostpassword_form', 'woocommerce_process_login_errors', 'authenticate', 'registration_errors', 'woocommerce_process_registration_errors', 'lostpassword_post', 'before_signup_form' ] as $hook ) {
			add_filter( $hook, [ $this, 'load_captcha' ], 0 );
		}
		add_action( 'login_init', [ $this, 'check_ipban' ] );
		add_filter( 'authenticate', [ $this, 'authenticate_ipban' ], 100, 3 );
		add_action( 'wp_login_failed', [ $this, 'record_failed_login' ], 10, 2 );
		add_action( 'login_enqueue_scripts', [ $this, 'login_enqueue_scripts' ], 1 );

		// 2FA related actions.
		if ( $this->local_2fa ) {
			add_action( 'profile_personal_options', [ $this, 'tfa_profile_personal_options' ] );
			add_action( 'personal_options', [ $this, 'tfa_personal_options' ] );
			add_action( 'edit_user_profile_update', [ $this, 'tfa_options_update' ] );
			add_action( 'user_profile_update_errors', [ $this, 'tfa_profile_update_errors' ], 99, 3 );
			add_action( 'profile_update', [ $this, 'tfa_commit_profile_change' ] );
			add_action( 'all_admin_notices', [ $this, 'tfa_profile_save_notice' ] );
			add_action( 'admin_enqueue_scripts', [ $this, 'tfa_admin_enqueue_scripts' ] );

			// WooCommerce related functionality.
			if ( class_exists( 'WooCommerce' ) ) {
				add_action( 'woocommerce_edit_account_form', [ $this, 'tfa_woocommerce_profile_personal_options' ] );
				add_action( 'woocommerce_save_account_details_errors', [ $this, 'tfa_woocommerce_validate_tfa' ], 10, 2 );
			}
		}
	}

	/**
	 * Register the Google reCAPTCHA JavaScript for the login area.
	 *
	 * @return void
	 */
	public function login_enqueue_scripts() {
		if ( $this->get_option( 'patchstack_captcha_login_form', false ) && $this->get_option( 'patchstack_captcha_type' ) != 'v3' && $this->get_option( 'patchstack_captcha_type' ) != 'turnstile' ) {
			wp_enqueue_script( 'patchstack_captcha', 'https://www.google.com/recaptcha/api.js' );
		}
	}

	/**
	 * Add the 2FA code to the login form.
	 *
	 * @return void
	 */
	public function tfa_login_form() {
		if ( ! $this->local_2fa && ! $this->needs_2fa ) {
			return;
		}
		require_once dirname( __FILE__ ) . '/views/2fa-login-form.php';
	}

	/**
	 * Add the 2FA code to the WooCommerce login form.
	 *
	 * @return void
	 */
	public function tfa_woocommerce_login_form() {
		if ( ! $this->local_2fa && ! $this->needs_2fa ) {
			return;
		}
		require_once dirname( __FILE__ ) . '/views/2fa-login-form-woocommerce.php';
	}

	/**
	 * Whether any site of a network enforces 2FA. Looking at every site costs a query per
	 * site, so the answer is kept for an hour and dropped as soon as a site changes one of
	 * the two settings that decide it.
	 *
	 * @param int $network_id
	 * @return boolean
	 */
	private function network_enforces_2fa( $network_id ) {
		$known = get_network_option( $network_id, 'patchstack_2fa_enforced', false );
		if ( is_array( $known ) && isset( $known['enforced'], $known['time'] ) && $known['time'] > time() - HOUR_IN_SECONDS && $known['time'] <= time() ) {
			return (bool) $known['enforced'];
		}

		// Read the two settings straight from each site's table: switching to every site
		// would load all of its options and keep them in memory for the rest of the request.
		global $wpdb;
		$enforced = false;
		$previous = $wpdb->suppress_errors( true );
		try {
			foreach ( get_sites( [ 'network_id' => $network_id, 'number' => 0, 'fields' => 'ids' ] ) as $blog_id ) {
				$table = $wpdb->get_blog_prefix( $blog_id ) . 'options';
				$set = $wpdb->get_col( "SELECT option_name FROM `$table` WHERE option_name IN ('patchstack_login_2fa', 'patchstack_license_free') AND option_value NOT IN ('', '0')" );
				if ( is_array( $set ) && in_array( 'patchstack_login_2fa', $set, true ) && ! in_array( 'patchstack_license_free', $set, true ) ) {
					$enforced = true;
					break;
				}
			}
		} finally {
			$wpdb->suppress_errors( $previous );
		}

		update_network_option( $network_id, 'patchstack_2fa_enforced', [ 'enforced' => $enforced ? 1 : 0, 'time' => time() ] );
		return $enforced;
	}

	/**
	 * Drop the remembered answer when a site turns 2FA on or off or changes its plan.
	 *
	 * @param string $option_name
	 * @return void
	 */
	public function forget_network_2fa( $option_name ) {
		if ( $option_name !== 'patchstack_login_2fa' && $option_name !== 'patchstack_license_free' ) {
			return;
		}

		$site = get_site( get_current_blog_id() );
		if ( $site ) {
			delete_network_option( $site->network_id, 'patchstack_2fa_enforced' );
		}
	}

	/**
	 * Check the 2FA code, if 2FA is enabled for the user.
	 *
	 * @param object $user
	 * @param string $username
	 * @param string $password
	 * @return object|WP_User|WP_Error
	 */
	public function tfa_authenticate( $user, $username = '', $password = '' ) {
		if ( ! isset( $user->ID ) ) {
			return $user;
		}

		// If we have a valid user object, check to see if the user has 2FA enabled.
		$enabled = $this->get_2fa_option( $user->ID, 'enabled' );
		if ( empty( $enabled ) ) {
			return $user;
		}

		if ( ! $this->local_2fa && is_multisite() ) {
			$this->needs_2fa = false;
			// A login on any blog can issue a cookie for a shared account.
			foreach ( get_blogs_of_user( $user->ID ) as $blog ) {
				if ( get_blog_option( $blog->userblog_id, 'patchstack_login_2fa' ) && ! get_blog_option( $blog->userblog_id, 'patchstack_license_free' ) ) {
					$this->needs_2fa = true;
					break;
				}
			}
			if ( ! $this->needs_2fa ) {
				// Super admins can access their networks' sites without explicit memberships.
				foreach ( get_networks( [ 'number' => 0, 'fields' => 'ids' ] ) as $network_id ) {
					$admins = isset( $GLOBALS['super_admins'] ) ? $GLOBALS['super_admins'] : get_network_option( $network_id, 'site_admins', [ 'admin' ] );
					if ( ! is_array( $admins ) || ! in_array( $user->user_login, $admins ) ) {
						continue;
					}
					if ( $this->network_enforces_2fa( $network_id ) ) {
						$this->needs_2fa = true;
						break;
					}
				}
			}
			if ( ! $this->needs_2fa ) {
				return $user;
			}
		}

		// If enabled, check to see if the verification code is being sent.
		if ( ! isset( $_POST['patchstack_2fa'] ) || $_POST['patchstack_2fa'] === '' ) {
			return new WP_Error( 'patchstack_2fa_empty_code', esc_attr__( 'Please enter the 2FA authentication code that is generated on your device.', 'patchstack' ) );
		}

		if ( $this->local_2fa && $this->login_ip_is_blocked() ) {
			return $this->login_blocked_error();
		}
		$result = $this->tfa_check_code( $user, $_POST['patchstack_2fa'] );
		return is_wp_error( $result ) ? $result : $user;
	}

	/**
	 * Check one code under the account's lock and failure limit.
	 * A login also consumes the code. An enrollment change only needs proof of the device.
	 *
	 * @param object $user
	 * @param mixed  $code
	 * @param bool   $consume
	 * @return true|WP_Error
	 */
	private function tfa_check_code( $user, $code, $consume = true ) {
		$lock_name = 'patchstack_2fa_lock_' . (int) $user->ID;
		$lock = $this->acquire_lock( $lock_name, 30, true );
		if ( ! $lock ) {
			return new WP_Error( 'patchstack_2fa_busy', esc_attr__( 'Please wait before trying another 2FA code.', 'patchstack' ) );
		}
		try {
			// User metadata is shared across blogs; discard request-local state after acquiring its lock.
			wp_cache_delete( $user->ID, 'user_meta' );
			require_once dirname( __FILE__ ) . '/2fa/rfc6238.php';
			$secret = $this->tfa_get_secret( $user, false );
			if ( ! is_string( $secret ) || $secret === '' ) {
				return new WP_Error( 'patchstack_2fa_unavailable', esc_attr__( 'The 2FA code could not be verified. Please try again.', 'patchstack' ) );
			}
			$fingerprint = hash( 'sha256', (string) $secret );
			$previous = get_user_meta( $user->ID, '_patchstack_2fa_state', true );
			$state = $previous;
			$now = time();
			if ( ! is_array( $state ) || ! isset( $state['key'], $state['failures'], $state['started'], $state['last_step'] ) || $state['key'] !== $fingerprint ) {
				$state = [ 'key' => $fingerprint, 'failures' => 0, 'started' => $now, 'last_step' => -1 ];
			}
			if ( isset( $state['blocked_until'] ) && $state['blocked_until'] > $now ) {
				return new WP_Error( 'patchstack_2fa_locked', esc_attr__( 'Too many incorrect 2FA codes. Please try again in five minutes.', 'patchstack' ) );
			}
			if ( $now - $state['started'] >= 300 ) {
				$state['failures'] = 0;
				$state['started'] = $now;
				unset( $state['blocked_until'] );
			}
			if ( (int) $lock <= $now ) {
				return new WP_Error( 'patchstack_2fa_busy', esc_attr__( 'Please wait before trying another 2FA code.', 'patchstack' ) );
			}
			$code = is_string( $code ) ? trim( $code ) : '';
			$step = TokenAuth6238::verify_time_step( $secret, $code );
			if ( $step === false || ( $consume && $step <= $state['last_step'] ) ) {
				$state['failures']++;
				if ( $state['failures'] >= 5 ) {
					$state['blocked_until'] = $now + 300;
				}
				update_user_meta( $user->ID, '_patchstack_2fa_state', $state, $previous );
				return new WP_Error( 'patchstack_2fa_invalid_code', esc_attr__( 'The 2FA authentication code you entered is invalid.', 'patchstack' ) );
			}
			if ( ! $consume ) {
				return true;
			}
			$state['last_step'] = $step;
			$state['failures'] = 0;
			$state['started'] = $now;
			unset( $state['blocked_until'] );
			if ( ! update_user_meta( $user->ID, '_patchstack_2fa_state', $state, $previous ) ) {
				return new WP_Error( 'patchstack_2fa_unavailable', esc_attr__( 'The 2FA code could not be verified. Please try again.', 'patchstack' ) );
			}
			return true;
		} finally {
			$this->release_lock( $lock_name, $lock, true );
		}
	}

	/**
	 * Show the 2FA disable field to the admin.
	 * 
	 * @param object $user
	 * @return void
	 */
	public function tfa_personal_options( $user ) {
		// The user's own profile has the full form below, which asks for a code.
		if ( defined( 'IS_PROFILE_PAGE' ) && IS_PROFILE_PAGE ) {
			return;
		}
		require_once dirname( __FILE__ ) . '/views/2fa-profile-configuration-admin.php';
	}

	/**
	 * Show the 2FA fields.
	 *
	 * @param object $user
	 * @return void
	 */
	public function tfa_profile_personal_options( $user ) {
		// Once enrolled, the secret is no longer shown: it would let any session clone the device.
		$enabled = (bool) $this->get_2fa_option( $user->ID, 'enabled' );
		$secret  = $enabled ? '' : $this->tfa_get_secret( $user );
		if ( ! $enabled && ! $secret ) {
			echo '<p class="notice notice-error">' . esc_html__( 'The 2FA setup could not be saved. Please try again.', 'patchstack' ) . '</p>';
			return;
		}
		require_once dirname( __FILE__ ) . '/views/2fa-profile-configuration.php';
	}

	/**
	 * Show the 2FA fields.
	 *
	 * @return void
	 */
	public function tfa_woocommerce_profile_personal_options() {
		$user = wp_get_current_user();
		if ( ! $user->exists() ) {
			return;
		}
		$enabled = (bool) $this->get_2fa_option( $user->ID, 'enabled' );
		$secret  = $enabled ? '' : $this->tfa_get_secret( $user );
		if ( ! $enabled && ! $secret ) {
			echo '<p class="notice notice-error">' . esc_html__( 'The 2FA setup could not be saved. Please try again.', 'patchstack' ) . '</p>';
			return;
		}
		require_once dirname( __FILE__ ) . '/views/2fa-profile-configuration-woocommerce.php';
	}

	/**
	 * Validate the 2FA connection of a WooCommerce customer.
	 * 
	 * @param mixed $errors
	 * @param mixed $user
	 * @return void
	 */
	public function tfa_woocommerce_validate_tfa( &$errors, &$user ) {
		if ( isset( $user->ID ) && $this->tfa_enrollment_change_verified( $user, $errors ) ) {
			add_action( 'woocommerce_save_account_details', [ $this, 'tfa_woocommerce_save_enrollment' ] );
		}
	}

	/**
	 * Store a verified 2FA change once WooCommerce has saved the account.
	 *
	 * @param integer $user_id
	 * @return void
	 */
	public function tfa_woocommerce_save_enrollment( $user_id ) {
		if ( ! $this->tfa_save_enrollment( $user_id ) && function_exists( 'wc_add_notice' ) ) {
			wc_add_notice( __( 'The 2FA setting could not be saved. Please try again.', 'patchstack' ), 'error' );
		}
	}

	/**
	 * Verify a profile change before WordPress decides whether to save the user.
	 *
	 * @param WP_Error $errors
	 * @param bool     $update
	 * @param object   $user
	 * @return void
	 */
	public function tfa_profile_update_errors( $errors, $update, $user ) {
		if ( ! $update || ! isset( $user->ID ) ) {
			return;
		}
		$user_id = (int) $user->ID;
		if ( $user_id === get_current_user_id() ) {
			$this->pending_profile_change = null;
			if ( ! $errors->get_error_codes() && $this->tfa_enrollment_change_verified( $user, $errors ) ) {
				$this->pending_profile_change = [ 'user_id' => $user_id, 'enabled' => ! empty( $_POST['patchstack_2fa_enabled'] ) ];
			}
		}
		if ( $this->pending_profile_change && $this->pending_profile_change['user_id'] === $user_id ) {
			// Later validators can still reject this save.
			$this->pending_profile_change['errors'] = $errors;
		}
	}

	public function tfa_commit_profile_change( $user_id ) {
		$change = $this->pending_profile_change;
		if ( ! isset( $change['errors'] ) || $change['user_id'] !== (int) $user_id ) {
			return;
		}
		$this->pending_profile_change = null;
		if ( ! $change['errors']->get_error_codes() && ! $this->tfa_set_enrollment( $user_id, $change['enabled'] ) ) {
			set_transient( 'patchstack_2fa_save_error_' . get_current_user_id(), 1, MINUTE_IN_SECONDS );
		}
	}

	public function tfa_profile_save_notice() {
		global $pagenow;
		if ( ! in_array( $pagenow, [ 'profile.php', 'user-edit.php' ], true ) ) {
			return;
		}
		$key = 'patchstack_2fa_save_error_' . get_current_user_id();
		if ( get_transient( $key ) ) {
			delete_transient( $key );
			echo '<div class="notice notice-error"><p>' . esc_html__( 'The profile was saved, but the 2FA setting could not be saved. Please try again.', 'patchstack' ) . '</p></div>';
		}
	}

	/**
	 * Determine if the submitted profile form changes the 2FA setting and carries a valid code for it.
	 * Enabling needs the code to prove the device is set up. Disabling needs it so that a stolen
	 * session, or a profile form that simply lacks the field, cannot switch 2FA off.
	 *
	 * @param object   $user
	 * @param WP_Error $errors
	 * @return bool
	 */
	private function tfa_enrollment_change_verified( $user, $errors ) {
		if ( empty( $_POST['patchstack_2fa_profile'] ) || (bool) $this->get_2fa_option( $user->ID, 'enabled' ) === ! empty( $_POST['patchstack_2fa_enabled'] ) ) {
			return false;
		}
		$code = isset( $_POST['patchstack_2fa_secretkey_verification'] ) ? $_POST['patchstack_2fa_secretkey_verification'] : '';
		if ( $code === '' ) {
			$errors->add( 'patchstack_2fa_empty_code', __( 'Enter the current code from your 2FA app to change the 2FA setting.', 'patchstack' ) );
			return false;
		}
		$result = $this->tfa_check_code( $user, $code, false );
		if ( is_wp_error( $result ) ) {
			$errors->add( $result->get_error_code(), $result->get_error_message() );
			return false;
		}
		return true;
	}

	/**
	 * Store the submitted 2FA setting of a user whose change has been verified.
	 *
	 * @param integer $user_id
	 * @return bool Whether the setting and any secret retirement were saved.
	 */
	public function tfa_save_enrollment( $user_id ) {
		return $this->tfa_set_enrollment( $user_id, ! empty( $_POST['patchstack_2fa_enabled'] ) );
	}

	/**
	 * An administrator can switch 2FA off for another account, as the way back in for a lost device.
	 * Switching it on is left to the account's owner, who has the device.
	 *
	 * @param integer $user_id
	 * @return void
	 */
	public function tfa_options_update( $user_id ) {
		$this->pending_profile_change = null;
		if ( (int) $user_id !== get_current_user_id() && ! empty( $_POST['patchstack_2fa_profile'] ) && empty( $_POST['patchstack_2fa_enabled'] ) && current_user_can( 'edit_user', $user_id ) ) {
			$this->pending_profile_change = [ 'user_id' => (int) $user_id, 'enabled' => false ];
		}
	}

	private function tfa_set_enrollment( $user_id, $enabled ) {
		if ( ! $enabled ) {
			return $this->reset_user_2fa( $user_id );
		}
		$lock_name = 'patchstack_2fa_lock_' . (int) $user_id;
		$lock = $this->acquire_lock( $lock_name, 30, true );
		if ( ! $lock ) {
			return false;
		}
		try {
			wp_cache_delete( $user_id, 'user_meta' );
			if ( get_user_meta( $user_id, '_patchstack_2fa_reset_pending', true ) || ! metadata_exists( 'user', $user_id, 'patchstack_2fa_enabled' ) ) {
				return false;
			}
			// A reset can replace the secret between profile validation and the actual save.
			$secret = $this->tfa_get_secret( get_userdata( $user_id ), false );
			$code = isset( $_POST['patchstack_2fa_secretkey_verification'] ) ? $_POST['patchstack_2fa_secretkey_verification'] : '';
			require_once dirname( __FILE__ ) . '/2fa/rfc6238.php';
			if ( ! is_string( $secret ) || $secret === '' || ! is_string( $code ) || TokenAuth6238::verify_time_step( $secret, trim( $code ) ) === false ) {
				return false;
			}
			update_user_meta( $user_id, 'patchstack_2fa_enabled', 1 );
			return (bool) $this->get_2fa_option( $user_id, 'enabled' );
		} finally {
			$this->release_lock( $lock_name, $lock, true );
		}
	}

	/**
	 * Add the QRCode image generator JavaScript library.
	 *
	 * @return void
	 */
	public function tfa_admin_enqueue_scripts() {
		wp_register_script( 'patchstack_qrcode', $this->plugin->url . '/assets/js/qrcode.min.js', [], $this->plugin->version );
		wp_enqueue_script( 'patchstack_qrcode' );
	}

	/**
	 * In case of legacy conditions, we encrypt the secret key and then store it.
	 * 
	 * @return string
	 */
	private function tfa_get_secret( $user, $create = true ) {
		// Verification already owns this account lock; profile rendering also writes enrollment data.
		$lock_name = 'patchstack_2fa_lock_' . (int) $user->ID;
		$lock = $create ? $this->acquire_lock( $lock_name, 30, true ) : false;
		if ( $create && ! $lock ) {
			return false;
		}
		try {
			wp_cache_delete( $user->ID, 'user_meta' );
			$enabled = $this->get_2fa_option( $user->ID, 'enabled' );
			if ( ! $enabled && get_user_meta( $user->ID, '_patchstack_2fa_reset_pending', true ) && ! $this->retire_2fa_secret( $user->ID ) ) {
				return false;
			}
			$stored = $this->get_2fa_option( $user->ID, 'secretkey' );
			$nonce = $this->get_2fa_option( $user->ID, 'secretkey_nonce' );
			if ( ( ! empty( $stored ) && ! is_string( $stored ) ) || ( ! $create && empty( $stored ) ) ) {
				return false;
			}
			if ( empty( $stored ) ) {
				update_user_meta( $user->ID, '_patchstack_2fa_reset_pending', 1 );
				if ( ! get_user_meta( $user->ID, '_patchstack_2fa_reset_pending', true ) ) {
					return false;
				}
				require_once dirname( __FILE__ ) . '/2fa/rfc6238.php';
				$secret = TokenAuth6238::generateRandomClue();
			} else {
				$secret = strlen( $stored ) === 16 ? $stored : $this->decrypt( $stored, $nonce );
			}
			if ( ! is_string( $secret ) || $secret === '' ) {
				return false;
			}
			if ( empty( $stored ) || ! metadata_exists( 'user', $user->ID, 'patchstack_2fa_enabled' ) ) {
				$enc = empty( $stored ) || strlen( $stored ) === 16 ? $this->encrypt( $secret ) : [ 'cipher' => $stored, 'nonce' => $nonce ];
				update_user_meta( $user->ID, 'patchstack_2fa_secretkey', $enc['cipher'] );
				update_user_meta( $user->ID, 'patchstack_2fa_secretkey_nonce', $enc['nonce'] );
				$complete = get_user_meta( $user->ID, 'patchstack_2fa_secretkey', true ) === $enc['cipher']
					&& get_user_meta( $user->ID, 'patchstack_2fa_secretkey_nonce', true ) === (string) $enc['nonce'];
				if ( $complete ) {
					update_user_meta( $user->ID, 'patchstack_2fa_enabled', $enabled ? 1 : 0 );
					$complete = metadata_exists( 'user', $user->ID, 'patchstack_2fa_enabled' );
				}
				if ( $complete ) {
					foreach ( [ 'webarx_2fa_enabled', 'webarx_2fa_secretkey', 'webarx_2fa_secretkey_nonce' ] as $key ) {
						delete_user_meta( $user->ID, $key );
					}
				}
				// Existing accounts retain the usable legacy secret if migration cannot finish.
				if ( empty( $stored ) ) {
					if ( ! $complete ) {
						return false;
					}
					delete_user_meta( $user->ID, '_patchstack_2fa_reset_pending' );
					if ( get_user_meta( $user->ID, '_patchstack_2fa_reset_pending', true ) ) {
						return false;
					}
				}
			}
			return $secret;
		} finally {
			if ( $lock ) {
				$this->release_lock( $lock_name, $lock, true );
			}
		}
	}

	private function login_blocked_error() {
		return new WP_Error( 'patchstack_login_blocked', esc_attr__( 'Too many failed login attempts. Please try again later.', 'patchstack' ) );
	}

	private function login_ip_is_blocked() {
		if ( ! $this->get_option( 'patchstack_block_bruteforce_ips', 0 ) || $this->plugin->ban->is_ip_whitelisted( $this->get_ip() ) ) {
			return false;
		}
		// A ban recorded before an upgrade is stored under the full address until it expires.
		foreach ( array_unique( [ $this->login_limit_key( $this->get_ip() ), $this->get_ip() ] ) as $key ) {
			$state = get_transient( 'patchstack_login_' . md5( $key ) );
			if ( is_array( $state ) && isset( $state['blocked_until'] ) && $state['blocked_until'] > time() ) {
				return true;
			}
		}
		global $wpdb;
		$previous = $wpdb->suppress_errors( true );
		try {
			$sql = $this->login_bans_query( $this->get_ip() );
			return (bool) $wpdb->get_var( $sql );
		} finally {
			$wpdb->suppress_errors( $previous );
		}
	}

	public function authenticate_ipban( $user, $username = '', $password = '' ) {
		return $this->login_ip_is_blocked() ? $this->login_blocked_error() : $user;
	}

	public function expire_login_records() {
		global $wpdb;
		$table = $wpdb->prefix . 'patchstack_event_log';
		$previous = $wpdb->suppress_errors( true );
		try {
			$wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE action IN ('login attempt', 'login ban') AND CAST(object_id AS UNSIGNED) <= %d", time() ) );
		} finally {
			$wpdb->suppress_errors( $previous );
		}
	}

	public function record_failed_login( $username, $error = null ) {
		if ( ! $this->get_option( 'patchstack_block_bruteforce_ips', 0 ) || $this->plugin->ban->is_ip_whitelisted( $this->get_ip() ) ) {
			return;
		}
		// WordPress versions before 5.4 omit the error from wp_login_failed.
		if ( ( is_wp_error( $error ) && $error->get_error_code() === 'patchstack_login_blocked' ) || ( $error === null && $this->login_ip_is_blocked() ) ) {
			return;
		}

		$now = time();
		$minutes = (int) $this->get_option( 'patchstack_anti_bruteforce_minutes', 30 );
		$blocktime = (int) $this->get_option( 'patchstack_anti_bruteforce_blocktime', 60 );
		$window = ( $minutes > 0 ? $minutes : 30 ) * MINUTE_IN_SECONDS;
		$block = ( $blocktime > 0 ? $blocktime : 60 ) * MINUTE_IN_SECONDS;
		$threshold = max( 1, (int) $this->get_option( 'patchstack_anti_bruteforce_attempts', 10 ) );
		$ip = $this->get_ip();
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return;
		}
		$ip = $this->login_limit_key( $ip );

		global $wpdb;
		$table = $wpdb->prefix . 'patchstack_event_log';
		$previous = $wpdb->suppress_errors( true );
		try {
			if ( $wpdb->insert( $table, [ 'ip' => $ip, 'action' => 'login attempt', 'date' => current_time( 'mysql' ), 'object_id' => $now + $window ] ) ) {
				$id = $wpdb->insert_id;
				$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE ip = %s AND action = 'login attempt' AND CAST(object_id AS UNSIGNED) > %d", $ip, $now ) );
				if ( $count !== null ) {
					if ( (int) $count < $threshold ) {
						return;
					}
					if ( $wpdb->update( $table, [ 'action' => 'login ban', 'object_id' => $now + $block ], [ 'id' => $id ] ) === 1 ) {
						return;
					}
				}
			}
		} finally {
			$wpdb->suppress_errors( $previous );
		}

		// Keep enforcing a short-lived limit while the site's log table is unavailable.
		$key = 'patchstack_login_' . md5( $ip );
		$lock_name = $key . '_lock';
		$lock = $this->acquire_lock( $lock_name, 30 );
		if ( ! $lock ) {
			return;
		}
		try {
			if ( wp_using_ext_object_cache() || wp_installing() ) {
				// Cached transients are authoritative; refresh local reads without deleting the counter.
				wp_cache_get( $key, 'transient', true );
			} else {
				wp_cache_delete( '_transient_' . $key, 'options' );
				wp_cache_delete( '_transient_timeout_' . $key, 'options' );
			}
			$state = get_transient( $key );
			if ( is_array( $state ) && isset( $state['blocked_until'] ) && $state['blocked_until'] > $now ) {
				return;
			}
			if ( ! is_array( $state ) || ! isset( $state['started'], $state['failures'] ) || $now - $state['started'] >= $window ) {
				$state = [ 'started' => $now, 'failures' => 0 ];
			}
			$state['failures']++;
			if ( $state['failures'] >= $threshold ) {
				$state['blocked_until'] = $now + $block;
			}
			set_transient( $key, $state, $window + $block );
		} finally {
			$this->release_lock( $lock_name, $lock );
		}
	}

	/**
	 * Check if the IP address is banned from attempting to guess passwords.
	 *
	 * @return void
	 */
	public function check_ipban() {
		if ( ! is_user_logged_in() && $this->login_ip_is_blocked() ) {
			$this->plugin->firewall_base->display_error_page( 24 );
		}
	}

	/**
	 * Register the CAPTCHA hooks the first time a form or a credential check needs them.
	 *
	 * @param mixed $value The value of the filter this runs on, passed through.
	 * @return mixed
	 */
	public function load_captcha( $value = null ) {
		if ( ! $this->captcha_loaded ) {
			$this->captcha_loaded = true;
			$this->add_captcha();
		}
		return $value;
	}

	/**
	 * Determine if we should inject reCAPTCHA into certain pages.
	 *
	 * @return void
	 */
	public function add_captcha() {
		switch ( $this->get_option( 'patchstack_captcha_type' ) ) {
			case 'v2':
				$public  = $this->get_option( 'patchstack_captcha_public_key', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key', '' );
				break;
			case 'invisible':
				$public  = $this->get_option( 'patchstack_captcha_public_key_v3', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key_v3', '' );
				break;
			case 'v3':
				$public  = $this->get_option( 'patchstack_captcha_public_key_v3_new', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key_v3_new', '' );
				break;
			case 'turnstile':
				$public  = $this->get_option( 'patchstack_captcha_public_key_turnstile', '' );
				$private = $this->get_option( 'patchstack_captcha_private_key_turnstile', '' );
				break;
			default:
				return;
			break;
		}

		// Make sure that the keys are set.
		if ( $public == '' || $private == '' ) {
			return;
		}

		// reCAPTCHA on the login page.
		if ( $this->get_option( 'patchstack_captcha_login_form' ) ) {
			add_filter( 'login_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_filter( 'woocommerce_login_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_filter( 'wp_authenticate_user', [ $this, 'login_captcha_check' ], 10, 2 );
			add_filter( 'woocommerce_process_login_errors', [ $this, 'login_captcha_check_woocommerce' ], 10, 1 );
		}

		// reCAPTCHA on the registration form.
		if ( $this->get_option( 'patchstack_captcha_registration_form' ) ) {
			add_action( 'register_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_action( 'woocommerce_register_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_action( 'registration_errors', [ $this, 'registration_captcha_check' ] );
			add_filter( 'woocommerce_process_registration_errors', [$this, 'general_captcha_check' ], 10, 1 );
			add_action( 'signup_extra_fields', [ $this, 'signup_captcha_display' ] );
			add_action( 'signup_blogform', [ $this, 'signup_captcha_display' ] );
			add_filter( 'wpmu_validate_user_signup', [ $this, 'signup_captcha_check' ] );
			add_filter( 'wpmu_validate_blog_signup', [ $this, 'signup_captcha_check' ] );
		}

		// reCAPTCHA on the reset password form.
		if ( $this->get_option( 'patchstack_captcha_reset_pwd_form' ) ) {
			add_action( 'lostpassword_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_action( 'woocommerce_lostpassword_form', [ $this->plugin->hardening, 'captcha_display' ] );
			add_action( 'lostpassword_post', [ $this, 'reset_captcha_check' ], 1, 1 );
		}
	}

	public function signup_captcha_display( $errors ) {
		if ( is_wp_error( $errors ) && $errors->get_error_message( 'patchstack_error' ) ) {
			echo '<p class="error">' . wp_kses_post( $errors->get_error_message( 'patchstack_error' ) ) . '</p>';
		}
		$this->plugin->hardening->captcha_display();
	}

	public function signup_captcha_check( $result ) {
		// WordPress also uses these validators outside the public signup page, without a challenge.
		if ( did_action( 'before_signup_form' ) && isset( $result['errors'] ) && is_wp_error( $result['errors'] ) ) {
			$result['errors'] = $this->general_captcha_check( $result['errors'] );
		}
		return $result;
	}

	/**
	 * Check the CAPTCHA of a submitted lost password form, on WordPress and WooCommerce.
	 * A reset sent by a logged-in user, such as an administrator from the users screen, has no form.
	 *
	 * @param mixed|WP_Error $errors
	 * @return void
	 */
	public function reset_captcha_check( $errors ) {
		if ( is_wp_error( $errors ) && ! is_user_logged_in() && $this->is_captcha_form( 'wc_reset_password' ) ) {
			$this->general_captcha_check( $errors );
		}
	}

	/**
	 * Check the CAPTCHA of the WordPress registration form. WooCommerce validates its own form
	 * through its own filter.
	 *
	 * @param mixed|WP_Error $errors
	 * @return mixed|WP_Error
	 */
	public function registration_captcha_check( $errors ) {
		return $this->is_captcha_form() ? $this->general_captcha_check( $errors ) : $errors;
	}

	/**
	 * The CAPTCHA covers the forms of WordPress itself (wp-login.php) and of WooCommerce, which
	 * show the widget. A login, registration or reset that reaches the same WordPress functions
	 * from elsewhere, such as XML-RPC or the form of another plugin, has no widget to answer
	 * and is not checked, so those keep working.
	 *
	 * @param string $woocommerce_field The field WooCommerce requires before it handles the form.
	 * @return boolean
	 */
	private function is_captcha_form( $woocommerce_field = '' ) {
		return did_action( 'login_init' ) > 0
			|| ( $woocommerce_field !== '' && isset( $_POST[ $woocommerce_field ] ) && function_exists( 'WC' ) );
	}

	/**
	 * Check reCAPTCHA upon login.
	 *
	 * @param string $user
	 * @param string $password
	 * @return WP_User|WP_Error
	 */
	public function login_captcha_check( $user, $password ) {
		// Only the WordPress and WooCommerce login forms show a CAPTCHA to answer.
		// WooCommerce validates its own login form through its own filter.
		if ( $this->validated || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ! $this->is_captcha_form() ) {
			return $user;
		}

		$result = $this->plugin->hardening->captcha_check();

		if ( ! $result['response'] ) {
			if ( $result['reason'] === 'ERROR_NO_KEYS' ) {
				$this->validated = true;
				return $user;
			}
			$error_message = sprintf( '<strong>%s</strong>: %s', 'Error', esc_attr__( 'You have entered an incorrect reCAPTCHA value.', 'patchstack' ) );

			if ( $result['reason'] === 'VERIFICATION_FAILED' || $result['reason'] === 'RECAPTCHA_EMPTY_RESPONSE' ) {
				wp_clear_auth_cookie();
				return new WP_Error( 'patchstack_error', $error_message );
			}

			if ( isset( $_REQUEST['log'], $_REQUEST['pwd'] ) ) {
				return new WP_Error( 'patchstack_error', $error_message );
			}
		} else {
			$this->validated = true;
			return $user;
		}
	}

	/**
	 * Check reCAPTCHA upon login.
	 *
	 * @param string $user
	 * @param string $password
	 * @return WP_User|WP_Error
	 */
	public function login_captcha_check_woocommerce( $error, $username = '', $password = '', $email = '' ) {
		if ( $this->validated ) {
			return $error;
		}

		$result = $this->plugin->hardening->captcha_check();

		if ( $result['response'] || $result['reason'] == 'ERROR_NO_KEYS' ) {
			$this->validated = true;
			return $error;
		}

		if ( ! is_wp_error( $error ) ) {
			$error = new WP_Error();
		}

		$error->add( 'patchstack_error', 'ERROR' . ':&nbsp;' . esc_attr__( 'You have entered an incorrect reCAPTCHA value.', 'patchstack' ) );
		return $error;
	}

	/**
	 * Captcha check for the register or lost password form.
	 *
	 * @param mixed|WP_Error $error
	 * @return WP_Error
	 */
	public function general_captcha_check( $error ) {
		if ( $this->validated ) {
			return $error;
		}

		$result = $this->plugin->hardening->captcha_check();

		if ( $result['response'] || $result['reason'] == 'ERROR_NO_KEYS' ) {
			$this->validated = true;
			return $error;
		}

		if ( ! is_wp_error( $error ) ) {
			$error = new WP_Error();
		}

		$error->add( 'patchstack_error', 'ERROR' . ':&nbsp;' . esc_attr__( 'You have entered an incorrect reCAPTCHA value.', 'patchstack' ) );
		return $error;
	}
}
