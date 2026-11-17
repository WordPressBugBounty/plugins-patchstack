<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The core class is used as a base class for all the other classes.
 * This will allow us to declare certain global methods/variables.
 */
class P_Core {

	/**
	 * This will allow us to communicate between classes.
	 *
	 * @var Patchstack
	 */
	public $plugin;

	/**
	 * Whether or not the site is a multisite.
	 *
	 * @var boolean
	 */
	public $is_multi_site = false;

	/**
	 * Allowed HTML for the wp_kses function used to render certain paragraphs of texts.
	 * 
	 * @var array
	 */
	public $allowed_html = [
		'a'        => [
			'href'     => [],
			'title'    => [],
			'target'    => []
		],
		'p'        => [
			'style'    => []
		],
		'span'     => [
			'style'    => []
		],
		'br'       => [],
		'strong'   => [],
		'b'        => [],
		'i'		   => [
			'style'    => []
		],
		'label'	   => [
			'for'      => [],
			'style'    => []
		],
		'input'    => [
			'type' 	   => [],
			'class'	   => [],
			'name'	   => [],
			'id'  	   => [],
			'value'    => [],
			'checked'  => [],
			'style'    => []
		],
		'textarea' => [
			'rows'     => [],
			'id'       => [],
			'name'     => []
		],
		'select'   => [
			'name'     => [],
			'id'       => [],
			'data-selected' => []
		],
		'option'   => [
			'value'    => [],
			'selected' => []
		],
		'table'    => [
			'class'    => [],
			'style'    => []
		],
		'thead'    => [],
		'th'       => [
			'style'    => []
		],
		'tr' 	   => [],
		'td' 	   => [],
		'div' 	   => [
			'class'    => [],
			'style'    => []
		]
	];

	/**
	 * @param Patchstack $plugin
	 * @return void
	 */
	public function __construct( $plugin ) {
		$this->plugin        = $plugin;
		$this->is_multi_site = is_multisite();
	}

	/**
	 * In case of multisite we want to determine if there's a difference between the
	 * network setting and site setting and if so, use the site setting.
	 *
	 * @param string $name
	 * @param mixed  $default
	 * @return mixed
	 */
	public function get_option( $name, $default = false ) {
		// We always want to return the site option on the default settings management page.
		if ( isset( $_GET['page'] ) && $_GET['page'] == 'patchstack-multisite-settings' && function_exists( 'wp_get_current_user' ) && is_super_admin() ) {
			return get_site_option( $name, $default );
		}

		// Get the setting of the current site.
		$secondary = get_option( $name, $default );

		// On single-site installs there is no network option to reconcile, so
		// avoid the extra get_site_option() lookup on every read.
		if ( ! is_multisite() ) {
			return $secondary;
		}

		// Get the setting of the network and in case there's a difference,
		// return the value of site.
		$main = get_site_option( $name, $default );
		return $main != $secondary ? $secondary : $main;
	}

	/**
	 * In case we need to retrieve the option of a specific site, we can use this.
	 * It will determine if it's on a multisite environment and if so, use get_blog_option.
	 *
	 * @param int    $site_id
	 * @param string $name
	 * @param mixed  $default
	 * @return mixed
	 */
	public function get_blog_option( $site_id, $name, $default = false ) {
		if ( $this->is_multi_site ) {
			return get_blog_option( $site_id, $name, $default );
		}

		return get_option( $name, $default );
	}

	/**
	 * In case we need to update the option of a specific site, we can use this.
	 * It will determine if it's on a multisite environment and if so, use update_blog_option.
	 *
	 * @param int    $site_id
	 * @param string $name
	 * @param mixed  $value
	 * @return mixed
	 */
	public function update_blog_option( $site_id, $name, $value ) {
		if ( $this->is_multi_site ) {
			return update_blog_option( $site_id, $name, $value );
		}

		return update_option( $name, $value );
	}

	/**
	 * Determine if the license is active and not expired.
	 *
	 * @return boolean
	 */
	public function license_is_active() {
		if ( get_option( 'patchstack_license_activated', 0 ) ) {
			return true;
		}

		$expiry = get_option( 'patchstack_license_expiry', '' );
		if ( $expiry != '' && ( strtotime( $expiry ) > ( time() - ( 3600 * 24 ) ) ) ) {
			return true;
		}

		return false;
	}

	protected function ban_window_minutes( $minutes_option, $timeout_option ) {
		$minutes = (int) $this->get_option( $minutes_option, 30 );
		$timeout = (int) $this->get_option( $timeout_option, 60 );
		return $minutes > 0 && $timeout > 0 ? $minutes + $timeout : 90;
	}

	// The dashboard and the authentication filter must agree on active bans, including pre-upgrade failures.
	protected function login_bans_query( $ip = null ) {
		global $wpdb;
		$time = $this->ban_window_minutes( 'patchstack_anti_bruteforce_minutes', 'patchstack_anti_bruteforce_blocktime' );
		$table = $wpdb->prefix . 'patchstack_event_log';
		$sql = "SELECT MAX(id) AS id, ip, MAX(date) AS date FROM $table WHERE ";
		$args = [];
		if ( $ip !== null ) {
			// Failures recorded before an upgrade carry the full address.
			$ips = array_values( array_unique( [ $ip, $this->login_limit_key( $ip ) ] ) );
			$sql .= 'ip IN (' . implode( ', ', array_fill( 0, count( $ips ), '%s' ) ) . ') AND ';
			$args = $ips;
		}
		$sql .= "((action = 'failed login' AND (flag IS NULL OR flag <> 'patchstack:login-audit') AND date >= (%s - INTERVAL %d MINUTE))
			OR (action = 'login ban' AND CAST(object_id AS UNSIGNED) > %d))
			GROUP BY ip HAVING MAX(action = 'login ban') = 1 OR COUNT(*) >= %d ORDER BY date DESC";
		return $wpdb->prepare( $sql, array_merge( $args, [ current_time( 'mysql' ), $time, time(), max( 1, (int) $this->get_option( 'patchstack_anti_bruteforce_attempts', 10 ) ) ] ) );
	}

	// An IPv6 subscriber controls a whole /64 and can use a fresh address for every attempt,
	// so login limits count that network as one client. IPv4, also when mapped into IPv6, stays per address.
	protected function login_limit_key( $ip ) {
		$packed = is_string( $ip ) && filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ? @inet_pton( $ip ) : false;
		if ( $packed === false || strlen( $packed ) !== 16 ) {
			return $ip;
		}
		if ( substr( $packed, 0, 12 ) === "\0\0\0\0\0\0\0\0\0\0\xff\xff" ) {
			return inet_ntop( substr( $packed, 12 ) );
		}
		return inet_ntop( substr( $packed, 0, 8 ) . "\0\0\0\0\0\0\0\0" );
	}

	protected function get_2fa_option( $user_id, $name ) {
		// The enabled row commits the namespace only after both secret fields are saved.
		if ( metadata_exists( 'user', $user_id, 'patchstack_2fa_enabled' ) ) {
			return get_user_meta( $user_id, 'patchstack_2fa_' . $name, true );
		}
		return get_user_option( 'webarx_2fa_' . $name, $user_id );
	}

	protected function reset_user_2fa( $user_id ) {
		$lock_name = 'patchstack_2fa_lock_' . (int) $user_id;
		$lock = $this->acquire_lock( $lock_name, 30, true );
		if ( ! $lock ) {
			return false;
		}
		try {
			wp_cache_delete( $user_id, 'user_meta' );
			// Persist the retirement intent before disabling or deleting either namespace.
			update_user_meta( $user_id, '_patchstack_2fa_reset_pending', 1 );
			if ( ! get_user_meta( $user_id, '_patchstack_2fa_reset_pending', true ) ) {
				return false;
			}
			update_user_meta( $user_id, 'patchstack_2fa_enabled', 0 );
			if ( ! metadata_exists( 'user', $user_id, 'patchstack_2fa_enabled' ) || $this->get_2fa_option( $user_id, 'enabled' ) ) {
				return false;
			}
			return $this->retire_2fa_secret( $user_id );
		} finally {
			$this->release_lock( $lock_name, $lock, true );
		}
	}

	protected function retire_2fa_secret( $user_id ) {
		$keys = [ 'webarx_2fa_enabled', 'webarx_2fa_secretkey', 'webarx_2fa_secretkey_nonce', 'patchstack_2fa_secretkey', 'patchstack_2fa_secretkey_nonce', '_patchstack_2fa_state' ];
		foreach ( $keys as $key ) {
			delete_user_meta( $user_id, $key );
		}
		foreach ( $keys as $key ) {
			if ( metadata_exists( 'user', $user_id, $key ) ) {
				return false;
			}
		}
		delete_user_meta( $user_id, '_patchstack_2fa_reset_pending' );
		return ! get_user_meta( $user_id, '_patchstack_2fa_reset_pending', true );
	}

	// WordPress option helpers cannot atomically take over a stale lease or release only its owner.
	protected function acquire_lock( $name, $seconds = 300, $global = false ) {
		global $wpdb;
		$table = $global ? $wpdb->base_prefix . 'options' : $wpdb->options;
		$table = '`' . str_replace( '`', '``', $table ) . '`';
		$token = ( time() + $seconds ) . ':' . wp_generate_uuid4();
		$inserted = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO $table (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, $token ) );
		if ( $inserted !== 1 ) {
			if ( $inserted === false ) {
				return false;
			}
			// Releases before 2.3.7 stored an idle processing flag as an empty string, which get_var() reports as null.
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT option_value FROM $table WHERE option_name = %s", $name ) );
			if ( ! $row || (int) $row->option_value > time() ) {
				return false;
			}
			$previous = $row->option_value;
			if ( $wpdb->query( $wpdb->prepare( "UPDATE $table SET option_value = %s, autoload = 'no' WHERE option_name = %s AND option_value = %s", $token, $name, $previous ) ) !== 1 ) {
				return false;
			}
			// Boolean processing flags may still be present in WordPress's autoload cache.
			if ( ! $global && in_array( $previous, [ '', '0', '1' ], true ) ) {
				wp_cache_delete( 'alloptions', 'options' );
			}
		}
		if ( ! $global ) {
			wp_cache_delete( $name, 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
		return $token;
	}

	protected function release_lock( $name, $token, $global = false ) {
		global $wpdb;
		$table = $global ? $wpdb->base_prefix . 'options' : $wpdb->options;
		$table = '`' . str_replace( '`', '``', $table ) . '`';
		// An expired owner must never release its successor's lease.
		$wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE option_name = %s AND option_value = %s", $name, $token ) );
		if ( ! $global ) {
			wp_cache_delete( $name, 'options' );
		}
	}

	/**
	 * Load the log redactor without risking a fatal error when an incomplete update left
	 * the autoloader or the class file missing.
	 *
	 * @return bool
	 */
	public function log_redactor_available() {
		$autoload = __DIR__ . '/../lib/patchstack/vendor/autoload.php';
		if ( ! file_exists( $autoload ) ) {
			return false;
		}

		require_once $autoload;
		return class_exists( 'Patchstack\LogRedactor', true );
	}

	/**
	 * Determine if the plugin is connected to the API.
	 * 
	 * @return boolean
	 */
	public function is_connected() {
		// Determine if the API client id is set.
		if ( $this->plugin->client_id == 'PATCHSTACK_CLIENT_ID' && ! get_option( 'patchstack_clientid' ) ) {
			return false;
		}

		// Determine if we have an API token.
		if ( get_option( 'patchstack_api_token', '' ) == '' ) {
			return false;
		}

		// Determine if we have a last license check set.
		$last_license_check = get_option( 'patchstack_last_license_check', 0 );
		if ( !empty( $last_license_check ) && time() - $last_license_check >= 604800 ) {
			return false;
		}

		return true;
	}

	/**
	 * Determine if the plugin provides protection.
	 * 
	 * @return boolean
	 */
	public function is_protected() {
		return (int) get_option( 'patchstack_license_free', 0 ) == 0;
	}

	/**
	 * Format a UNIX timestamp as a short relative-time string for the connection card.
	 * Returns "Never" for empty/zero, otherwise "Just now" / "Xm ago" / "Xh ago" / "Xd ago".
	 *
	 * The returned string is the raw translated value — escape it at the call site.
	 *
	 * @param int $timestamp UNIX timestamp.
	 * @return string Translated relative-time label (not escaped).
	 */
	public function format_relative_time( $timestamp ) {
		$timestamp = (int) $timestamp;
		if ( $timestamp <= 0 ) {
			return __( 'Never', 'patchstack' );
		}

		$diff = time() - $timestamp;
		if ( $diff < 60 ) {
			return __( 'Just now', 'patchstack' );
		}
		if ( $diff < 3600 ) {
			/* translators: %d: number of minutes since the last sync. */
			return sprintf( __( '%dm ago', 'patchstack' ), (int) floor( $diff / 60 ) );
		}
		if ( $diff < 86400 ) {
			/* translators: %d: number of hours since the last sync. */
			return sprintf( __( '%dh ago', 'patchstack' ), (int) floor( $diff / 3600 ) );
		}
		/* translators: %d: number of days since the last sync. */
		return sprintf( __( '%dd ago', 'patchstack' ), (int) floor( $diff / 86400 ) );
	}

	/**
	 * Get the timestamp of the last successful API sync.
	 *
	 * Prefers patchstack_last_sync, which is stamped on every successful (200 OK)
	 * API request (log/software uploads, rule pulls, license verify, ping, etc.),
	 * so it reflects real sync activity rather than only license verification.
	 * Falls back to patchstack_last_license_check for sites that have not synced
	 * yet since this option was introduced.
	 *
	 * @return int UNIX timestamp, or 0 if never synced.
	 */
	public function get_last_sync_time() {
		$last_sync = (int) get_option( 'patchstack_last_sync', 0 );
		if ( $last_sync > 0 ) {
			return $last_sync;
		}

		return (int) get_option( 'patchstack_last_license_check', 0 );
	}

	/**
	 * Grab the IP address of the user. Give the override IP header priority.
	 * If this does not exist, we should always default to REMOTE_ADDR.
	 *
	 * @return string
	 */
	/**
	 * Make a request value fit a text column of the log tables. WordPress refuses the whole
	 * row when a value is longer than its column or is not valid text for the table, and a
	 * blocked request must still be recorded.
	 *
	 * @param mixed $value
	 * @param integer $bytes
	 * @return string
	 */
	public function log_field( $value, $bytes = 255 ) {
		$value = is_scalar( $value ) ? (string) $value : '';
		if ( $value === '' ) {
			return '';
		}

		// Invalid UTF-8 and characters outside the basic plane (which a utf8 table cannot hold) become "?".
		if ( @preg_match( '//u', $value ) !== 1 ) {
			$value = function_exists( 'mb_convert_encoding' ) ? mb_convert_encoding( $value, 'UTF-8', 'UTF-8' ) : preg_replace( '/[^\x20-\x7e]/', '?', $value );
		}
		$clean = @preg_replace( '/[\x{10000}-\x{10FFFF}]/u', '?', $value );
		$value = is_string( $clean ) ? $clean : preg_replace( '/[^\x20-\x7e]/', '?', $value );

		if ( strlen( $value ) > $bytes ) {
			$value = function_exists( 'mb_strcut' ) ? mb_strcut( $value, 0, $bytes, 'UTF-8' ) : substr( preg_replace( '/[^\x20-\x7e]/', '?', $value ), 0, $bytes );
		}
		return $value;
	}

	public function get_ip() {
		$override = get_option( 'patchstack_firewall_ip_header', '' );
		if ( $override != '' && isset( $_SERVER[ $override ] ) ) {
			return $_SERVER[ $override ];
		}

		return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
	}

	/**
	 * Grab the secret key used for API communication.
	 * 
	 * @param string $custom
	 * @return string
	 */
	public function get_secret_key( $custom = '' ) {
		if ( $custom != '' ) {
			return $this->encrypt( $custom );
		}

		$secret = get_option( 'patchstack_secretkey', '' );
		if ( ! $secret ) {
			return '';
		}

		if ( strlen( $secret ) === 40 ) {
			$enc = $this->encrypt( $secret );

			update_option( 'patchstack_secretkey', $enc['cipher'] );
			update_option( 'patchstack_secretkey_nonce', $enc['nonce'] );

			return $secret;
		}

		$nonce = get_option( 'patchstack_secretkey_nonce' );
		return $this->decrypt( $secret, $nonce );
	}

	/**
	 * Set the secret key used for API communication.
	 * 
	 * @param string $secret
	 * @return void
	 */
	public function set_secret_key( $secret ) {
		$enc = $this->encrypt( $secret );

		update_option( 'patchstack_secretkey', $enc['cipher'] );
		update_option( 'patchstack_secretkey_nonce', $enc['nonce'] );
	}

	/**
	 * Determine which encryption dependency we can use.
	 * 
	 * @return string
	 */
	public function get_enc_type() {
		if ( function_exists('sodium_crypto_generichash') ) {
			return 'native';
		}

		return 'compat';
	}

	/**
	 * Get the unique nonce that is used for the secretbox.
	 * 
	 * @return string
	 */
	public function get_enc_nonce() {
		if ( function_exists('random_bytes') ) {
			return random_bytes( 24 );
		}

		require_once dirname( __FILE__ ) . '/2fa/polyfill/lib/random.php';
		return random_bytes( 24 );
	}

	/**
	 * Encrypt a string.
	 * 
	 * @param string $message
	 * @return array
	 */
	public function encrypt( $message ) {
		if ( is_null( $message ) || ! defined( 'AUTH_KEY' ) ) {
			return [
				'cipher' => $message,
				'nonce' => ''
			];
		}

		$enc_type = $this->get_enc_type();
		$nonce = $this->get_enc_nonce();

		try {
			// Use the PHP native encryption functions.
			if ( $enc_type == 'native' ) {
				$key = sodium_crypto_generichash( AUTH_KEY );

				return [
					'cipher' => sodium_bin2hex( sodium_crypto_secretbox( $message, $nonce, $key ) ),
					'nonce' => sodium_bin2hex( $nonce )
				];
			}

			// Use the Sodium polyfill library part of WordPress core.
			if ( ! file_exists( ABSPATH . WPINC . '/sodium_compat/autoload.php' ) ) {
				return [
					'cipher' => $message,
					'nonce' => ''
				];
			}
			require_once ABSPATH . WPINC . '/sodium_compat/autoload.php';
			$key = \Sodium\crypto_generichash( AUTH_KEY );

			return [
				'cipher' => \Sodium\bin2hex( \Sodium\crypto_secretbox( $message, $nonce, $key ) ),
				'nonce' => \Sodium\bin2hex( $nonce )
			];
		} catch ( Exception $e ) {
			return [
				'cipher' => $message,
				'nonce' => ''
			];
		}
	}

	/**
	 * Decrypt a cipher to plain-text.
	 * 
	 * @param string $cipher
	 * @param string $nonce
	 * @return string
	 */
	public function decrypt( $cipher, $nonce ) {
		$enc_type = $this->get_enc_type();

		// If we received an empty nonce, we assume it was never properly encrypted to begin with.
		if ( $nonce == '' || ! defined( 'AUTH_KEY' ) ) {
			return $cipher;
		}

		try {
			// Determine if we should use native or polyfill functions.
			if ( $enc_type == 'native' ) {
				$key = sodium_crypto_generichash( AUTH_KEY );
				$dec = sodium_crypto_secretbox_open( sodium_hex2bin( $cipher ), sodium_hex2bin( $nonce ), $key );
			} else {
				if ( ! file_exists( ABSPATH . WPINC . '/sodium_compat/autoload.php' ) ) {
					return $cipher;
				}
				require_once ABSPATH . WPINC . '/sodium_compat/autoload.php';
				$key = \Sodium\crypto_generichash( AUTH_KEY );
				$dec = \Sodium\crypto_secretbox_open( sodium_hex2bin( $cipher ), sodium_hex2bin( $nonce ), $key );
			}
		} catch ( Exception $e ) {
			return $cipher;
		}

		// In case decryption failed, return null.
		if ( ! $dec ) {
			return null;
		}

		return $dec;
	}
}
