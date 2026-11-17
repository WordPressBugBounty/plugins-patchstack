<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to provide several hardening options.
 */
class P_Hardening extends P_Core {

	/**
	 * Whether libcurl has to be kept from decoding response bodies, once determined.
	 *
	 * @var boolean|null
	 */
	private $curl_decoding_exposed = null;

	/**
	 * Whether the request libcurl is sending has a response size limit and asked for no compression.
	 *
	 * @var boolean
	 */
	private $curl_response_limited = false;

	/**
	 * Add the actions required for the hardening of the site.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		// Auto update plugins.
		add_action( 'patchstack_update_plugins', [ $this, 'update_vulnerable_plugins' ] );

		// The hardening features can only be used on an activated license.
		if ( ! $this->license_is_active() || $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		// Disallowed modification of the theme files?
		if ( ! defined( 'DISALLOW_FILE_EDIT' ) && $this->get_option( 'patchstack_pluginedit', true ) ) {
			define( 'DISALLOW_FILE_EDIT', 1 );
		}

		// Set security headers
		add_filter( 'wp_headers', [ $this, 'set_security_headers' ], 10, 1 );

		// Apply comment captcha?
		if ( $this->get_option( 'patchstack_captcha_on_comments', 0 ) && ! is_user_logged_in() ) {
			add_action( 'comment_form_after_fields', [ $this, 'captcha_display' ] );
			add_filter( 'preprocess_comment', [ $this, 'verify_recaptcha' ] );
		}

		// Disable the application passwords feature?
		if ( $this->get_option( 'patchstack_application_passwords_disabled', false ) == true ) {
			add_filter( 'wp_is_application_passwords_available', '__return_false' );
		}

		// Turn XML-RPC off? The xmlrpc_enabled filter only covers the methods that log in,
		// so pingbacks and the other anonymous methods have to be unregistered as well.
		if ( $this->get_option( 'patchstack_xmlrpc_is_disabled', false ) == true ) {
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'xmlrpc_methods', [ $this, 'remove_xmlrpc_methods' ], PHP_INT_MAX );
			add_filter( 'wp_headers', [ $this, 'remove_pingback_header' ], PHP_INT_MAX );
			add_action( 'wp', [ $this, 'remove_pingback_header' ], PHP_INT_MAX, 0 );
			remove_action( 'wp_head', 'rsd_link' );
		}

		// Keep libcurl from unpacking response bodies while its Brotli decoder is exposed.
		// This changes every outbound request, so it only applies once the site opts in.
		add_action( 'http_api_curl', [ $this, 'disable_curl_decoding' ], PHP_INT_MAX, 2 );
		add_action( 'requests-curl.after_request', [ $this, 'refuse_unrequested_encoding' ], 10, 1 );

		// Block unauthorized wp-json requests?
		if ( $this->get_option( 'patchstack_json_is_disabled', false ) ) {
			add_filter( 'rest_pre_dispatch', [ $this, 'disable_wpjson' ], 10, 3 );
		}

		// Prevent user enumeration?
		if ( $this->get_option( 'patchstack_userenum' ) ) {
			add_action( 'init', [ $this, 'stop_user_enum' ], 1 );
			add_action( 'parse_request', [ $this, 'stop_user_enum_query' ] );
			add_filter( 'wp_sitemaps_add_provider', [ $this, 'remove_users_sitemap' ], 10, 2 );
			add_filter( 'rest_pre_dispatch', [ $this, 'restrict_rest_users' ], 10, 3 );
		}

		// Attempt to hide the WordPress version?
		if ( $this->get_option( 'patchstack_hidewpversion' ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', [ $this, 'remove_generator' ] );
		}

		// Auto update software?
		$update = get_site_option( 'patchstack_auto_update', [] );
		if ( is_array( $update ) ) {
			foreach ( $update as $type ) {
				if ( $type != 'vulnerable' ) {
					add_filter( 'auto_update_' . $type, '__return_true' );
				}
			}
		}
	}

	/**
	 * Perform updates if the software upload call returns vulnerabilities.
	 * This is only executed when auto updates are enabled for vulnerable plugins.
	 *
	 * @param array $plugins
	 * @return void
	 */
	public function update_vulnerable_plugins() {
		// Is the auto update setting for vulnerable plugins enabled?
		$update = get_site_option( 'patchstack_auto_update', [] );
		if ( ! is_array( $update ) || ! in_array( 'vulnerable', $update, true ) || ! wp_is_file_mod_allowed( 'automatic_updater' ) ) {
			return;
		}

		// Do we even have any vulnerable plugins to auto update?
		$plugins = get_site_option( 'patchstack_vulnerable_plugins', [] );
		if ( ! is_array( $plugins ) || count( $plugins ) == 0 ) {
			return;
		}

		// Might not be necessary, but should prevent any hanging issues.
		@set_time_limit( 180 );

		// Require some files we need to execute the upgrade.
		@include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		if ( file_exists( ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php' ) ) {
			@include_once ABSPATH . 'wp-admin/includes/class-plugin-upgrader.php';
		}

		@include_once ABSPATH . 'wp-admin/includes/plugin.php';
		@include_once ABSPATH . 'wp-admin/includes/misc.php';
		@include_once ABSPATH . 'wp-admin/includes/file.php';
		if ( ( new WP_Automatic_Updater() )->is_disabled() ) {
			return;
		}

		@wp_update_plugins();
		$all_plugins = get_plugins();

		// New array with all available plugins and the ones we want to upgrade.
		$upgrade = [];
		foreach ( $all_plugins as $path => $data ) {
			if ( in_array( $path, $plugins ) ) {
				array_push( $upgrade, $path );
			}
		}

		// Upgrade the plugins.
		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$results = $upgrader->bulk_upgrade( $upgrade );

		$completed = [];
		foreach ( $plugins as $path ) {
			if ( is_string( $path ) && ( ! isset( $all_plugins[$path] ) || ( is_array( $results ) && ! empty( $results[$path] ) && ! is_wp_error( $results[$path] ) ) ) ) {
				$completed[] = $path;
			}
		}
		// Retain failed updates and work queued by callbacks during the attempt.
		$pending = get_site_option( 'patchstack_vulnerable_plugins', [] );
		if ( is_array( $pending ) ) {
			$pending = array_values( array_filter( $pending, function ( $path ) use ( $completed ) {
				return ! in_array( $path, $completed, true );
			} ) );
			update_site_option( 'patchstack_vulnerable_plugins', $pending );
		}

		// Resend the sofware data to the API.
		do_action( 'patchstack_send_software_data' );
	}

	/**
	 * Prevent unauthorized users from accessing wp-json.
	 *
	 * @return void|WP_Error
	 */
	public function disable_wpjson( $result, $server, $request ) {
		if ( ! defined( 'REST_REQUEST' ) || ! REST_REQUEST || is_wp_error( $result ) || is_user_logged_in()
			|| stripos( $request->get_route(), '/contact-form-7/' ) === 0 ) {
			return $result;
		}
		$msg = apply_filters( 'disable_wp_rest_api_error', esc_attr__( 'The WP REST API cannot be accessed by unauthorized users.', 'disable-wp-rest-api' ) );
		return new WP_Error( 'rest_authorization_required', $msg, [ 'status' => rest_authorization_required_code() ] );
	}

	public function restrict_rest_users( $result, $server, $request ) {
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST && ! is_wp_error( $result ) && ! is_user_logged_in()
			&& preg_match( '~^/wp/v2/users(?:/|$)~i', $request->get_route() ) ) {
			return new WP_Error( 'rest_authorization_required', esc_attr__( 'Authentication required.', 'patchstack' ), [ 'status' => 401 ] );
		}
		return $result;
	}

	/**
	 * Set security headers if the option is enabled.
	 *
	 * @param array $headers
	 * @return void|array
	 */
	public function set_security_headers( $headers ) {
		if ( get_option( 'patchstack_add_security_headers' ) ) {
			$headers['Referrer-Policy']           = 'strict-origin-when-cross-origin';
			$headers['X-Frame-Options']           = 'SAMEORIGIN';
			$headers['X-XSS-Protection']          = '1; mode=block';
			$headers['X-Content-Type-Options']    = 'nosniff';
			$headers['X-Powered-By']              = null;
			$headers['Server']                    = null;
			$headers['Strict-Transport-Security'] = 'max-age=31536000';
		}

		return $headers;
	}

	/**
	 * Determine if the reCAPTCHA is valid upon comment submission.
	 *
	 * @param array $comment_data
	 * @return void|array
	 */
	public function verify_recaptcha( $comment_data ) {
		$result = $this->captcha_check();
		if ( ! $result['response'] && ( $result['reason'] === 'VERIFICATION_FAILED' || $result['reason'] === 'RECAPTCHA_EMPTY_RESPONSE' ) ) {
			wp_clear_auth_cookie();
			wp_die( 'reCaptcha was not solved or response was empty', 'Error' );
		}

		return $comment_data;
	}

	/**
	 * Unregister the XML-RPC methods of WordPress itself, pingbacks included.
	 *
	 * @param array $methods
	 * @return array
	 */
	public function remove_xmlrpc_methods( $methods ) {
		$kept = [];
		foreach ( (array) $methods as $name => $callback ) {
			// WordPress registers its own methods as "this:" callbacks. Methods another plugin
			// registered carry their own authentication, such as a signed request, and stay.
			$core = ( is_string( $callback ) && strpos( $callback, 'this:' ) === 0 ) || preg_match( '/^(?:wp|blogger|metaWeblog|mt|pingback|demo)\./i', $name );
			if ( ! $core ) {
				$kept[$name] = $callback;
			}
		}

		$allowed = apply_filters( 'patchstack_xmlrpc_allowed_methods', $kept, $methods );
		return is_array( $allowed ) ? $allowed : [];
	}

	/**
	 * Stop advertising the pingback endpoint while XML-RPC is turned off. WordPress 6.1 and
	 * later pass the header through the wp_headers filter; older releases send it directly
	 * once the post is known, so it is also withdrawn on the wp action.
	 *
	 * @param array|null $headers
	 * @return array|null
	 */
	public function remove_pingback_header( $headers = null ) {
		if ( is_array( $headers ) ) {
			unset( $headers['X-Pingback'] );
		} elseif ( ! headers_sent() ) {
			header_remove( 'X-Pingback' );
		}
		return $headers;
	}

	/**
	 * CVE-2026-111497 is a memory corruption in the Brotli decoder that libcurl uses to unpack
	 * response bodies, so any server WordPress fetches from can trigger it. libcurl is taken
	 * out of the decoding altogether on sites that switched the patchstack_disable_curl_decoding
	 * setting on. WordPress unpacks gzip itself, so ordinary requests still
	 * ask for it; a response that is streamed to a file or cut off at a size limit cannot be
	 * unpacked afterwards and is requested uncompressed.
	 *
	 * @param resource|CurlHandle $handle
	 * @param array $request
	 * @return void
	 */
	public function disable_curl_decoding( $handle, $request = [] ) {
		$this->curl_response_limited = false;
		if ( $this->curl_decoding_exposed === null ) {
			$enabled = $this->get_option( 'patchstack_disable_curl_decoding', 0 ) && $this->has_exposed_brotli();
			$this->curl_decoding_exposed = (bool) apply_filters( 'patchstack_disable_curl_decoding', $enabled );
		}

		if ( $this->curl_decoding_exposed && defined( 'CURLOPT_HTTP_CONTENT_DECODING' ) ) {
			$buffered = is_array( $request ) && empty( $request['stream'] ) && empty( $request['filename'] ) && ! isset( $request['limit_response_size'] )
				&& ( ! isset( $request['decompress'] ) || $request['decompress'] ) && function_exists( 'gzdecode' );
			curl_setopt( $handle, CURLOPT_ENCODING, $buffered ? 'gzip' : 'identity' );
			curl_setopt( $handle, CURLOPT_HTTP_CONTENT_DECODING, 0 );
			$this->curl_response_limited = is_array( $request ) && isset( $request['limit_response_size'] );
		}
	}

	/**
	 * A size limit counts the bytes libcurl hands over, which are no longer unpacked. A server
	 * that compresses a size-limited response although it was asked not to would have its body
	 * unpacked after the limit was applied, to far more than the limit. Its Content-Encoding
	 * header is dropped here, so the body stays as received and within the limit.
	 *
	 * @param string $response The raw response headers, followed by the body.
	 * @return void
	 */
	public function refuse_unrequested_encoding( &$response ) {
		if ( ! $this->curl_response_limited || ! is_string( $response ) ) {
			return;
		}

		$this->curl_response_limited = false;
		$end = strpos( $response, "\r\n\r\n" );
		$headers = $end === false ? $response : substr( $response, 0, $end );
		$kept = preg_replace( '/\r?\nContent-Encoding[ \t]*:[^\r\n]*/i', '', $headers );
		if ( is_string( $kept ) && $kept !== $headers ) {
			$response = $kept . ( $end === false ? '' : substr( $response, $end ) );
		}
	}

	/**
	 * Whether libcurl was built with a Brotli release from 1.0.3 up to the fixes in 1.0.10,
	 * 1.1.1 and 1.2.1. A build that does not report its Brotli version counts as exposed.
	 * Distributions that backport the fix keep the old version number, so a patched server
	 * can still be reported here; the cost is limited to the change described above.
	 *
	 * @return boolean
	 */
	private function has_exposed_brotli() {
		$curl = function_exists( 'curl_version' ) ? curl_version() : false;
		// 1 << 23 is CURL_VERSION_BROTLI, which PHP only defines from 7.3.
		if ( ! is_array( $curl ) || ! isset( $curl['features'] ) || ! ( $curl['features'] & 8388608 ) ) {
			return false;
		}

		return $this->is_exposed_brotli_version( isset( $curl['brotli_version'] ) ? $curl['brotli_version'] : '' );
	}

	/**
	 * @param string $reported The version as libcurl reports it, such as "1.0.9" or "brotli/1.1.0".
	 * @return boolean
	 */
	private function is_exposed_brotli_version( $reported ) {
		if ( ! is_string( $reported ) || ! preg_match( '/(\d+)\.(\d+)\.(\d+)/', $reported, $v ) ) {
			return true;
		}

		$version = $v[1] . '.' . $v[2] . '.' . $v[3];
		if ( version_compare( $version, '1.0.3', '<' ) || version_compare( $version, '1.2.1', '>=' ) ) {
			return false;
		}
		return ! ( $v[2] == 0 && $v[3] >= 10 ) && ! ( $v[2] == 1 && $v[3] >= 1 );
	}

	/**
	 * Add the captcha to the comments form.
	 *
	 * @return void
	 */
	public function captcha_display() {
		switch ( $this->get_option( 'patchstack_captcha_type' ) ) {
			case 'v2':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key' ) );
				require dirname( __FILE__ ) . '/views/captcha_v2.php';
				break;
			case 'invisible':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key_v3' ) );
				require dirname( __FILE__ ) . '/views/captcha_invisible.php';
				break;
			case 'v3':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key_v3_new' ) );
				require dirname( __FILE__ ) . '/views/captcha_v3.php';
				break;
			case 'turnstile':
				$site_key = trim( $this->get_option( 'patchstack_captcha_public_key_turnstile' ) );
				require dirname( __FILE__ ) . '/views/captcha_turnstile.php';
				break;
		}
	}

	/**
	 * Check if the submitted reCAPTCHA is valid.
	 *
	 * @return array
	 */
	public function captcha_check() {
		$secret_key = '';
		$site_key   = '';
		switch ( $this->get_option( 'patchstack_captcha_type' ) ) {
			case 'v2':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key' ) );
				break;
			case 'invisible':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key_v3' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key_v3' ) );
				break;
			case 'v3':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key_v3_new' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key_v3_new' ) );
				break;
			case 'turnstile':
				$secret_key = trim( $this->get_option( 'patchstack_captcha_private_key_turnstile' ) );
				$site_key   = trim( $this->get_option( 'patchstack_captcha_public_key_turnstile' ) );
				break;
		}

		if ( ! $secret_key || ! $site_key ) {
			return [
				'response' => false,
				'reason'   => 'ERROR_NO_KEYS',
			];
		}

		if ( ! isset( $_POST['g-recaptcha-response'] ) || ! is_string( $_POST['g-recaptcha-response'] ) || $_POST['g-recaptcha-response'] === '' ) {
			return [
				'response' => false,
				'reason'   => 'RECAPTCHA_EMPTY_RESPONSE',
			];
		}

		$type = $this->get_option( 'patchstack_captcha_type' );
		$response = $this->get_captcha_response( $secret_key, $type );
		$valid = is_array( $response ) && isset( $response['success'] ) && $response['success'] === true;
		if ( $valid && $type === 'v3' ) {
			$threshold = apply_filters( 'patchstack_recaptcha_v3_threshold', 0.5 );
			$threshold = is_numeric( $threshold ) && $threshold >= 0 && $threshold <= 1 ? (float) $threshold : 0.5;
			$valid = isset( $response['score'], $response['action'] )
				&& is_numeric( $response['score'] ) && $response['score'] >= $threshold && $response['score'] <= 1
				&& $response['score'] >= 0 && $response['action'] === 'submit';
		}
		if ( $valid ) {
			return [
				'response' => true,
				'reason'   => '',
			];
		}

		return [
			'response' => false,
			'reason'   => 'VERIFICATION_FAILED',
		];
	}

	/**
	 * Query Google for reAPTCHA validation and response.
	 *
	 * @param string $privatekey
	 * @param string $type
	 * @return array
	 */
	public function get_captcha_response( $privatekey, $type ) {
		$args = [
			'body'      => [
				'secret'   => $privatekey,
				'response' => $_POST['g-recaptcha-response'],
			],
		];

		if ($type != 'turnstile') {
			$resp = wp_remote_post( 'https://www.google.com/recaptcha/api/siteverify', $args );
		} else {
			$resp = wp_remote_post( 'https://challenges.cloudflare.com/turnstile/v0/siteverify', $args );
		}
		
		return json_decode( wp_remote_retrieve_body( $resp ), true );
	}

	/**
	 * Disable user enumeration with ?author= and the REST endpoint.
	 *
	 * @return void
	 */
	public function stop_user_enum() {
		if ( isset( $_GET['author'] ) && ! is_user_logged_in() && ! is_admin() ) {
			die( wp_safe_redirect( get_site_url() ) );
		}

	}

	/**
	 * WordPress also reads the author query variable from a POST body, which the check above never sees.
	 *
	 * @param WP $wp
	 * @return void
	 */
	public function stop_user_enum_query( $wp ) {
		$author = isset( $wp->query_vars['author'] ) ? $wp->query_vars['author'] : '';
		if ( is_scalar( $author ) && preg_match( '/\d/', (string) $author ) && ! is_user_logged_in() && ! is_admin() ) {
			wp_safe_redirect( get_site_url() );
			exit;
		}
	}

	/**
	 * The users sitemap lists every author archive, which names the accounts the checks above hide.
	 *
	 * @param mixed  $provider
	 * @param string $name
	 * @return mixed
	 */
	public function remove_users_sitemap( $provider, $name ) {
		return $name === 'users' ? false : $provider;
	}

	/**
	 * Hide the WordPress generator version in response.
	 *
	 * @return string
	 */
	public function remove_generator() {
		return '';
	}
}
