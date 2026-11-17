<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to communicate from the API to the plugin.
 */
class P_Listener extends P_Core {
	private $signed_request;
	private $signature;
	private $request_blog_id;

	/**
	 * Add the actions required to hide the login page.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		add_action( 'wp_scheduled_delete', [ $this, 'expire_signatures' ] );

		// Only hook into the action if the authentication is set and valid.
		if ( isset( $_POST['patchstack_secret'] ) ) {
			$this->signed_request = $this->signed_payload( $_POST['patchstack_secret'], $this->signature );
			if ( $this->signed_request !== false ) {
				$this->request_blog_id = get_current_blog_id();
				add_action( 'init', [ $this, 'handleRequest' ] );
			}
		}

		// OTT action.
		if ( isset( $_POST['patchstack_ott_action'] ) && is_string( $_POST['patchstack_ott_action'] ) ) {
			$ott = get_option( 'patchstack_ott_action', '' );
			if ( ! empty( $ott ) && hash_equals( $ott, $_POST['patchstack_ott_action'] ) ) {
				$this->setIpHeader( $_POST );
			}
		}

		// License (re)activation.
		if ( isset( $_POST['patchstack_ra_action'] ) && is_string( $_POST['patchstack_ra_action'] ) ) {
			$aas = get_option( 'patchstack_activation_secret', '' );
			$aat = get_option( 'patchstack_activation_time', '' );
			if ( ! empty( $aas ) && hash_equals( $aas, $_POST['patchstack_ra_action'] ) && ! empty ( $aat ) && ( time() - $aat ) < 1800 ) {
				$this->setLicenseInfo();
			}
		}
	}

	/**
	 * Handle the incoming request.
	 *
	 * @return void
	 */
	public function handleRequest() {
		if ( ! isset( $this->signed_request['action'] ) || $this->request_blog_id !== get_current_blog_id() ) {
			return;
		}
		$action = $this->signed_request['action'];

		// Available mapped actions.
		$actions = [
			'patchstack_remote_users'       => 'listUsers',
			'patchstack_firewall_switch'    => 'switchFirewallStatus',
			'patchstack_wordpress_upgrade'  => 'wordpressCoreUpgrade',
			'patchstack_theme_upgrade'      => 'themeUpgrade',
			'patchstack_plugins_upgrade'    => 'pluginsUpgrade',
			'patchstack_plugins_toggle'     => 'pluginsToggle',
			'patchstack_plugins_delete'     => 'pluginsDelete',
			'patchstack_get_options'        => 'getAvailableOptions',
			'patchstack_set_options'        => 'saveOptions',
			'patchstack_refresh_rules'      => 'refreshRules',
			'patchstack_get_firewall_bans'  => 'getFirewallBans',
			'patchstack_firewall_unban_ip'  => 'unbanFirewallIp',
			'patchstack_firewall_unban_all' => 'unbanFirewallAll',
			'patchstack_upload_software'    => 'uploadSoftware',
			'patchstack_upload_logs'        => 'uploadLogs',
			'patchstack_send_ping'          => 'sendPing',
			'patchstack_login_bans'         => 'getLoginBans',
			'patchstack_unban_login'        => 'unbanLogin',
			'patchstack_debug_info'         => 'debugInfo',
			'patchstack_set_ip_header'	    => 'setIpHeader',
			'patchstack_refresh_license'    => 'refreshLicense',
			'patchstack_reset_2fa'			=> 'resetTFA',
			'patchstack_reset_cache'		=> 'resetCache'
		];

		// Action must exist.
		if ( ! isset( $actions[ $action ] ) ) {
			return;
		}
		
		// A captured request stays inside its time window for minutes, so each signature runs once.
		// It is claimed here and not on arrival: the API sends one signed request to admin-ajax.php
		// and then to the site root, and an attempt that never got this far must not use it up.
		if ( ! $this->acquire_lock( 'patchstack_replay_' . sha1( $this->signature ), 11 * MINUTE_IN_SECONDS ) ) {
			$this->returnResults( false, null, 'This request has already been received.' );
		}

		$method = $actions[ $action ];
		$updates = [ 'wordpressCoreUpgrade', 'themeUpgrade', 'pluginsUpgrade', 'pluginsDelete' ];
		if ( in_array( $method, $updates, true ) && ! wp_is_file_mod_allowed( 'patchstack_remote_management' ) ) {
			$this->returnResults( false, null, 'File changes are disabled on this installation.' );
		}
		// Only the primary site evaluates the network's existing WordPress update policy.
		if ( $method === 'pluginsUpgrade' && is_multisite() && is_main_network() && is_main_site() ) {
			$this->pluginsUpgrade( true );
			return;
		}
		if ( is_multisite() && in_array( $method, array_merge( $updates, [ 'pluginsToggle', 'resetTFA', 'resetCache' ] ), true )
			&& ! $this->network_allows_action( $this->network_grant() ) ) {
			$this->returnResults( false, null, 'This action requires authorization from the network administrator.' );
		}

		// Execute the action.
		$this->$method();
	}

	// The network administrator's grant covers commands signed with the primary site's key.
	// A subsite's key never inherits it.
	private function network_grant() {
		return is_main_network() && is_main_site() && in_array( get_site_option( 'patchstack_network_plugin_updates', 0 ), [ 1, '1' ], true );
	}

	private function network_allows_action( $default ) {
		return apply_filters( 'patchstack_allow_network_remote_management', $default, $this->request_blog_id, $this->signed_request['action'] );
	}

	/**
	 * Determine if the provided secret hash equals the sha1 of the private id and key.
	 *
	 * @param string $secret Hash that is sent from our API.
	 * @return boolean
	 */
	public function verifyToken( $secret ) {
		return $this->signed_payload( $secret ) !== false;
	}

	public function expire_signatures() {
		global $wpdb;
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM $wpdb->options WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, ':', 1) AS UNSIGNED) <= %d",
			$wpdb->esc_like( 'patchstack_replay_' ) . '%',
			time()
		) );
	}

	private function signed_payload( $secret, &$signature = null ) {
		if ( ! is_string( $secret ) ) {
			return false;
		}
		$request = json_decode( base64_decode( $secret ), true );
		if ( ! isset( $request['nonce'], $request['time'], $request['data'], $request['hmac'] )
			|| ( ! is_string( $request['nonce'] ) && ! is_int( $request['nonce'] ) ) || ! is_string( $request['data'] ) || ! is_string( $request['hmac'] )
			|| ( ! is_int( $request['time'] ) && ! is_string( $request['time'] ) )
			|| ! ctype_digit( (string) $request['time'] ) || (string) (int) $request['time'] !== (string) $request['time']
			|| abs( (int) floor( time() / 30 ) - (int) $request['time'] ) > 10 ) {
			return false;
		}

		$id  = get_option( 'patchstack_clientid' );
		$key = $this->get_secret_key();
		if ( empty( $id ) || empty( $key ) ) {
			return false;
		}
		$hmac = hash_hmac( 'sha1', $request['nonce'] . $request['time'] . $request['data'], $key . '-' . $id );
		if ( ! hash_equals( $hmac, $request['hmac'] ) ) {
			return false;
		}
		$signature = $hmac;

		$data = json_decode( $request['data'], true );
		if ( is_string( $data ) ) {
			// Older clients can double-encode the signed body.
			$data = json_decode( $data, true );
		}
		return isset( $data['action'] ) && is_string( $data['action'] ) ? $data : false;
	}

	/**
	 * Determine if given action succeded or not, then return the appropriate message.
	 *
	 * @param mixed  $thing
	 * @param string $success
	 * @param string $fail
	 * @return void
	 */
	private function returnResults( $thing, $success = '', $fail = '' ) {
		if ( ! is_wp_error( $thing ) && $thing !== false ) {
			wp_send_json( [ 'success' => $success ] );
		}

		wp_send_json( [ 'error' => $fail ] );
	}

	/**
	 * Send a ping back to the API.
	 *
	 * @return void
	 */
	private function sendPing() {
		do_action( 'patchstack_send_ping' );
		wp_send_json( [ 'firewall' => $this->get_option( 'patchstack_basic_firewall' ) == 1 ] );
	}

	/**
	 * Get list of all users on WordPress
	 *
	 * @return void
	 */
	private function listUsers() {
		// Only fetch data we actually need.
		$users = get_users( [ 'role__in' => [ 'administrator', 'editor', 'author', 'contributor' ] ] );
		$roles = wp_roles();
		$roles = $roles->get_names();
		$data  = [];

		// Loop through all users.
		foreach ( $users as $user ) {

			// Get text friendly version of the role.
			$text = '';
			foreach ( $user->roles as $role ) {
				if ( isset( $roles[ $role ] ) ) {
					$text .= $roles[ $role ] . ', ';
				} else {
					$text .= $role . ', ';
				}
			}

			// Push to array that we will eventually output.
			array_push(
				$data,
				[
					'id'       => $user->data->ID,
					'username' => $user->data->user_login,
					'email'    => $user->data->user_email,
					'roles'    => substr( $text, 0, -2 ),
				]
			);
		}

		wp_send_json( [ 'users' => $data ] );
	}

	/**
	 * Switch the firewall status from on to off or off to on.
	 *
	 * @return string
	 */
	private function switchFirewallStatus() {
		$state = $this->get_option( 'patchstack_basic_firewall' ) == 1;
		update_option( 'patchstack_basic_firewall', $state == 1 ? 0 : 1, true );
		$this->returnResults( null, 'Firewall ' . ( $state == 1 ? 'disabled' : 'enabled' ) . '.', null );
	}

	/**
	 * Upgrade the core of WordPress.
	 *
	 * @return string|void
	 */
	private function wordpressCoreUpgrade() {
		@set_time_limit( 180 );

		// Get the core update info.
		wp_version_check();
		$core = get_site_transient( 'update_core' );

		// Any updates available?
		if ( ! isset( $core->updates[0] ) ) {
			$this->returnResults( false, null, 'No update available at this time.' );
		}

		// Are we on the latest version already?
		if ( $core->updates[0]->response == 'latest' ) {
			$this->returnResults( false, null, 'Site is already running the latest version available.' );
		}

		// Require some libraries and attempt the upgrade.
		@include_once ABSPATH . '/wp-admin/includes/admin.php';
		@include_once ABSPATH . '/wp-admin/includes/class-wp-upgrader.php';
		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Core_Upgrader( $skin );
		$result   = $upgrader->upgrade(
			$core->updates[0],
			[
				'attempt_rollback'             => true,
				'do_rollback'                  => true,
				'allow_relaxed_file_ownership' => true,
			]
		);
		if ( ! $result ) {
			$this->returnResults( false, null, 'The WordPress core could not be upgraded, most likely because of invalid filesystem connection information.' );
		}

		// Synchronize again with the API.
		do_action( 'patchstack_send_software_data' );
		$this->returnResults( $result, 'WordPress core has been upgraded.', 'The WordPress core could not be upgraded.' );
	}

	/**
	 * Upgrade a WordPress theme.
	 *
	 * @return string|void
	 */
	private function themeUpgrade() {
		if ( !isset( $this->signed_request['patchstack_theme_upgrade'] ) ) {
			return;
		}

		@set_time_limit( 180 );

		// Require some files we need to execute the upgrade.
		$theme = wp_filter_nohtml_kses( $this->signed_request['patchstack_theme_upgrade'] );
		@include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		if ( file_exists( ABSPATH . 'wp-admin/includes/class-theme-upgrader.php' ) ) {
			@include_once ABSPATH . 'wp-admin/includes/class-theme-upgrader.php';
		}
		@include_once ABSPATH . 'wp-admin/includes/misc.php';
		@include_once ABSPATH . 'wp-admin/includes/file.php';

		// Upgrade the theme.
		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Theme_Upgrader( $skin );
		$result   = $upgrader->upgrade( $theme, [ 'allow_relaxed_file_ownership' => true ] );
		if ( ! $result || is_wp_error( $result ) ) {
			$this->returnResults( false, null, 'The theme could not be upgraded, most likely because of invalid filesystem connection information.' );
		}

		// Synchronize again with the API.
		do_action( 'patchstack_send_software_data' );
		$this->returnResults( null, 'The theme has been updated successfully.' );
	}

	/**
	 * Upgrade a batch of plugins at once.
	 *
	 * @return string|void
	 */
	private function pluginsUpgrade( $check_network_policy = false ) {
		if ( empty( $this->signed_request['patchstack_plugins_upgrade'] ) || ! is_string( $this->signed_request['patchstack_plugins_upgrade'] ) ) {
			$this->returnResults( false, null, 'No valid plugin names have been given.' );
		}

		@set_time_limit( 180 );

		$plugins = array_filter( explode( '|', $this->signed_request['patchstack_plugins_upgrade'] ), 'strlen' );

		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/misc.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/template.php';
		require_once ABSPATH . 'wp-admin/includes/update.php';
		wp_update_plugins();

		$upgrade = [];
		$matched = [];
		foreach ( get_plugins() as $path => $data ) {
			$parts = explode( '/', $path, 2 );
			if ( in_array( $parts[0], $plugins, true ) ) {
				$upgrade[] = $path;
				$matched[] = $parts[0];
			}
		}
		if ( ! $upgrade || array_diff( $plugins, $matched ) ) {
			$this->returnResults( false, null, 'One or more requested plugins could not be found.' );
		}
		if ( $check_network_policy ) {
			$approved = $this->network_grant();
			if ( ! $approved ) {
				$offers = get_site_transient( 'update_plugins' );
				$updater = new WP_Automatic_Updater();
				$approved = true;
				foreach ( $upgrade as $path ) {
					if ( ! isset( $offers->response[ $path ]->plugin ) || $offers->response[ $path ]->plugin !== $path
						|| ! $updater->should_update( 'plugin', $offers->response[ $path ], WP_PLUGIN_DIR ) ) {
						$approved = false;
						break;
					}
				}
			}
			if ( ! $this->network_allows_action( $approved ) ) {
				$this->returnResults( false, null, 'This plugin update requires authorization from the network administrator.' );
			}
		}

		// Upgrade the plugins.
		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		$result   = $upgrader->bulk_upgrade( $upgrade, [ 'allow_relaxed_file_ownership' => true ] );
		foreach ( $upgrade as $path ) {
			if ( ! is_array( $result ) || empty( $result[ $path ] ) || is_wp_error( $result[ $path ] ) ) {
				$this->returnResults( false, null, 'The plugin update did not complete for ' . $path . '.' );
			}
		}

		// Synchronize again with the API.
		do_action( 'patchstack_send_software_data' );
		$this->returnResults( null, 'The plugins have been updated successfully.' );
	}

	/**
	 * Toggle the state of a batch of plugin to activated or de-activated.
	 *
	 * @return string|void
	 */
	private function pluginsToggle() {
		if (!isset( $this->signed_request['patchstack_plugins'], $this->signed_request['patchstack_plugins_toggle'] ) ) {
			return;
		}

		@set_time_limit( 180 );

		// Must have a valid number of plugins received to toggle.
		$plugins = wp_filter_nohtml_kses( $this->signed_request['patchstack_plugins'] );
		$plugins = explode( '|', $plugins );
		$state = $this->signed_request['patchstack_plugins_toggle'] == 'on' ? 'on' : 'off';
		if ( count( $plugins ) == 0 ) {
			$this->returnResults( false, null, 'No valid plugin names have been given.' );
		}

		@include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$all_plugins = get_plugins();

		// New array with all available plugins and the ones we want to toggle.
		$toggle = [];
		foreach ( $all_plugins as $path => $data ) {
			$t = explode( '/', $path );

			// Don't continue if the plugin does not exist locally.
			if ( ! in_array( $t[0], $plugins ) ) {
				continue;
			}

			// If plugin should be turned on, check if it's already turned on first.
			if ( $state == 'on' && ! is_plugin_active( $path ) ) {
				array_push( $toggle, $path );
			}

			// If plugin should be turned off, check if it's already turned off first.
			if ( $state == 'off' && is_plugin_active( $path ) ) {
				array_push( $toggle, $path );
			}
		}

		// Don't continue if we have no valid plugins to toggle..
		if ( count( $toggle ) == 0 ) {
			$this->returnResults( false, null, 'The plugins are already turned ' . $state . '.' );
		}

		// Turn the plugins on or off?
		if ( $state == 'on' ) {
			$result = activate_plugins( $toggle );
			if ( is_wp_error( $result ) ) {
				$this->returnResults( false, null, 'One or more plugins could not be activated.' );
			}
		}

		if ( $state == 'off' ) {
			deactivate_plugins( $toggle );
		}

		// Synchronize again with the API.
		do_action( 'patchstack_send_software_data' );
		$this->returnResults( null, 'The ' . ( count( $toggle ) == 1 ? 'plugin has' : 'plugins have' ) . ' been successfully turned ' . $state . '.' );
	}

	/**
	 * Delete a batch of plugins.
	 *
	 * @return string|void
	 */
	private function pluginsDelete() {
		if (!isset( $this->signed_request['patchstack_plugins'] ) ) {
			return;
		}

		@set_time_limit( 180 );

		// Must have a valid number of plugins received to toggle.
		$plugins = wp_filter_nohtml_kses( $this->signed_request['patchstack_plugins'] );
		$plugins = explode( '|', $plugins );
		if ( count( $plugins ) == 0 ) {
			$this->returnResults( false, null, 'No valid plugin names have been given.' );
		}

		@include_once ABSPATH . 'wp-admin/includes/file.php';
		@include_once ABSPATH . 'wp-admin/includes/plugin.php';
		$all_plugins = get_plugins();

		// New array with all available plugins and the ones we want to toggle.
		$delete = [];
		foreach ( $all_plugins as $path => $data ) {
			$t = explode( '/', $path );

			// Don't continue if the plugin does not exist locally.
			if ( ! in_array( $t[0], $plugins ) ) {
				continue;
			}

			array_push( $delete, $path );
		}

		// Don't continue if we have no valid plugins to toggle..
		if ( count( $delete ) == 0 ) {
			$this->returnResults( false, null, 'No valid plugins to delete.' );
		}

		@deactivate_plugins( $delete );
		$result = delete_plugins( $delete );
		if ( $result !== true ) {
			$this->returnResults( false, null, 'One or more plugins could not be deleted.' );
		}

		// Synchronize again with the API.
		do_action( 'patchstack_send_software_data' );
		$this->returnResults( null, 'The plugins have been successfully deleted.' );
	}

	/**
	 * Save received options.
	 *
	 * @return void
	 */
	private function saveOptions() {
		if ( ! isset( $this->signed_request['patchstack_set_options'] ) ) {
			exit;
		}

		// Get the received options.
		$options = json_decode( base64_decode( $this->signed_request['patchstack_set_options'] ), true );
		if ( ! $options || count( $options ) == 0 ) {
			exit;
		}

		// Loop through the options and update their value.
		$exclude_filter = ['patchstack_firewall_custom_rules'];
		foreach ( $options as $key => $value ) {
			if ( array_key_exists( $key, $this->plugin->admin_options->options ) ) {

				// Booleans would persist as '1' / '' otherwise, store them as 1/0 so type checks behave consistently.
				if ( is_bool( $value ) ) {
					$value = $value ? 1 : 0;
				}

				// Some options should not be filtered and could cause unexpected behavior if they are filtered.
				if ( ! in_array( $key, $exclude_filter ) ) {
					$value = map_deep( $value, 'wp_filter_nohtml_kses' );
				}

				update_option( $key, $value );
			}
		}

		$this->returnResults( null, 'Plugin options has been updated.' );
	}

	/**
	 * Return list of keys and values of Patchstack options.
	 *
	 * @return array
	 */
	private function getAvailableOptions() {
		// Get all options and filter by the Patchstack prefix.
		global $wpdb;
		$options  = $wpdb->get_results( "SELECT option_name, option_value FROM " . $wpdb->options . " WHERE option_name LIKE 'patchstack_%'" );
		$settings = [];
		$found = [];

		// Internal lock rows are not part of the dashboard's options contract.
		foreach ( $options as $option ) {
			if ( preg_match( '/^patchstack_(replay_|2fa_lock_|login_[0-9a-f]{32}_lock$)/', $option->option_name ) ) {
				continue;
			}
			array_push( $found, $option->option_name );
			$settings[] = (array) $option;
		}

		// Check for potential missing options and add them to the output.
		foreach( [ 'patchstack_firewall_custom_rules' ] as $slug ) {
			if ( ! in_array( $slug, $found, true ) ) {
				$settings[] = [
					'option_name'  => $slug,
					'option_value' => $this->get_option( $slug, '' )
				];
			}
		}

		// Add custom values which aren't directly available from the options table.
		// User roles available for whitelisting.
		$roles           = wp_roles();
		$roles           = $roles->get_names();
		$roles_available = [];
		foreach ( $roles as $key => $role ) {
			$roles_available[ $key ] = $role;
		}
		$settings[] = [
			'option_name'  => 'patchstack_basic_firewall_roles_available',
			'option_value' => serialize( $roles_available ),
		];

		// Whether or not auto-updates are disabled in the code.
		$settings[] = [
			'option_name'  => 'patchstack_auto_updates_disabled',
			'option_value' => defined( 'AUTOMATIC_UPDATER_DISABLED' ) && AUTOMATIC_UPDATER_DISABLED,
		];

		wp_send_json( $settings );
	}

	/**
	 * Pull firewall rules from the API.
	 *
	 * @return void
	 */
	private function refreshRules() {
		do_action( 'patchstack_post_dynamic_firewall_rules' );
		$this->returnResults( null, 'Firewall rules have been refreshed.' );
	}

	/**
	 * Get a list of IP addresses that are currently banned by the firewall.
	 *
	 * @return void|array
	 */
	private function getFirewallBans($return = false) {
		// Calculate block time.
		$minutes = (int) $this->get_option( 'patchstack_autoblock_minutes', 30 );
		$timeout = (int) $this->get_option( 'patchstack_autoblock_blocktime', 60 );
		if ( empty( $minutes ) || empty( $timeout ) ) {
			$time = 30 + 60;
		} else {
			$time = $minutes + $timeout;
		}

		global $wpdb;
		$results = $wpdb->get_results(
			$wpdb->prepare( 'SELECT ip FROM ' . $wpdb->prefix . "patchstack_firewall_log WHERE apply_ban = 1 AND log_date >= ('" . current_time( 'mysql' ) . "' - INTERVAL %d MINUTE) GROUP BY ip", [ $time ] ),
			OBJECT
		);

		$out = [];
		foreach ( $results as $result ) {
			if ( isset( $result->ip ) ) {
				array_push( $out, $result->ip );
			}
		}

		if ($return) {
			return $out;
		}

		wp_send_json( $out );
	}

	/**
	 * Unban a specific IP address from the firewall.
	 *
	 * @return void
	 */
	private function unbanFirewallIp() {
		if ( ! isset( $this->signed_request['patchstack_ip'] ) || !filter_var( $this->signed_request['patchstack_ip'], FILTER_VALIDATE_IP ) ) {
			return;
		}

		global $wpdb;
		$wpdb->query( $wpdb->prepare( 'UPDATE ' . $wpdb->prefix . 'patchstack_firewall_log SET apply_ban = 0 WHERE ip = %s', [ $this->signed_request['patchstack_ip'] ] ) );
		$this->returnResults( null, 'The IP has been unbanned.' );
	}

	/**
	 * Unban a specific IP address from the firewall.
	 *
	 * @return void
	 */
	private function unbanFirewallAll() {
		global $wpdb;

		// Get all banned IP addresses.
		$ips = $this->getFirewallBans(true);
		if (count($ips) == 0) {
			$this->returnResults( null, 'There are no IP addresses to unban.' );
		}

		// Unban all IP addresses.
		foreach ($ips as $ip) {
			$wpdb->query( $wpdb->prepare( 'UPDATE ' . $wpdb->prefix . 'patchstack_firewall_log SET apply_ban = 0 WHERE ip = %s', [ $ip ] ) );
		}
		
		$this->returnResults( null, 'All IP addresses has been unbanned.' );
	}

	/**
	 * Send all current software on the WordPress site to the API.
	 *
	 * @return void
	 */
	private function uploadSoftware() {
		do_action( 'patchstack_send_software_data' );
		$this->returnResults( null, 'The software data has been sent to the API.' );
	}

	/**
	 * Upload the firewall and activity logs.
	 *
	 * @return void
	 */
	private function uploadLogs() {
		do_action( 'patchstack_send_hacker_logs' );
		do_action( 'patchstack_send_event_logs' );
		$this->returnResults( null, 'The logs have been sent to the API.' );
	}

	/**
	 * Get the currently banned IP addresses from the login page.
	 *
	 * @return void
	 */
	private function getLoginBans() {
		global $wpdb;
		wp_send_json( [ 'banned' => $wpdb->get_results( $this->login_bans_query() ) ] );
	}

	/**
	 * Unban a banned login IP address.
	 *
	 * @return void
	 */
	private function unbanLogin() {
		if ( ! isset( $this->signed_request['id'], $this->signed_request['type'] ) || ! is_scalar( $this->signed_request['id'] ) || ! ctype_digit( (string) $this->signed_request['id'] ) ) {
			exit;
		}

		if ( ! in_array( $this->signed_request['type'], [ 'unblock', 'unblock_whitelist' ], true ) ) {
			return;
		}
		global $wpdb;
		$table = $wpdb->prefix . 'patchstack_event_log';
		$ip = $wpdb->get_var( $wpdb->prepare( "SELECT ip FROM $table WHERE id = %s AND action IN ('failed login', 'login ban')", $this->signed_request['id'] ) );
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			if ( $this->signed_request['type'] === 'unblock_whitelist' ) {
				// An IPv6 ban covers the client's /64, so the whitelist entry has to as well.
				$entry = strpos( $ip, ':' ) !== false && $this->login_limit_key( $ip ) === $ip ? $ip . '/64' : $ip;
				update_option( 'patchstack_login_whitelist', $this->get_option( 'patchstack_login_whitelist', '' ) . "\n" . $entry );
			}
			if ( $wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE ip = %s AND (action IN ('login attempt', 'login ban') OR (action = 'failed login' AND (flag IS NULL OR flag <> 'patchstack:login-audit')))", $ip ) ) === false ) {
				$this->returnResults( false, null, 'The login ban could not be removed.' );
			}
			delete_transient( 'patchstack_login_' . md5( $ip ) );
		}

		$this->returnResults( null, 'The unban has been processed.' );
	}

	/**
	 * Get information for debugging purposes.
	 * 
	 * @return void
	 */
	private function debugInfo() {
		// $_SERVER also carries the host's environment and any credential a proxy forwards in a header,
		// so only named request details are returned, plus the variables that hold nothing but addresses:
		// those are how a proxy passes on the visitor's IP, whatever it calls the variable.
		$known = [
			'REMOTE_ADDR', 'REMOTE_PORT', 'SERVER_ADDR', 'SERVER_NAME', 'SERVER_PORT', 'SERVER_PROTOCOL', 'SERVER_SOFTWARE', 'REQUEST_METHOD', 'REQUEST_URI', 'REQUEST_SCHEME', 'REQUEST_TIME', 'HTTPS', 'GATEWAY_INTERFACE', 'SCRIPT_NAME', 'CONTENT_TYPE', 'CONTENT_LENGTH',
			'HTTP_HOST', 'HTTP_USER_AGENT', 'HTTP_VIA', 'HTTP_FORWARDED', 'HTTP_X_FORWARDED_PROTO', 'HTTP_X_FORWARDED_HOST', 'HTTP_X_FORWARDED_PORT', 'HTTP_CF_RAY', 'HTTP_CF_IPCOUNTRY', 'HTTP_CDN_LOOP',
		];
		$server = [];
		foreach ( $_SERVER as $key => $value ) {
			if ( ! is_scalar( $value ) ) {
				continue;
			}
			$addresses = array_filter( array_map( 'trim', explode( ',', (string) $value ) ), 'strlen' );
			$only_addresses = $addresses && count( $addresses ) === count( array_filter( $addresses, function ( $address ) {
				return filter_var( $address, FILTER_VALIDATE_IP ) !== false;
			} ) );
			if ( in_array( $key, $known, true ) || $only_addresses ) {
				$server[ $key ] = $value;
			}
		}

		$debug = [
			'server' 	=> $server,
			'php' 		=> phpversion()
		];

		wp_send_json( $debug );
	}

	/**
	 * Try to determine the proper IP address headers.
	 * 
	 * @return void
	 */
	private function setIpHeader( $params = null ) {
		if ( $params === null ) {
			$params = $this->signed_request;
		}
		if ( ! isset( $params['ip'] ) ) {
			return;
		}

		$ips = ! is_array ( $params['ip'] ) ? [ $params['ip'] ] : $params['ip'];

		// REMOTE_ADDR?
		foreach ( $ips as $ip ) {
			if ( isset( $_SERVER['REMOTE_ADDR'] ) && $_SERVER['REMOTE_ADDR'] == $ip ) {
				update_option( 'patchstack_firewall_ip_header', 'REMOTE_ADDR', true );
				update_option( 'patchstack_ip_header_computed', 1 );
				update_option( 'patchstack_ott_action', '' );
				wp_send_json( [ 'success' => true, 'header' => 'REMOTE_ADDR' ] );
			}
		}

		// IP address headers in order of priority.
		$priority = [ 'REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_SUCURI_CLIENTIP',  'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'SUCURI_RIP' ];
		foreach ( $ips as $ip ) {
			foreach ( $priority as $header ) {
				if ( isset( $_SERVER[ $header ] ) && $_SERVER[ $header ] == $ip ) {
					update_option( 'patchstack_firewall_ip_header', $header, true );
					update_option( 'patchstack_ip_header_computed', 1 );
					update_option( 'patchstack_ott_action', '' );
					wp_send_json( [ 'success' => true,  'header' => $header ] );
				}
			}
		}

		// Still not found? Iterate over all $_SERVER keys.
		foreach ( $ips as $ip ) {
			foreach ( $_SERVER as $key => $value ) {
				if ( $value == $ip ) {
					update_option( 'patchstack_firewall_ip_header', $key, true );
					update_option( 'patchstack_ip_header_computed', 1 );
					update_option( 'patchstack_ott_action', '' );
					wp_send_json( [ 'success' => true,  'header' => $key ] );
				}
			}
		}

		update_option( 'patchstack_ott_action', '' );
		wp_send_json( [ 'success' => false, 'header' => 'unknown' ] );
	}

	/**
	 * Refresh the license and subscription information.
	 * 
	 * @return void
	 */
	private function refreshLicense () {
		do_action( 'patchstack_update_license_status' );
		do_action( 'patchstack_sync_software_and_rules' );
		
		wp_send_json( array( 'success' => true ) );
	}

	/**
	 * Set license information.
	 * 
	 * @return void
	 */
	private function setLicenseInfo () {
		if ( ! isset( $_POST['id'], $_POST['secret'] ) ) {
			wp_send_json( [ 'success' => false, 'message' => 'Missing required parameters.' ] );
		}

		$result = $this->plugin->activation->alter_license( $_POST['id'], $_POST['secret'], 'activate' );
		if ( $result['result'] == 'error' ) {
			wp_send_json( [ 'success' => false, 'message' => 'The license could not be activated.' ] );
		}

		update_option( 'patchstack_activation_secret', '' );
		update_option( 'patchstack_activation_time', '' );
		wp_send_json( [ 'success' => true ] );
	}

	/**
	 * Reset the 2FA data all users or specific ones.
	 * 
	 * @return void
	 */
	private function resetTFA () {
		$user_id = 0;
		$all = ! array_key_exists( 'user_id', $this->signed_request ) && ! array_key_exists( 'user_name', $this->signed_request );
		if ( isset( $this->signed_request['user_id'] ) && is_scalar( $this->signed_request['user_id'] ) && ctype_digit( (string) $this->signed_request['user_id'] ) ) {
			$user_id = (int) $this->signed_request['user_id'];
		} elseif ( isset( $this->signed_request['user_name'] ) && is_string( $this->signed_request['user_name'] ) ) {
			$name = $this->signed_request['user_name'];
			$user = get_user_by( 'login', $name );
			if ( ! $user ) {
				$user = get_user_by( 'email', $name );
			}
			$user_id = $user ? $user->ID : 0;
		}
		if ( ! $all && ( ! $user_id || ! get_userdata( $user_id ) ) ) {
			$this->returnResults( false, null, 'The requested account could not be found.' );
		}
		if ( ! $all ) {
			if ( ! $this->reset_user_2fa( $user_id ) ) {
				$this->returnResults( false, null, 'The 2FA reset could not be completed. Please try again.' );
			}
		} else {
			global $wpdb;
			$last_id = 0;
			$keys = [ 'webarx_2fa_enabled', 'webarx_2fa_secretkey', 'webarx_2fa_secretkey_nonce', 'patchstack_2fa_enabled', 'patchstack_2fa_secretkey', 'patchstack_2fa_secretkey_nonce', '_patchstack_2fa_state', '_patchstack_2fa_reset_pending' ];
			do {
				$ids = $wpdb->get_col( $wpdb->prepare(
					"SELECT DISTINCT user_id FROM $wpdb->usermeta WHERE meta_key IN (" . implode( ', ', array_fill( 0, count( $keys ), '%s' ) ) . ') AND (meta_key <> %s OR meta_value <> %s) AND user_id > %d ORDER BY user_id LIMIT 100',
					array_merge( $keys, [ 'patchstack_2fa_enabled', '0', $last_id ] )
				) );
				if ( $wpdb->last_error ) {
					$this->returnResults( false, null, 'The 2FA reset could not be completed. Please try again.' );
				}
				foreach ( $ids as $id ) {
					$last_id = (int) $id;
					if ( ! $this->reset_user_2fa( $last_id ) ) {
						$this->returnResults( false, null, 'The 2FA reset could not be completed. Please try again.' );
					}
				}
			} while ( count( $ids ) === 100 );
		}

		wp_send_json( [ 'success' => true ] );
	}

	/**
	 * Reset the WordPress cache.
	 * 
	 * @return void
	 */
	private function resetCache () {
		wp_send_json( [ 'success' => wp_cache_flush() ] );
	}
}
