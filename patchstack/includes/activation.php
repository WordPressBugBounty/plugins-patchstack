<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to activate and deactivate the plugin.
 * Additionally, we use it to run migrations.
 */
class P_Activation extends P_Core {

	/**
	 * Holds any activation errors.
	 * 
	 * @var array
	 */
	private $activation_errors = [];

	private $migration_versions = [ '3.0.0', '3.0.1', '3.0.2', '3.0.3', '3.0.4', '3.0.5' ];

	/**
	 * Plugin activation owns its final sync after license setup completes.
	 *
	 * @var boolean
	 */
	private $defer_license_sync = false;

	/**
	 * Add the actions required for the activation.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		add_action( 'activated_plugin', [ $this, 'redirect_activation' ], 10, 2 );
		add_action( 'updated_option', [ $this, 'updated_option' ], 10, 3 );
		add_action( 'patchstack_migrate', [ $this, 'run_scheduled_migrations' ] );
		add_action( 'admin_notices', [ $this, 'migration_notice' ] );
		add_action( 'admin_post_patchstack_retry_migration', [ $this, 'retry_migration' ] );
		add_action( 'added_option', [ $this, 'added_option' ], 10, 2 );
		add_action( 'update_site_option_active_sitewide_plugins', [ $this, 'refresh_auto_prepend_config' ] );
		add_action( 'add_site_option_active_sitewide_plugins', [ $this, 'refresh_auto_prepend_config' ] );
	}

	/**
	 * Redirect the user to our settings page after plugin activation.
	 *
	 * @param string  $plugin The plugin that is activated.
	 * @param boolean $network_activation If a network wide activation. (multisite)
	 * @return void
	 */
	public function redirect_activation( $plugin, $network_activation ) {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}

		// Only if it's the current plugin.
		if ( $plugin == $this->plugin->basename && ! isset( $_REQUEST['_ajax_nonce'] ) ) {

			// If plugin bulk activate through wp-admin, we ignore the redirect if it's more than 1 plugin.
			if ( isset( $_POST['checked'] ) && is_array( $_POST['checked'] ) && count( $_POST['checked'] ) > 1 ) {
				return;
			}

			// If the plugin is already connected or API activated, no need to redirect again.
			if ( $this->license_is_active() || $this->is_connected() ) {
				return;
			}

			// Determine if secret token was set, if so, sync with API.
			$attemptAuto = false;
			$secretToken = get_option( 'patchstack_activation_secret', '' );
			if ( ! empty( $secretToken ) ) {
				$attemptAuto = true;
			}

			// In case of multisite, we want to redirect the user to a different page.
			if ( $network_activation ) {
				wp_safe_redirect( network_admin_url( 'admin.php?page=patchstack-multisite-settings&tab=multisite&ps_activated=1' . ($attemptAuto ? '&ps_autoa=1' : '' ) ) );
			} else {
				wp_safe_redirect( admin_url( 'admin.php?page=' . $this->plugin->name . '&ps_activated=1' . ($attemptAuto ? '&ps_autoa=1' : '' ) ) );
			}
			exit;
		}
	}

	/**
	 * Check if the plugin meets requirements and disable it if they are not present.
	 *
	 * @return boolean
	 */
	public function check_requirements() {
		if ( $this->meets_requirements() ) {
			return true;
		}

		// Add a dashboard notice.
		add_action( 'all_admin_notices', [ $this, 'requirements_not_met_notice' ] );
		return false;
	}

	/**
	 * Check that all plugin requirements are met.
	 *
	 * @return boolean
	 */
	public function meets_requirements() {
		// Check to see if we can access the API.
		$response = wp_remote_request(
			$this->plugin->api_url,
			[
				'method'      => 'GET',
				'timeout'     => 10,
				'redirection' => 5,
			]
		);

		// Check if we can access the API.
		if ( is_wp_error( $response ) ) {
			$this->activation_errors[] = 'We were unable to contact our API server. Please contact your host and ask them to make sure that outgoing connections to api.patchstack.com are not blocked.<br />Additional error message to give to your host: ' . $response->get_error_message();
			return false;
		}

		// Do checks for required classes / functions or similar.
		// Add detailed messages to $this->activation_errors array.
		if ( version_compare( phpversion(), '5.6.0', '<' ) ) {
			$this->activation_errors[] = 'Please update the PHP version on your host to at least 5.6.0. Ask your host if you do not know what this means.';
			return false;
		}

		global $wp_version;
		if ( version_compare( $wp_version, '4.3.0', '<' ) ) {
			$this->activation_errors[] = 'Please upgrade your WordPress site to at least 4.3.0.';
			return false;
		}

		return true;
	}

	/**
	 * Adds a notice to the dashboard if the plugin requirements are not met.
	 *
	 * @return void
	 */
	public function requirements_not_met_notice() {
		// Deactivate the plugin.
		deactivate_plugins( $this->plugin->basename );

		// Compile default message.
		$default_message = esc_attr__( 'Patchstack could not be activated due to a conflict. See below for information regarding the conflict.<br />', 'patchstack' );

		// Print the errors on the screen.
		echo wp_kses_post( $default_message );
		echo wp_kses_post( implode( '<br />', $this->activation_errors ) );
	}

	/**
	 * Activate the plugin.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function activate( $core ) {
		// Bail early if requirements are not met.
		if ( ! $this->check_requirements() ) {
			$this->requirements_not_met_notice();
			exit;
		}

		// Check if the webarx/webarx.php plugin is present, if so, remove it.
		if ( is_dir( WP_PLUGIN_DIR . '/webarx' ) ) {

			if ( ! $this->migrate_legacy_options() ) {
				wp_die( esc_html__( 'The existing WebARX settings could not be copied. Please try activating Patchstack again.', 'patchstack' ) );
			}

			// Deactivate the plugin.
			include_once ABSPATH . 'wp-admin/includes/plugin.php';
			deactivate_plugins( [ 'webarx/webarx.php' ] );
			update_option( 'patchstack_license_free', '0', true );
		}

		// Make sure any rewrite functionality has been loaded.
		$this->migrate();
		add_option( 'patchstack_first_activated', '1' );

		// Whether or not we should send a secret key to our API.
		$sendSecret = false;

		$was_deferred = $this->defer_license_sync;
		$this->defer_license_sync = true;
		try {
			// Activate the license.
			if ( $this->plugin->client_id != 'PATCHSTACK_CLIENT_ID' && $this->plugin->private_key != 'PATCHSTACK_PRIVATE_KEY' ) {
				$this->alter_license( $this->plugin->client_id, $this->plugin->private_key, 'activate' );
			} elseif ( get_option( 'patchstack_clientid', false ) != false && get_option( 'patchstack_secretkey', false ) != false ) {
				$this->alter_license( get_option( 'patchstack_clientid' ), $this->get_secret_key(), 'activate' );
			} else {
				$sendSecret = true;
				update_option( 'patchstack_license_free', '1', true );
			}
		} finally {
			$this->defer_license_sync = $was_deferred;
		}

		// Update firewall status after activating plugin
		$api   = new P_Api( $core );
		$token = $api->get_access_token();
		if ( ! empty( $token ) ) {
			$api->update_firewall_status( [ 'status' => 1 ] );
			$api->update_url( [ 'plugin_url' => get_option( 'siteurl' ) ] );
		} elseif ( $sendSecret ) {
			$secretToken = wp_generate_password( 36, true );
			update_option( 'patchstack_activation_secret', $secretToken );
			update_option( 'patchstack_activation_time', time() + 59 ) ;
		}

		// Immediately send software data to our server to set firewall as enabled.
		// Also immediately download the whitelist file and the firewall rules.
		do_action( 'patchstack_sync_software_and_rules' );
		if ( get_option( 'patchstack_license_free', 0 ) != 1 ) {
			do_action( 'patchstack_post_firewall_rules' );
		}

		// Try to create the mu-plugins folder/file.
		// No need to do this if it already exists.
		if ( file_exists( WPMU_PLUGIN_DIR . '/patchstack.php' ) || file_exists( WPMU_PLUGIN_DIR . '/_patchstack.php' ) || ( defined( 'PS_DISABLE_MU' ) && PS_DISABLE_MU ) ) {
			return;
		}

		// The mu-plugin does not exist, try to create it.
		@include_once ABSPATH . 'wp-admin/includes/file.php';
		$wpfs = WP_Filesystem();

		// Failed to initialize WP_Filesystem.
		if ( ! $wpfs ) {
			return;
		}

		if ( ! is_dir( WPMU_PLUGIN_DIR ) ) {
			wp_mkdir_p( WPMU_PLUGIN_DIR );
		}

		// Failed to create the mu-plugin folder.
		if ( ! is_dir( WPMU_PLUGIN_DIR ) ) {
			return;
		}

		// Create the mu-plugin file in the folder.
		if ( is_writable( WPMU_PLUGIN_DIR ) ) {
			$php = @file_get_contents( trailingslashit( plugin_dir_path( __FILE__ ) ) . 'mu-plugin.php' );
			@file_put_contents( trailingslashit( WPMU_PLUGIN_DIR ) . '_patchstack.php', $php );
		}
	}

	/**
	 * Copy missing settings without replacing a site's current Patchstack configuration.
	 * A partial copy can be retried while WebARX remains active.
	 */
	private function migrate_legacy_options() {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value, autoload FROM $wpdb->options WHERE option_name LIKE %s", $wpdb->esc_like( 'webarx_' ) . '%' ) );
		if ( $wpdb->last_error || ! is_array( $rows ) ) {
			return false;
		}
		try {
			foreach ( $rows as $row ) {
				$name = 'patchstack_' . substr( $row->option_name, strlen( 'webarx_' ) );
				// Copy serialized bytes without loading objects or changing an existing setting.
				if ( $wpdb->query( $wpdb->prepare(
					"INSERT INTO $wpdb->options (option_name, option_value, autoload) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE option_name = option_name",
					$name, $row->option_value, $row->autoload
				) ) === false ) {
					return false;
				}
				wp_cache_delete( $name, 'options' );
			}
		} finally {
			// A partial copy must also be visible to WordPress before a later retry.
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( 'notoptions', 'options' );
		}
		return true;
	}

	/**
	 * Build the required Patchstack tables.
	 *
	 * @param null|string  $ver The version to upgrade to.
	 * @param null|integer $site_id The blog id to perform the upgrades on.
	 * @return bool
	 */
	public function migrate( $ver = null, $site_id = null ) {
		global $wpdb;
		$switched = false;
		if ( $site_id !== null ) {
			if ( ! is_scalar( $site_id ) || ! ctype_digit( (string) $site_id ) || (int) $site_id < 1 ) {
				return false;
			}
			$site_id = (int) $site_id;
			if ( is_multisite() ) {
				if ( ! get_site( $site_id ) ) {
					return false;
				}
				if ( $site_id !== get_current_blog_id() ) {
					switch_to_blog( $site_id );
					$switched = true;
				}
			} elseif ( $site_id !== get_current_blog_id() ) {
				return false;
			}
		}

		try {
			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			$charset_collate = $wpdb->get_charset_collate();
			$prefix = $wpdb->prefix;
			$file = dirname( __FILE__ ) . '/migrations/base.php';
			if ( $ver !== null ) {
				if ( ! is_string( $ver ) || ! preg_match( '/^[0-9]+\.[0-9]+\.[0-9]+$/D', $ver ) ) {
					return false;
				}
				$file = dirname( __FILE__ ) . '/migrations/v' . str_replace( '.', '', $ver ) . '.php';
			}
			if ( ! is_readable( $file ) ) {
				return false;
			}

			// Data migrations must run independently for each site and retry in this request.
			return ( require $file ) !== false;
		} finally {
			if ( $switched ) {
				restore_current_blog();
			}
		}
	}

	/**
	 * Check if the database version of the plugin is running behind.
	 * If so, run the migrations up until the latest version.
	 *
	 * @return bool
	 */
	public function migrate_check() {
		// Only perform migrations if we have any to execute.
		$versions = $this->migration_versions;
		if ( count( $versions ) == 0 ) {
			return true;
		}

		// Get current database version and run the migrations.
		$db_version = (string) get_option( 'patchstack_db_version', '0' );
		foreach ( $versions as $version ) {
			if ( version_compare( $db_version, $version, '<' ) ) {
				if ( ! $this->migrate( $version ) || version_compare( (string) get_option( 'patchstack_db_version', '0' ), $version, '<' ) ) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Queue schema work outside the request serving a visitor.
	 *
	 * @return void
	 */
	public function schedule_migrations() {
		if ( version_compare( (string) get_option( 'patchstack_db_version', '0' ), end( $this->migration_versions ), '>=' ) || (int) get_option( 'patchstack_log_schema_attempts', 0 ) >= 3 ) {
			return;
		}
		if ( ! wp_next_scheduled( 'patchstack_migrate' ) ) {
			// WordPress 5.2 stores a broken entry when the first event of a new site is a single event.
			if ( ! is_array( _get_cron_array() ) ) {
				_set_cron_array( [] );
			}
			$when = max( time() + 10, (int) get_option( 'patchstack_log_schema_retry_after', 0 ), (int) get_option( 'patchstack_log_schema_lock', 0 ) );
			wp_schedule_single_event( $when, 'patchstack_migrate' );
		}
	}

	public function run_scheduled_migrations() {
		global $wpdb;
		try {
			$attempts = (int) get_option( 'patchstack_log_schema_attempts', 0 );
			if ( $attempts >= 3 || (int) get_option( 'patchstack_log_schema_retry_after', 0 ) > time() ) {
				return;
			}
			// Network activation does not run the activation hook separately for each site.
			$missing = false;
			foreach ( [ 'patchstack_firewall_log', 'patchstack_event_log', 'patchstack_logic' ] as $table ) {
				if ( ! $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $wpdb->prefix . $table ) ) ) ) {
					$missing = true;
					break;
				}
			}
			if ( $missing && ! $this->migrate() ) {
				update_option( 'patchstack_log_schema_attempts', $attempts + 1, false );
				update_option( 'patchstack_log_schema_retry_after', time() + 5 * MINUTE_IN_SECONDS, false );
				return;
			}
			// Settings introduced since a connected site last activated its license have no row yet,
			// and a missing row costs a query on every request that reads it.
			if ( $this->migrate_check() && get_option( 'patchstack_clientid', '' ) != '' ) {
				$options = is_a( $this->plugin, 'patchstack' ) || isset( $this->plugin->admin_options ) ? $this->plugin->admin_options : null;
				if ( $options ) {
					$options->settings_init();
				}
			}
		} finally {
			$this->schedule_migrations();
		}
	}

	public function migration_notice() {
		if ( ! current_user_can( 'manage_options' ) || version_compare( (string) get_option( 'patchstack_db_version', '0' ), end( $this->migration_versions ), '>=' ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p>';
		if ( get_option( 'patchstack_log_schema_attempts', 0 ) ) {
			echo esc_html__( 'Patchstack could not finish updating its log tables. Logging may be affected. Automatic retries stop after three attempts. Please ask your host to check database permissions, free disk space, and conflicting indexes before retrying.', 'patchstack' );
		} else {
			echo esc_html__( 'Patchstack has a pending log database update. It runs through WordPress cron, or you can run it manually below.', 'patchstack' );
		}
		echo ' <a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=patchstack_retry_migration' ), 'patchstack-retry-migration' ) ) . '">' . esc_html__( 'Run database update', 'patchstack' ) . '</a></p></div>';
	}

	public function retry_migration() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to update this database.', 'patchstack' ) );
		}
		check_admin_referer( 'patchstack-retry-migration' );
		delete_option( 'patchstack_log_schema_attempts' );
		delete_option( 'patchstack_log_schema_retry_after' );
		wp_clear_scheduled_hook( 'patchstack_migrate' );
		$this->run_scheduled_migrations();
		wp_safe_redirect( admin_url() );
		exit;
	}

	/**
	 * Perform cleanup when the plugin is deactivated.
	 *
	 * @return void
	 */
	public function deactivate( $network_wide = false ) {
		wp_clear_scheduled_hook( 'patchstack_migrate' );
		// Update firewall status after de-activating plugin
		try {
			$token = $this->plugin->api->get_access_token();
			if ( ! empty( $token ) ) {
				$this->plugin->api->update_firewall_status( [ 'status' => 0 ] );
			}
		} catch (\Exception $e) {
			//
		}

		// Clear all Patchstack scheduled tasks.
		$tasks = [ 'patchstack_retry_software_upload', 'patchstack_zip_backup', 'patchstack_send_software_data', 'patchstack_send_hacker_logs', 'patchstack_send_visitor_logs', 'patchstack_send_event_logs', 'patchstack_reset_blocked_attacks', 'patchstack_post_firewall_rules', 'patchstack_post_firewall_htaccess_rules', 'patchstack_post_dynamic_firewall_rules', 'patchstack_update_license_status', 'patchstack_update_plugins', 'patchstack_send_ping', 'patchstack_check_env', 'puc_cron_check_updates-webarx' ];
		foreach ( $tasks as $task ) {
			wp_clear_scheduled_hook( $task );
		}

		// Shared files must outlive any other active site or network.
		if ( is_multisite() && ( ! $this->controls_auto_prepend() || $this->has_other_active_sites( $network_wide ) ) ) {
			return;
		}

		// Cleanup the .htaccess file.
		$this->plugin->htaccess->cleanup_htaccess_file();
		$this->auto_prepend_removal();

		// Remove the mu-plugin file if it exists.
		foreach (['patchstack.php', '_patchstack.php'] as $file) {
			if ( file_exists( WPMU_PLUGIN_DIR . '/' . $file )) {
				wp_delete_file( WPMU_PLUGIN_DIR . '/' . $file );
			}
		}
	}

	/**
	 * Activate or deactivate a license on the current site.
	 *
	 * @param integer $id
	 * @param string  $secret
	 * @param string  $action
	 * @return array
	 */
	public function alter_license( $id, $secret, $action ) {
		// Set default options in case they have not been set yet.
		$this->plugin->admin_options->settings_init();

		// Store current keys in tmp variable so in case it fails, we can set it back.
		$tmp_id  = get_option( 'patchstack_clientid' );
		$tmp_key = $this->get_secret_key();

		// Set the new values.
		update_option( 'patchstack_clientid', $id );
		$this->set_secret_key( $secret );

		// Activate the license.
		if ( $action == 'activate' ) {
			$api_result = $this->plugin->api->get_access_token( $id, $secret, true );

			// Valid result?
			if ( ! $api_result ) {
				update_option( 'patchstack_clientid', $tmp_id );
				$this->set_secret_key( $tmp_key );

				return [
					'result'  => 'error',
					'body' => json_encode($this->plugin->api->message),
					'message' => 'Cannot activate license!',
				];
			}

			// Successfully activated.
			update_option( 'patchstack_license_activated', '1', true );

			// Update license status and fetch policy settings.
			$fetchPolicy = (int) get_option( 'patchstack_last_license_check', 0 ) == 0;
			$this->plugin->api->update_license_status( $fetchPolicy );

			// Perform post-activation actions, incl. access token retrieval.
			$token = $this->plugin->api->get_access_token();
			if ( ! empty( $token ) ) {

				// Immediately send software data to our server to set firewall as enabled.
				// Also immediately download the whitelist file and the firewall rules.
				if ( ! $this->defer_license_sync ) {
					do_action( 'patchstack_sync_software_and_rules' );
				}
				if ( get_option( 'patchstack_license_free', 0 ) != 1 ) {
					update_option( 'patchstack_basic_firewall', 1, true );
					if ( ! $this->defer_license_sync ) {
						do_action( 'patchstack_post_firewall_rules' );
					}
					$this->header();
				}

				// Update firewall status, URL and ping API.
				$this->plugin->api->update_firewall_status( [ 'status' => $this->get_option( 'patchstack_basic_firewall' ) == 1 ] );
				$this->plugin->api->update_url( [ 'plugin_url' => get_option( 'siteurl' ) ] );
				$this->auto_prepend_injection();
			}

			return [
				'result'  => 'success',
				'message' => 'License activated!',
			];
		}

		// Deactivate the license.
		if ( $action == 'deactivate' ) {
			update_option( 'patchstack_api_token', '' );
			update_option( 'patchstack_license_activated', '0' );
			update_option( 'patchstack_clientid', '' );
			update_option( 'patchstack_secretkey', '' );
			update_option( 'patchstack_secretkey_nonce', '' );

			$this->auto_prepend_removal();
	
			return [
				'result'  => 'success',
				'message' => 'License deactivated!',
			];
		}
	}

	/**
	 * Send a request to our API for the IP address header.
	 * 
	 * @return void
	 */
	public function header()
	{
		$header = get_option( 'patchstack_firewall_ip_header', '' );
		$computed = get_option( 'patchstack_ip_header_computed', 0 );
		$force = get_option( 'patchstack_ip_header_force_compute', 0 );

		if ( ( $header == '' && ! $computed ) || $force ) {
			// Create an OTT token.
			$ott = md5( wp_generate_password( 32, true, true ) );
			update_option( 'patchstack_ott_action', $ott );
	
			// Tell our API.
			wp_remote_request(
				$this->plugin->api_url . '/api/header',
				[
					'method'      => 'POST',
					'timeout'     => 60,
					'redirection' => 5,
					'httpversion' => '1.0',
					'blocking'    => true,
					'headers'     => [
						'Source-Host'   => get_site_url(),
					],
					'body'        => [
						'token' => $ott,
						'url' => get_site_url()
					],
					'cookies'     => [],
				]
			);
		}
	}

	/**
	 * The auto-prepend files are shared by every site in a network, so only its primary site
	 * installs or removes them. The filter can name another blog that may.
	 *
	 * @return bool
	 */
	private function controls_auto_prepend() {
		return ! is_multisite() || ( is_main_network() && is_main_site() )
			|| apply_filters( 'patchstack_allow_network_remote_management', false, get_current_blog_id(), 'patchstack_firewall_ap_enabled' );
	}

	/**
	 * Create the environment needed for the auto prepend firewall functionality.
	 * 1. First we check if an auto_prepend_file already exists somewhere.
	 * 2. Then we write to the .htaccess file and check its status code.
	 * 3. Then we write to the .user.ini file and check its status code, .user.ini is optional if there are any errors with it.
	 * 
	 * @param boolean $refresh
	 * @return boolean
	 */
	public function auto_prepend_injection($refresh = false)
	{
		$controls_files = $this->controls_auto_prepend();
		$config_path = WP_CONTENT_DIR . '/pslogs/config.php';
		if ( ! $controls_files ) {
			// The shared loader reads this file even on subsites that never enabled the local installer.
			if ( ! $refresh || ! $this->has_auto_prepend_config( $config_path ) ) {
				return;
			}
		} elseif ( ! get_option( 'patchstack_firewall_ap_enabled', false ) ) {
			return;
		}

		// No need to display this error if the .htaccess functionality has been disabled.
		if ( get_option( 'patchstack_disable_htaccess', 0 ) || ( defined( 'PS_DISABLE_HTACCESS' ) && PS_DISABLE_HTACCESS ) || ( defined( 'PS_DISABLE_MU' ) && PS_DISABLE_MU ) ) {
			return;
		}

		// Refreshing an installed config must not retry changes to the server configuration.
		if ( $refresh && $this->has_auto_prepend_config( $config_path ) ) {
			return $this->refresh_auto_prepend_config();
		}

		if ( get_option( 'patchstack_firewall_ap_error', '' ) != '' ) {
			return;
		}

		global $wp_filesystem;
		if ( ! $this->get_filesystem( $controls_files ? ABSPATH : dirname( $config_path ) ) ) {
			update_option( 'patchstack_firewall_ap_error', 'Could not establish filesystem.' );
			return false;
		}
		if ( ! $controls_files ) {
			return $this->has_auto_prepend_config( $config_path ) && $this->write_auto_prepend_config( $config_path );
		}

		// First ensure a .htaccess file exists, otherwise no point.
		$htaccess_file = ABSPATH . '.htaccess';
		if ( ! $wp_filesystem->exists( $htaccess_file ) && ! $wp_filesystem->touch( $htaccess_file ) ) {
			update_option( 'patchstack_firewall_ap_error', 'The .htaccess file could be found nor created.' );
			return false;
		}

		// Completely halt if there is already an auto_prepend_file present in .htaccess and not of Patchstack.
		$htaccess_content = $wp_filesystem->get_contents( $htaccess_file );
		if ( stripos( $htaccess_content, 'auto_prepend_file' ) !== false && stripos( $htaccess_content, 'mu-plugin-ap.php' ) === false ) {
			update_option( 'patchstack_firewall_ap_error', 'A different auto_prepend_file value is already present in the .htaccess file.' );
			return false;
		}

		// Completely halt if there is already an auto_prepend_file present in .user.ini and not of Patchstack.
		$user_ini = ini_get( 'user_ini.filename' );
		if ( $user_ini && $wp_filesystem->exists( ABSPATH . $user_ini ) ) {
			$ini_content = $wp_filesystem->get_contents( ABSPATH . $user_ini );
			if ( stripos( $ini_content, 'auto_prepend_file' ) !== false && stripos( $ini_content, 'mu-plugin-ap.php' ) === false ) {
				update_option( 'patchstack_firewall_ap_error', 'A different auto_prepend_file value is already present in the .user.ini file.' );
				return false;
			}
		}

		// Determine if we can write the /wp-content/pslogs/ folder.
		$logs_dir = WP_CONTENT_DIR . '/pslogs/';
		if ( ! $wp_filesystem->exists( $logs_dir ) && ! $wp_filesystem->mkdir( $logs_dir ) ) {
			update_option( 'patchstack_firewall_ap_error', 'The path ' . $logs_dir . ' could not be created.' );
			return false;
		}

		// Create the blank index.php file.
		if ( ! $wp_filesystem->exists( $logs_dir . 'index.php' ) && ! $wp_filesystem->put_contents( $logs_dir . 'index.php', '' ) ) {
			update_option( 'patchstack_firewall_ap_error', 'The file ' . $logs_dir . 'index.php could not be created.' );
			return false;
		}

		// Create the logs.php file.
		if ( ! $wp_filesystem->exists( $logs_dir . 'logs.php' ) && ! $wp_filesystem->put_contents( $logs_dir . 'logs.php', '<?php exit; ?>' . PHP_EOL ) ) {
			update_option( 'patchstack_firewall_ap_error', 'The file ' . $logs_dir . 'logs.php could not be created.' );
			return false;
		}

		if ( ! $this->write_auto_prepend_config( $config_path ) ) {
			return false;
		}

		// In case we only want to refresh the auto prepend rules, we stop here.
		if ( $refresh ) {
			return true;
		}

		// Prepare the rules to inject into .htaccess.
		$prepend_rules = $this->get_auto_prepend_rules();
		if ( ! $prepend_rules ) {
			return false;
		}

		// Determine if the rules already exist and overwrite them in case of path change.
		$original_htaccess = $htaccess_content;
		$re = '/# BEGIN AP Patchstack.*?# END AP Patchstack/is';
		if ( preg_match( $re, $htaccess_content ) ) {
			$htaccess_content = preg_replace( $re, rtrim($prepend_rules['htaccess']), $htaccess_content );
		} else {
			$htaccess_content .= "\n" . $prepend_rules['htaccess'];
		}

		// Attempt to write to the .htaccess file.
		if ( ! $wp_filesystem->put_contents( $htaccess_file, $htaccess_content ) ) {
			update_option( 'patchstack_firewall_ap_error', 'Could not inject into the .htaccess file.' );
			return false;
		}

		// Determine if the site still works as expected with the injected htaccess rules.
		if ( $this->get_site_status_code() >= 400 ) {
			$wp_filesystem->put_contents( $htaccess_file, $original_htaccess );
			update_option( 'patchstack_firewall_ap_error', 'The .htaccess rules caused a fatal internal server error.' );
			return false;
		}

		// Ensure a .user.ini is present.
		$user_ini = ini_get( 'user_ini.filename' );
		if ( ! $user_ini ) {
			update_option( 'patchstack_firewall_ap_error', '' );
			return true;
		}

		// Define full path to the .user.ini file.
		$user_ini = ABSPATH . $user_ini;

		// Create the file if it does not exist.
		if ( ! $wp_filesystem->exists( $user_ini ) && ! $wp_filesystem->touch( $user_ini ) ) {
			update_option( 'patchstack_firewall_ap_error', 'The .user.ini file could not be created.' );
			return true;
		}
		
		// Get the contents of the current .user.ini file.
		$ini_content = $wp_filesystem->get_contents( $user_ini );

		// Determine if the rules already exist and overwrite them in case of path change.
		$original_ini = $ini_content;
		$re = '/; BEGIN AP Patchstack.*?; END AP Patchstack/is';
		if ( preg_match( $re, $ini_content ) ) {
			$ini_content = preg_replace( $re, rtrim($prepend_rules['ini']), $ini_content );
		} else {
			$ini_content .= "\n" . $prepend_rules['ini'];
		}

		// Attempt to write to the .user.ini file.
		if ( ! $wp_filesystem->put_contents( $user_ini, $ini_content ) ) {
			update_option( 'patchstack_firewall_ap_error', 'Could not inject into the .user.ini file.' );
			return true;
		}

		// Determine if the site still works as expected with the injected .user.ini rules.
		if ( $this->get_site_status_code() == 500 ) {
			$wp_filesystem->put_contents( $user_ini, $original_ini );
			update_option( 'patchstack_firewall_ap_error', 'The .user.ini rules caused a fatal internal server error.' );
			return false;
		}

		update_option( 'patchstack_firewall_ap_error', '' );
		return true;
	}

	private function has_other_active_sites( $network_wide ) {
		if ( is_file( WPMU_PLUGIN_DIR . '/patchstack/patchstack.php' ) ) {
			return true;
		}
		foreach ( $this->get_sites() as $site ) {
			$network_plugins = get_network_option( $site->site_id, 'active_sitewide_plugins', [] );
			if ( ( ! $network_wide || (int) $site->site_id !== get_current_network_id() ) && isset( $network_plugins[$this->plugin->basename] ) ) {
				return true;
			}
			if ( ( $network_wide || (int) $site->id !== get_current_blog_id() ) && in_array( $this->plugin->basename, (array) get_blog_option( $site->id, 'active_plugins', [] ), true ) ) {
				return true;
			}
		}
		return false;
	}

	public function refresh_auto_prepend_config() {
		$config_path = WP_CONTENT_DIR . '/pslogs/config.php';
		if ( $this->has_auto_prepend_config( $config_path ) && $this->get_filesystem( dirname( $config_path ) ) ) {
			return $this->write_auto_prepend_config( $config_path );
		}
		return false;
	}

	/**
	 * Whether the auto-prepend config is installed. The backup stands in for a config whose
	 * replacement over SFTP was cut off, so the next refresh can finish it.
	 *
	 * @param string $config_path
	 * @return boolean
	 */
	private function has_auto_prepend_config( $config_path ) {
		return is_file( $config_path ) || is_file( dirname( $config_path ) . '/config.backup.php' );
	}

	private function write_auto_prepend_config( $config_path ) {
		global $wp_filesystem;

		$sites = $this->get_sites();
		$data = [];
		foreach ($sites as $site) {
			$switched = is_multisite() && get_current_blog_id() != $site->id;
			if ( $switched ) {
				$this->switch_to_blog( $site->id );
			}
			try {
				$network_plugins = is_multisite() ? get_network_option( $site->site_id, 'active_sitewide_plugins', [] ) : [];
				$active = is_file( WPMU_PLUGIN_DIR . '/patchstack/patchstack.php' )
					|| in_array( $this->plugin->basename, (array) get_option( 'active_plugins', [] ), true )
					|| isset( $network_plugins[$this->plugin->basename] );
				$data[] = [
					'site_id' => $site->id,
					'site_url' => preg_replace( '/^https?:\/\//i', '', $site->siteurl ),
					'home_url' => preg_replace( '/^https?:\/\//i', '', get_option( 'home' ) ),
					'patchstack_basic_firewall' => $active ? get_option( 'patchstack_basic_firewall', 1 ) : 0,
					'patchstack_license_activated' => get_option( 'patchstack_license_activated', 0 ),
					'patchstack_license_free' => get_option( 'patchstack_license_free', 0 ),
					'patchstack_firewall_ip_header' => get_option( 'patchstack_firewall_ip_header', '' ),
					'patchstack_log_redaction' => get_option( 'patchstack_log_redaction', 0 ),
					'patchstack_firewall_rules_v3_ap' => base64_encode( get_option( 'patchstack_firewall_rules_v3_ap', '[]' ) )
				];
			} finally {
				// Preserve any existing switches owned by the caller, including syncs.
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}

		$content = '<?php return ' . var_export( $data, true ) . ';';
		$temp_path = $config_path . '.' . uniqid( '', true ) . '.php';
		$written = $wp_filesystem->put_contents( $temp_path, $content )
			&& $wp_filesystem->get_contents( $temp_path ) === $content;
		if ( $written ) {
			// Direct and SSH2 move wrappers may delete the destination before replacement succeeds.
			if ( $wp_filesystem->method === 'direct' ) {
				$written = @rename( $temp_path, $config_path );
			} elseif ( $wp_filesystem->method === 'ssh2' ) {
				$written = $this->replace_over_sftp( $wp_filesystem->sftp_link, $temp_path, $config_path );
			} else {
				$written = $wp_filesystem->move( $temp_path, $config_path, true );
			}
		}
		if ( ! $written ) {
			$wp_filesystem->delete( $temp_path );
			update_option( 'patchstack_firewall_ap_error', 'The file ' . $config_path . ' could not be created.' );
			return false;
		}

		// The live config is complete again, so a backup from an unfinished replacement can go.
		$backup_path = dirname( $config_path ) . '/config.backup.php';
		if ( $wp_filesystem->exists( $config_path ) && $wp_filesystem->exists( $backup_path ) ) {
			$wp_filesystem->delete( $backup_path );
		}

		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $config_path, true );
		}
		// A config write resolves filesystem errors, but cannot resolve installation errors.
		if ( in_array( get_option( 'patchstack_firewall_ap_error', '' ), [
			'Could not establish filesystem.',
			'Unable to establish filesystem connection.',
			'Unable to establish filesystem connection through acquired creds.',
			'The file ' . $config_path . ' could not be created.',
		], true ) ) {
			update_option( 'patchstack_firewall_ap_error', '' );
		}
		return true;
	}

	/**
	 * Put a prepared file in place of the live one over SFTP. An SFTP rename does not overwrite
	 * an existing file, so the live file steps aside under its backup name first and returns if
	 * the swap fails. The loader reads the backup while the live file is missing, so a complete
	 * config stays readable even when the connection drops halfway; the next refresh finishes
	 * the replacement.
	 *
	 * @param resource $sftp
	 * @param string $temp_path
	 * @param string $path
	 * @return boolean
	 */
	private function replace_over_sftp( $sftp, $temp_path, $path ) {
		// Nothing to step aside on a first installation or after an attempt that was cut off,
		// or the server overwrites on rename.
		if ( @ssh2_sftp_rename( $sftp, $temp_path, $path ) ) {
			return true;
		}

		// With the live file missing or out of reach, a backup is the only complete config
		// and has to stay. Next to a live file it is a leftover of an earlier attempt.
		$backup_path = dirname( $path ) . '/config.backup.php';
		if ( ! @ssh2_sftp_stat( $sftp, $path ) ) {
			return false;
		}
		@ssh2_sftp_unlink( $sftp, $backup_path );
		if ( ! @ssh2_sftp_rename( $sftp, $path, $backup_path ) ) {
			return false;
		}

		if ( @ssh2_sftp_rename( $sftp, $temp_path, $path ) ) {
			return true;
		}

		@ssh2_sftp_rename( $sftp, $backup_path, $path );
		return false;
	}

	/**
	 * Remove everything related to the auto prepend functionality.
	 * 
	 * @return boolean
	 */
	public function auto_prepend_removal()
	{
		if ( ! $this->controls_auto_prepend() ) {
			return;
		}

		global $wp_filesystem;
		if ( ! $this->get_filesystem() ) {
			return false;
		}

		// Define our paths to access.
		$logs_dir = WP_CONTENT_DIR . '/pslogs/';
		$htaccess_file = ABSPATH . '.htaccess';
		$ini_file = ABSPATH . '.user.ini';

		// Remove the entire /pslogs/ directory.
		if ( $wp_filesystem->is_dir( $logs_dir ) ) {
			$wp_filesystem->delete( $logs_dir, true );
		}

		// Remove the .htaccess injected rules.
		if ( $wp_filesystem->is_file( $htaccess_file ) ) {
			$htaccess_content = $wp_filesystem->get_contents( $htaccess_file );
			$re = '/# BEGIN AP Patchstack.*?# END AP Patchstack/is';
			if ( preg_match( $re, $htaccess_content ) ) {
				$htaccess_content = preg_replace( $re, '', $htaccess_content );
				$wp_filesystem->put_contents( $htaccess_file, $htaccess_content );
			}
		}

		// Remove the .user.ini injected rules.
		if ( $wp_filesystem->is_file( $ini_file ) ) {
			$ini_content = $wp_filesystem->get_contents( $ini_file );
			$re = '/; BEGIN AP Patchstack.*?; END AP Patchstack/is';
			if ( preg_match( $re, $ini_content ) ) {
				$ini_content = preg_replace( $re, '', $ini_content );
				$wp_filesystem->put_contents( $ini_file, $ini_content );
			}
		}
	}

	/**
	 * Attempt to establish the proper WP_FileSystem.
	 * 
	 * @return boolean
	 */
	private function get_filesystem( $context = ABSPATH )
	{
		// Seems to be the only native way to obtain FTP credentials, if defined.
		include_once( ABSPATH . 'wp-admin/includes/file.php' );
		ob_start();
		$creds = request_filesystem_credentials( admin_url( 'admin-ajax.php' ), '', false, $context, null, true );
		ob_end_clean();

		// Returns false if no filesystem connection could be determined.
		if ( $creds === false ) {
			update_option( 'patchstack_firewall_ap_error', 'Unable to establish filesystem connection.' );
			return false;
		}

		// Attempt to initialize it.
		$fs = WP_Filesystem( $creds, $context, true );
		if ( ! $fs ) {
			update_option( 'patchstack_firewall_ap_error', 'Unable to establish filesystem connection through acquired creds.' );
			return false;
		}

		return true;
	}

	/**
	 * Get sites as part of the environment.
	 * 
	 * @return array
	 */
	private function get_sites()
	{
		if ( ! function_exists( 'get_sites' ) ) {
			return [
				(object) [
					'id' => 0,
					'siteurl' => get_site_url()
				]
			];
		}

		return get_sites( [ 'number' => 0 ] );
	}

	/**
	 * Switch to a different site.
	 * 
	 * @param integer $site_id
	 * @return void
	 */
	private function switch_to_blog($site_id)
	{
		if ( ! function_exists( 'switch_to_blog' ) ) {
			return;
		}

		switch_to_blog( $site_id );
	}

	/**
	 * Determine the web-server software and make sure we support it before we generate the .htaccess rules for it.
	 * 
	 * @return array|boolean
	 */
	private function get_auto_prepend_rules()
	{
		// Establish location of the auto prepend file.
		$mu_file = __DIR__ . '/mu-plugin-ap.php';
		if ( ! file_exists( $mu_file ) ) {
			return false;
		}

		// Ensure that the SERVER_SOFTWARE value is set.
		$software = isset( $_SERVER['SERVER_SOFTWARE'] ) ? $_SERVER['SERVER_SOFTWARE'] : '';
		if ( ! $software ) {
			update_option( 'patchstack_firewall_ap_error', 'Unsupported SERVER_SOFTWARE, found: ' . $software );
			return false;
		}

		// At this time, reject non-Apache environments.
		$sapi = function_exists( 'php_sapi_name' ) ? php_sapi_name() : false;
		if ( ! $sapi || stripos( $_SERVER['SERVER_SOFTWARE'], 'litespeed' ) === false && $sapi != 'litespeed' && stripos($_SERVER['SERVER_SOFTWARE'], 'apache' ) === false) {
			update_option( 'patchstack_firewall_ap_error', 'Unsupported SERVER_SOFTWARE, found: ' . $_SERVER['SERVER_SOFTWARE'] . ' and ' . $sapi );
			return false;
		}

		// Seperate flag for LiteSpeed.
		$is_litespeed = stripos( $_SERVER['SERVER_SOFTWARE'], 'litespeed' ) !== false || $sapi == 'litespeed';

		// Attempt to find the Apache version, < 2.4 does not support <If>.
		// This depends on ServerTokens value, so only stop execution if we can't find the specific unsupported versions.
		$version = function_exists( 'apache_get_version' ) ? apache_get_version() : $software;
		if ( ! $is_litespeed && stripos( $version, 'Apache/2.4' ) === false ) {
			update_option( 'patchstack_firewall_ap_error', 'Unsupported SERVER_SOFTWARE, found: ' . $software );
			return false;
		}

		// Add c-style slashes.
		$mu_file_as = wp_normalize_path(addcslashes($mu_file, "'"));

		// Bit different rules for LiteSpeed.
		if ( ! $is_litespeed ) {
			$rules = "<IfModule mod_php.c>
      php_value auto_prepend_file '" . $mu_file_as . "'
    </IfModule>
    <IfModule mod_php5.c>
      php_value auto_prepend_file '" . $mu_file_as . "'
    </IfModule>
    <IfModule mod_php7.c>
      php_value auto_prepend_file '" . $mu_file_as . "'
    </IfModule>";
		} else {
			$rules = "<IfModule LiteSpeed>
      php_value auto_prepend_file '" . $mu_file_as . "'
    </IfModule>
    <IfModule lsapi_module>
      php_value auto_prepend_file '" . $mu_file_as . "'
    </IfModule>";
		}

		return [
			'htaccess' => "# BEGIN AP Patchstack
<IfModule mod_authz_core.c>
	<If \"-f '" . $mu_file_as . "'\">
		" . $rules . "

		<Files \".user.ini\">
		<IfModule mod_authz_core.c>
			Require all denied
		</IfModule>
		<IfModule !mod_authz_core.c>
			Order deny,allow
			Deny from all
		</IfModule>
		</Files>
	</If>
</IfModule>
# END AP Patchstack
",
			'ini' => "; BEGIN AP Patchstack
auto_prepend_file = '" . $mu_file_as . "'
; END AP Patchstack
"
		];
	}

	/**
	 * Retrieve the status code of the site.
	 * This is done to determine if the .htaccess rules do not trigger an error.
	 *
	 * @return integer
	 */
	public function get_site_status_code() {
		$response = wp_remote_get( get_site_url() );
		$http_code = wp_remote_retrieve_response_code( $response );
		return $http_code;
	}

	/**
	 * If option is updated, refresh AP config file.
	 *
	 * @param string $option_name
	 * @param string $option_name
	 * @param mixed  $value
	 * @return void
	 */
	public function updated_option( $option_name, $old_value, $value ) {
		if ( $option_name === 'active_plugins' ) {
			if ( in_array( $this->plugin->basename, (array) $old_value, true ) !== in_array( $this->plugin->basename, (array) $value, true ) ) {
				$this->refresh_auto_prepend_config();
			}
			return;
		}
		// Only allow to run for our options. The IP header is embedded in the AP config
		// file too, so a change there must also regenerate it.
		if ( !in_array( $option_name, [ 'patchstack_basic_firewall', 'patchstack_license_activated', 'patchstack_license_free', 'patchstack_firewall_rules_v3_ap', 'patchstack_firewall_ip_header', 'patchstack_log_redaction' ] ) ) {
			return;
		}

		// Not strict type matching.
		if ( $old_value == $value ) {
			return;
		}

		$this->auto_prepend_injection(true);
	}

	/**
	 * A site's initial license or redaction setting may be added after its shared config was written.
	 *
	 * @param string $option_name
	 * @param mixed  $value
	 * @return void
	 */
	public function added_option( $option_name, $value ) {
		if ( ! in_array( $option_name, [ 'patchstack_log_redaction', 'patchstack_license_activated', 'active_plugins' ], true ) ) {
			return;
		}

		$this->updated_option( $option_name, 0, $value );
	}
}
