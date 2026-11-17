<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to upload the local logs to our API so it can
 * be shown on the app.
 */
class P_Upload extends P_Core {

	/**
	 * Software-change notifications awaiting a final inventory upload, per blog.
	 *
	 * @var array
	 */
	private $pending_software_uploads = [];

	/**
	 * Blogs whose explicit resync will pull rules after all software callbacks.
	 *
	 * @var array
	 */
	private $deferred_rule_refreshes = [];

	private $flushing_software_upload = false;

	private $software_change_hooks = [ 'activated_plugin', 'deactivated_plugin', 'deleted_plugin', 'upgrader_process_complete', '_core_updated_successfully' ];

	/**
	 * Add the actions required to upload logs to our API.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		if ( property_exists( $core, 'upload' ) && $core->upload instanceof P_Upload ) {
			return;
		}
		if ( get_option( 'patchstack_software_upload_pending', false ) ) {
			$this->schedule_software_retry();
		}

		// In case the software has never been synchronized, force it.
		if ( ! get_option( 'patchstack_software_data_hash', false ) && ! get_option( 'patchstack_software_upload_attempted', false ) ) {
			$this->upload_software();
		}

		// Register the actions.
		add_action( 'patchstack_send_software_data', [ $this, 'upload_software' ], 10, 0 );
		add_action( 'patchstack_sync_software_and_rules', [ $this, 'sync_software_and_rules' ], 10, 0 );
		add_action( 'patchstack_retry_software_upload', [ $this, 'retry_software_upload' ], 10, 0 );
		add_action( 'shutdown', [ $this, 'flush_software_uploads' ], PHP_INT_MAX );
		add_action( 'patchstack_send_hacker_logs', [ $this, 'upload_firewall_logs' ] );
		add_action( 'patchstack_send_event_logs', [ $this, 'upload_activity_logs' ] );
		add_action( 'patchstack_import_ap_logs', [ $this, 'import_ap_logs' ] );
		add_action( 'wp_scheduled_delete', [ $this, 'expire_undelivered_logs' ] );

		// In case a plugin or upgrade has been performed, re-synchronize with the app.
		foreach ( $this->software_change_hooks as $hook ) {
			add_action( $hook, [ $this, 'upload_software' ], 10, 0 );
		}
	}

	/**
	 * Coalesce automatic change hooks until the operation has its final inventory.
	 * Explicit sync actions still run immediately and consume this pending work.
	 *
	 * @return void
	 */
	public function queue_software_upload() {
		// Nothing can be delivered before the site is connected, and connecting synchronizes it.
		if ( ! get_option( 'patchstack_clientid', false ) ) {
			return;
		}

		$pending = uniqid( '', true );
		$this->pending_software_uploads[ get_current_blog_id() ] = $pending;
		update_option( 'patchstack_software_upload_pending', $pending, false );

		// A new change is tried soon, even when earlier failures pushed the retry further out.
		if ( get_option( 'patchstack_software_upload_retries', 0 ) ) {
			delete_option( 'patchstack_software_upload_retries' );
			wp_clear_scheduled_hook( 'patchstack_retry_software_upload' );
		}
		$this->schedule_software_retry();
	}

	private function schedule_software_retry( $delay = 300 ) {
		if ( ! wp_next_scheduled( 'patchstack_retry_software_upload' ) ) {
			wp_schedule_single_event( time() + $delay, 'patchstack_retry_software_upload' );
		}
	}

	public function retry_software_upload() {
		$pending = get_option( 'patchstack_software_upload_pending', false );
		if ( ! $pending ) {
			return;
		}

		// A site that is not connected has nowhere to deliver to; do not keep a retry running.
		if ( ! get_option( 'patchstack_clientid', false ) ) {
			delete_option( 'patchstack_software_upload_pending' );
			delete_option( 'patchstack_software_upload_retries' );
			return;
		}

		$this->pending_software_uploads[ get_current_blog_id() ] = $pending;
		// Schedule before attempting HTTP so a timeout or fatal error leaves a retry. Each
		// failure doubles the wait, from five minutes up to six hours.
		$retries = (int) get_option( 'patchstack_software_upload_retries', 0 );
		update_option( 'patchstack_software_upload_retries', $retries + 1, false );
		$this->schedule_software_retry( (int) min( 21600, 300 * pow( 2, min( $retries, 7 ) ) ) );
		$this->flush_software_uploads();
	}

	/**
	 * Failures and changes to an already attempted blog remain in the durable queue.
	 * Other blogs, including those queued by callbacks, can still finish this request.
	 *
	 * @return void
	 */
	public function flush_software_uploads() {
		$attempted = [];
		while ( $blogs = array_diff( array_keys( $this->pending_software_uploads ), $attempted ) ) {
			$blog_id = reset( $blogs );
			$attempted[] = $blog_id;
			$switched = get_current_blog_id() != $blog_id;
			if ( $switched ) {
				switch_to_blog( $blog_id );
			}
			$was_flushing = $this->flushing_software_upload;
			$this->flushing_software_upload = true;
			try {
				$this->upload_software();
			} catch ( Exception $error ) {
				// The persisted marker and cron event retain this blog for a later attempt.
			} catch ( Throwable $error ) {
				// PHP 7+ errors must not stop uploads for the other blogs either.
			} finally {
				$this->flushing_software_upload = $was_flushing;
				if ( $switched ) {
					restore_current_blog();
				}
			}
		}
	}

	private function complete_software_upload( $blog_id, $pending ) {
		if ( isset( $this->pending_software_uploads[ $blog_id ] ) && $this->pending_software_uploads[ $blog_id ] === $pending ) {
			unset( $this->pending_software_uploads[ $blog_id ] );
		}
		if ( $pending ) {
			global $wpdb;
			// Compare in the database: this request's option cache may hold an older generation.
			$wpdb->delete( $wpdb->options, [
				'option_name' => 'patchstack_software_upload_pending',
				'option_value' => $pending,
			] );
			wp_cache_delete( 'patchstack_software_upload_pending', 'options' );
			delete_option( 'patchstack_software_upload_retries' );
			// A newer request may share the retry event; it exits without HTTP when no work remains.
		}
	}

	/**
	 * Activation and manual resync always request rules after uploading software.
	 * Suppress the upload's conditional rule pull so this operation sends only one.
	 *
	 * @return void
	 */
	public function sync_software_and_rules() {
		$blog_id = get_current_blog_id();
		$already_deferred = isset( $this->deferred_rule_refreshes[ $blog_id ] );
		$api_blog_id = $this->plugin->api->blog_id;
		$this->deferred_rule_refreshes[ $blog_id ] = true;
		$this->plugin->api->blog_id = $blog_id;
		try {
			// Keep the existing public action available to integration callbacks.
			do_action( 'patchstack_send_software_data' );
			if ( ! $already_deferred ) {
				do_action( 'patchstack_post_dynamic_firewall_rules' );
			}
		} finally {
			$this->plugin->api->blog_id = $api_blog_id;
			if ( ! $already_deferred ) {
				unset( $this->deferred_rule_refreshes[ $blog_id ] );
			}
		}
	}

	/**
	 * Synchronize the software data with our API.
	 * This includes plugins, themes, WordPress and PHP version.
	 *
	 * @return void|array
	 */
	public function upload_software() {
		if ( in_array( current_filter(), $this->software_change_hooks, true ) ) {
			$this->queue_software_upload();
			return;
		}
		$api_blog_id = $this->plugin->api->blog_id;
		$this->plugin->api->blog_id = get_current_blog_id();
		try {
			return $this->upload_current_software();
		} finally {
			$this->plugin->api->blog_id = $api_blog_id;
		}
	}

	/**
	 * Upload using the current blog's inventory, options and API credentials.
	 *
	 * @return void|array
	 */
	private function upload_current_software() {
		$blog_id = get_current_blog_id();
		$pending = get_option( 'patchstack_software_upload_pending', false );
		// Get the software data and hash.
		$data = $this->get_software_data();
		$hash = sha1( json_encode( $data ) );

		// Do not sync for no reason.
		if ( $this->flushing_software_upload && get_option( 'patchstack_software_data_hash', false ) === $hash ) {
			$this->complete_software_upload( $blog_id, $pending );
			return;
		}
		if ( ! defined( 'DOING_CRON' ) && ! isset( $_POST['patchstack_secret'] ) && get_option( 'patchstack_software_data_hash', false ) === $hash && ! is_admin() && ! defined( 'WP_CLI' ) ) {
			return;
		}

		// Make sure to not keep calling this function.
		update_option( 'patchstack_software_upload_attempted', 1 );

		// Synchronize the software list with the API.
		$results = $this->plugin->api->upload_software( [ 'software' => json_encode( $data ) ] );
		if ( ! empty( $results['success'] ) ) {
			if ( array_key_exists( 'vulnerable', $results ) && ! is_array( $results['vulnerable'] ) ) {
				return;
			}

			// The result will also contain a list of all vulnerable plugins on the site that is returned by the API.
			// If the auto update setting is enabled for vulnerable plugins, perform the update once the 15 minute
			// scheduled task "patchstack_update_plugins" is executed.
			$update = get_site_option( 'patchstack_auto_update', [] );
			if ( isset( $results['vulnerable'] ) && is_array( $update ) && in_array( 'vulnerable', $update ) ) {
				$plugins = $results['vulnerable'];
				if ( is_multisite() ) {
					// Plugin files are shared across the network; retain every site's pending updates.
					$plugins = array_values( array_unique( array_merge( (array) get_site_option( 'patchstack_vulnerable_plugins', [] ), $plugins ) ) );
				}
				update_site_option( 'patchstack_vulnerable_plugins', $plugins );
			}

			// If we have vulnerable plugins, determine if we had them before and if not, pull latest firewall rules.
			if ( isset( $results['vulnerable'] ) && count( $results['vulnerable'] ) > 0 ) {
				$prev = get_option( 'patchstack_latest_vulnerable', [] );
				foreach ( $results['vulnerable'] as $vuln ) {
					if ( ! isset( $this->deferred_rule_refreshes[ $blog_id ] ) && is_array( $prev ) && ! in_array ( $vuln, $prev ) ) {
						do_action( 'patchstack_post_dynamic_firewall_rules' );
						break;
					}
				}

				update_option( 'patchstack_latest_vulnerable', $results['vulnerable'] );
			} else {
				update_option( 'patchstack_latest_vulnerable', [] );
			}

			if ( is_multisite() && get_site_option( 'patchstack_latest_vulnerable', false ) !== false ) {
				delete_site_option( 'patchstack_latest_vulnerable' );
			}

			// If we received the number of vulnerable count.
			if ( isset ( $results['vulnerability_count'], $results['vulnerability_fix_count'] ) ) {
				update_option( 'patchstack_vulns_present', $results['vulnerability_count'] );
				update_option( 'patchstack_fixes_present', $results['vulnerability_fix_count'] );
			}

			update_option( 'patchstack_software_data_hash', $hash );
			$this->complete_software_upload( $blog_id, $pending );
			return $results;
		}

		return;
	}

	/**
	 * Synchronize the firewall logs with our API.
	 *
	 * @return void
	 */
	public function upload_firewall_logs() {

		// Do not execute upload action on free sites.
		if ( ! $this->license_is_active() || $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		// Rows logged before redaction was switched on still hold the raw request, so redact them on the way out too.
		// If the redactor can't be loaded, keep the logs queued rather than upload them raw.
		$redact = (bool) get_option( 'patchstack_log_redaction', 0 );
		if ( $redact && ! $this->log_redactor_available() ) {
			return;
		}

		$lock = $this->acquire_lock( 'patchstack_firewall_log_processing' );
		if ( ! $lock ) {
			return;
		}
		try {
			// Requests blocked by the auto-prepend firewall wait in a file; bring them in first.
			for ( $i = 0; $i < 5 && $this->import_ap_logs() === true && $this->has_ap_logs(); $i++ );
			$this->upload_firewall_logs_batch( $redact );
		} finally {
			$this->release_lock( 'patchstack_firewall_log_processing', $lock );
		}
	}

	// A populated legacy flag can hold country information. Keep it intact while that row enforces a ban.
	private function pending_logs( $table, $columns, $retain, $where = '1=1' ) {
		global $wpdb;
		return $wpdb->get_results( "SELECT $columns, ($retain) AS retain_for_ban FROM $table
			WHERE ($where) AND (flag IS NULL OR LENGTH(flag) = 0 OR (flag <> 'patchstack:sent' AND NOT ($retain)))
			ORDER BY id LIMIT 100", ARRAY_A );
	}

	private function acknowledge_logs( $table, $items ) {
		global $wpdb;
		$retain = [];
		$remove = [];
		foreach ( $items as $item ) {
			if ( $item['retain_for_ban'] ) {
				$retain[] = $item['id'];
			} else {
				$remove[] = $item['id'];
			}
		}
		// IDs can exceed PHP_INT_MAX. Compare the exact unsigned integers in the database.
		if ( $retain ) {
			$ids = implode( ', ', array_fill( 0, count( $retain ), 'CAST(%s AS UNSIGNED)' ) );
			if ( $wpdb->query( $wpdb->prepare( "UPDATE $table SET flag = 'patchstack:sent' WHERE id IN ($ids) AND (flag IS NULL OR LENGTH(flag) = 0)", $retain ) ) === false ) {
				return false;
			}
		}
		if ( $remove ) {
			$ids = implode( ', ', array_fill( 0, count( $remove ), 'CAST(%s AS UNSIGNED)' ) );
			return $wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE id IN ($ids)", $remove ) ) !== false;
		}
		return true;
	}

	// The firewall log rows that still enforce an automatic ban.
	private function firewall_ban_rows() {
		global $wpdb;
		$window = $this->ban_window_minutes( 'patchstack_autoblock_minutes', 'patchstack_autoblock_blocktime' );
		return $wpdb->prepare( "COALESCE(block_type, '') = 'BLOCK' AND apply_ban = 1 AND log_date IS NOT NULL AND log_date >= (%s - INTERVAL %d MINUTE)", current_time( 'mysql' ), $window );
	}

	// The failed logins recorded before an upgrade that still count towards a login ban.
	private function login_ban_rows() {
		global $wpdb;
		$window = $this->ban_window_minutes( 'patchstack_anti_bruteforce_minutes', 'patchstack_anti_bruteforce_blocktime' );
		return $wpdb->prepare( "%d <> 0 AND COALESCE(action, '') = 'failed login' AND (flag IS NULL OR flag <> 'patchstack:login-audit') AND date IS NOT NULL AND date >= (%s - INTERVAL %d MINUTE)", (int) $this->get_option( 'patchstack_block_bruteforce_ips', 0 ), current_time( 'mysql' ), $window );
	}

	/**
	 * Remove log rows that have waited 7 days for the API to accept them. A site that cannot
	 * deliver its logs, for any reason, would otherwise grow these tables without limit.
	 *
	 * @return void
	 */
	public function expire_undelivered_logs() {
		global $wpdb;
		$previous = $wpdb->suppress_errors( true );
		try {
			$wpdb->query( $wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}patchstack_firewall_log WHERE log_date < (%s - INTERVAL 7 DAY) AND NOT (" . $this->firewall_ban_rows() . ') LIMIT 20000',
				current_time( 'mysql' )
			) );
			$wpdb->query( $wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}patchstack_event_log WHERE date < (%s - INTERVAL 7 DAY) AND (action IS NULL OR action NOT IN ('login attempt', 'login ban')) AND NOT (" . $this->login_ban_rows() . ') LIMIT 20000',
				current_time( 'mysql' )
			) );
		} finally {
			$wpdb->suppress_errors( $previous );
		}
	}

	private function upload_firewall_logs_batch( $redact ) {
		global $wpdb;
		$table = $wpdb->prefix . 'patchstack_firewall_log';
		$retain = $this->firewall_ban_rows();
		for ( $i = 0; $i < 2; $i++ ) {
			$items = $this->pending_logs( $table, 'id, ip, log_date, request_uri, user_agent, fid, method, post_data', $retain );
			if ( ! $items ) {
				break;
			}

			// Construct the array to be uploaded to our API.
			$logs = [];
			foreach ( $items as $item ) {

				// Blocks by the proxy comment posting hardening rule are not stored on the API side.
				// Its rule ID is checked too, so the path in a URL cannot hide another block.
				if ( (string) $item['fid'] === '7' && stripos( $item['request_uri'], 'wp-comments-post' ) !== false ) {
					continue;
				}

				// Push to entries to be uploaded.
				$logs[] = [
					'ip'          => $item['ip'],
					'fid'         => $item['fid'],
					'request_uri' => $redact ? Patchstack\LogRedactor::uri( $item['request_uri'] ) : $item['request_uri'],
					'user_agent'  => $item['user_agent'],
					'method'      => $item['method'],
					'log_date'    => $item['log_date'],
					'post_data'   => $redact ? Patchstack\LogRedactor::PAYLOAD : $item['post_data'],
				];
			}
	
			if ( $logs ) {
				$result = $this->plugin->api->upload_firewall_logs( [ 'logs' => wp_json_encode( $logs ), 'type' => 'firewall' ] );
				if ( empty( $result['success'] ) || isset( $result['error'] ) || isset( $result['errors'] ) ) {
					break;
				}
			}
			if ( ! $this->acknowledge_logs( $table, $items ) ) {
				break;
			}
		}

		$wpdb->query( "DELETE FROM $table WHERE flag = 'patchstack:sent' AND NOT ($retain) LIMIT 200" );
	}

	/**
	 * Synchronize the activity logs with our API.
	 *
	 * @return void
	 */
	public function upload_activity_logs() {

		// Do not execute upload action on free sites.
		if ( ! $this->license_is_active() || $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		$lock = $this->acquire_lock( 'patchstack_eventlog_processing' );
		if ( ! $lock ) {
			return;
		}
		try {
			$this->upload_activity_logs_batch();
		} finally {
			$this->release_lock( 'patchstack_eventlog_processing', $lock );
		}
	}

	private function upload_activity_logs_batch() {
		global $wpdb;
		$table = $wpdb->prefix . 'patchstack_event_log';
		$send_failures = $this->get_option( 'patchstack_activity_log_failed_logins_db', 0 ) == 1;
		$retain = $this->login_ban_rows();
		for ( $i = 0; $i < 2; $i++ ) {
			$items = $this->pending_logs( $table, 'id, author, ip, object, object_id, object_name, action, date', $retain, "action IS NULL OR action NOT IN ('login attempt', 'login ban')" );
			if ( ! $items ) {
				break;
			}
			$logs = [];
			foreach ( $items as $item ) {
				if ( $send_failures || $item['action'] !== 'failed login' ) {
					unset( $item['retain_for_ban'] );
					// A change logged before this was masked at the source is still waiting to be sent.
					if ( $item['object'] === 'option' && strpos( (string) $item['object_name'], 'mailserver_pass from ' ) === 0 ) {
						$item['object_name'] = 'mailserver_pass from "[redacted]" to "[redacted]"';
					}
					$logs[] = $item;
				}
			}
			if ( $logs ) {
				$result = $this->plugin->api->upload_activity_logs( [ 'logs' => wp_json_encode( $logs ) ] );
				if ( empty( $result['success'] ) || isset( $result['error'] ) || isset( $result['errors'] ) ) {
					break;
				}
			}
			if ( ! $this->acknowledge_logs( $table, $items ) ) {
				break;
			}
		}

		$wpdb->query( "DELETE FROM $table WHERE flag = 'patchstack:sent' AND NOT ($retain) LIMIT 200" );
	}

	/**
	 * Obtain information about the software that the user has installed.
	 * This includes plugins, themes, WordPress and PHP version.
	 *
	 * @return array
	 */
	public function get_software_data() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}

		// Refetch updates data if we are performing a plugin listener related action.
		if ( isset( $_POST['patchstack_secret'] ) ) {
			@require_once ABSPATH . 'wp-includes/update.php';
			@wp_update_themes();
			@wp_update_plugins();
		}

		// Fetch list of plugins.
		$all_plugin        = get_plugins();
		$installed_plugins = array_keys( $all_plugin );
		$updatable_plugins = get_plugin_updates();
		$software_list     = [];

		foreach ( $installed_plugins as $plugin ) {
			if ( ! file_exists( WP_PLUGIN_DIR . '/' . $plugin ) ) {
				continue;
			}

			// The first synchronization runs before init; translating the headers there loads every plugin's text domain too early.
			$plugin_data    = get_plugin_data( WP_PLUGIN_DIR . '/' . $plugin, false, false );
			$new_version    = empty( $updatable_plugins[ $plugin ]->update->new_version ) ? '' : $updatable_plugins[ $plugin ]->update->new_version;
			$plugin_name    = empty( $plugin_data['Name'] ) ? '' : $plugin_data['Name'];
			$plugin_version = empty( $plugin_data['Version'] ) ? '' : $plugin_data['Version'];

			if ( ! empty( $plugin_name ) && ! empty( $plugin_version ) ) {
				
				// Determine the active state.
				if ( isset( $_GET['action'], $_GET['plugin'] ) && $_GET['action'] == 'deactivate' && $_GET['plugin'] == $plugin) {
					$active = 0;
				} else {
					$active = (int) is_plugin_active( $plugin );
				}

				$software_list[] = [
					'sw_type'    => 'plugin',
					'sw_name'    => $plugin_name,
					'sw_cur_ver' => $plugin_version,
					'sw_new_ver' => $new_version,
					'sw_key'     => $plugin,
					'sw_active'  => $active
				];
			}
		}

		// Fetch list of themes.
		$themes           = wp_get_themes();
		$themes_keys      = array_keys( $themes );
		$updatable_themes = get_theme_updates();

		foreach ( $themes_keys as $theme_key ) {
			$themes_data       = $themes[ $theme_key ];
			$theme_temporary   = empty( $updatable_themes[ $theme_key ] ) ? '' : $updatable_themes[ $theme_key ];
			$theme_new_version = empty( $updatable_themes[ $theme_key ] ) || ! isset( $theme_temporary->update, $theme_temporary->update['new_version'] ) ? '' : $theme_temporary->update['new_version'];
			$theme_name        = $themes_data->get( 'Name' );
			$theme_version     = $themes_data->get( 'Version' );

			if ( ! empty( $theme_name ) && ! empty( $theme_version ) ) {
				$software_list[] = [
					'sw_type'    => 'theme',
					'sw_name'    => $theme_name,
					'sw_cur_ver' => $theme_version,
					'sw_new_ver' => $theme_new_version,
					'sw_key'     => $theme_key,
				];
			}
		}

		// Fetch WordPress version.
		global $wp_version;
		$core_updates    = get_core_updates();
		$new_wp_version  = ( ! empty( $core_updates ) && $core_updates[0]->response == 'upgrade' ) ? $core_updates[0]->version : '';
		$software_list[] = [
			'sw_type'    => 'wordpress',
			'sw_name'    => 'WordPress',
			'sw_cur_ver' => $wp_version,
			'sw_new_ver' => $new_wp_version,
		];

		// Fetch PHP version.
		$software_list[] = [
			'sw_type'    => 'php',
			'sw_name'    => 'PHP',
			'sw_cur_ver' => phpversion(),
			'sw_new_ver' => '',
		];

		// Fetch database server version.
		global $wpdb;
		if ( ! is_null( $wpdb ) ) {
			$software_list[] = [
				'sw_type' => 'database',
				'sw_name' => 'Database',
				'sw_cur_ver' => $wpdb->get_var( 'SELECT VERSION()' ),
				'sw_new_ver' => ''
			];
		}

		$software_list = apply_filters( 'patchstack_get_software_data', $software_list );
		return $software_list;
	}

	protected function ap_log_path() {
		return __DIR__ . '/../../../pslogs/logs.php';
	}

	// Whether blocked requests are still waiting in the auto-prepend log.
	private function has_ap_logs() {
		$logs = $this->ap_log_path();
		clearstatcache();
		return is_file( $logs . '.pending.php' ) || ( is_file( $logs ) && filesize( $logs ) > 32 );
	}

	/**
	 * Import the logs generated by the auto prepend firewall rules.
	 *
	 * @return bool|void
	 */
	public function import_ap_logs() {
		// The file is shared by every site of a network, so any site that uploads logs imports it,
		// whether or not the auto-prepend installer is switched on for that site.
		$logs = $this->ap_log_path();
		if ( ! file_exists( $logs ) && ! file_exists( $logs . '.pending.php' ) ) {
			return;
		}
		$autoload = __DIR__ . '/../lib/patchstack/vendor/autoload.php';
		if ( ! is_readable( $autoload ) ) {
			return;
		}
		require_once $autoload;
		if ( ! class_exists( 'Patchstack\LogQueue' ) ) {
			return;
		}
		$can_redact = $this->log_redactor_available();
		if ( ! $can_redact && ( $this->is_multi_site || get_option( 'patchstack_log_redaction', 0 ) ) ) {
			return;
		}
		// The AP file is shared across blogs; its consumer lock is filesystem-wide.
		delete_option( 'patchstack_firewall_log_ap_processing' );
		global $wpdb;
		$extension = new Patchstack\Extensions\WordPress\Extension( [], $this );
		// Rows are stamped by the database, so the time of an imported block is expressed on its clock.
		$db_now = strtotime( (string) $wpdb->get_var( 'SELECT NOW()' ) );
		return Patchstack\LogQueue::consume( $logs, function ( $line ) use ( $wpdb, $extension, $can_redact, $db_now ) {
			$data = json_decode( base64_decode( $line, true ), true );
			if ( ! is_array( $data ) || ! isset( $data['site_id'], $data['ip'], $data['request_uri'], $data['user_agent'], $data['method'], $data['fid'], $data['post_data'] ) ) {
				return true;
			}
			// Keep the time the request was blocked: a block from last month must not count towards
			// a ban today. Blocks older than the 7 days undelivered logs are kept for are left out.
			// Entries written before 2.3.8 only carry a date in the server's own timezone.
			if ( isset( $data['time'] ) && is_int( $data['time'] ) ) {
				$blocked = $data['time'];
			} else {
				$blocked = isset( $data['log_date'] ) && is_string( $data['log_date'] ) ? strtotime( $data['log_date'] ) : false;
			}
			$age = $blocked ? max( 0, time() - $blocked ) : 0;
			if ( $age > 7 * DAY_IN_SECONDS ) {
				return true;
			}
			if ( $this->get_blog_option( $data['site_id'], 'patchstack_log_redaction', 0 ) ) {
				if ( ! $can_redact ) {
					return false;
				}
				$data['request_uri'] = Patchstack\LogRedactor::uri( $data['request_uri'] );
				$data['post_data'] = Patchstack\LogRedactor::PAYLOAD;
			}
			$inserted = $wpdb->insert(
				$wpdb->get_blog_prefix( $data['site_id'] ) . 'patchstack_firewall_log',
				[
					'ip' => $this->log_field( $data['ip'] ),
					'request_uri' => $this->log_field( $data['request_uri'] ),
					'user_agent' => $this->log_field( $data['user_agent'] ),
					'method' => $this->log_field( $data['method'] ),
					'fid' => $this->log_field( $data['fid'] ),
					'flag' => '',
					'post_data' => is_string( $data['post_data'] ) ? $data['post_data'] : '',
					'block_type' => 'BLOCK',
					'log_date' => date( 'Y-m-d H:i:s', ( $db_now ? $db_now : time() ) - $age ),
				]
			);
			if ( $inserted === false ) {
				return false;
			}
			$hits = (int) $this->get_blog_option( $data['site_id'], 'patchstack_hits_all_time', 0 );
			$this->update_blog_option( $data['site_id'], 'patchstack_hits_all_time', $hits + 1 );
			$counters = $this->get_blog_option( $data['site_id'], 'patchstack_hits_last_30', [] );
			$this->update_blog_option( $data['site_id'], 'patchstack_hits_last_30', $extension->merge_counters( [ date( 'Y-m-d' ) => 1 ], $counters ) );
			return true;
		} );
	}
}
