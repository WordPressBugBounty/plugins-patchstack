<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to handle anything multisite related.
 */
class P_Multisite extends P_Core {
	/**
	 * Add the actions required for the multisite functionality.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		if ( ! is_super_admin() ) {
			return;
		}

		if ( is_multisite() && is_main_network() ) {
			add_action( 'network_admin_edit_patchstack_network_plugin_updates', [ $this, 'save_network_update_setting' ] );
		}

		// When we need to re-run the migration of a specific site.
		if ( isset( $_GET['site'], $_GET['PatchstackNonce'] ) && wp_verify_nonce( $_GET['PatchstackNonce'], 'patchstack-migration' ) ) {
			$this->run_migration();
		}
	}

	public function save_network_update_setting() {
		if ( ! is_multisite() || ! is_main_network() || ! current_user_can( 'manage_network_options' )
			|| ! isset( $_POST['patchstack_network_updates_nonce'] ) || ! is_string( $_POST['patchstack_network_updates_nonce'] )
			|| ! wp_verify_nonce( $_POST['patchstack_network_updates_nonce'], 'patchstack_network_plugin_updates' ) ) {
			return;
		}

		$enabled = isset( $_POST['patchstack_network_plugin_updates'] ) && $_POST['patchstack_network_plugin_updates'] === '1';
		update_site_option( 'patchstack_network_plugin_updates', $enabled ? 1 : 0 );
		if ( (bool) get_site_option( 'patchstack_network_plugin_updates', 0 ) !== $enabled ) {
			wp_die( esc_html__( 'The remote management setting could not be saved.', 'patchstack' ) );
		}
		wp_safe_redirect( network_admin_url( 'admin.php?page=patchstack-multisite&settings-updated=1' ) );
		exit;
	}

	/**
	 * This will be called when the network admin clicks on the "Sites" button.
	 * It will show all sites.
	 *
	 * @return void
	 */
	public function sites_section_callback() {
		require_once dirname( __FILE__ ) . '/views/pages/multisite-table.php';
	}

	/**
	 * Re-run the migration for a specific multisite site.
	 * 
	 * @return void
	 */
	private function run_migration( ) {
		// Must be a number.
		if ( ! isset( $_GET['site'] ) || ! is_scalar( $_GET['site'] ) || ! ctype_digit( (string) $_GET['site'] ) ) {
			exit;
		}

		// Site must be valid and exists.
		$site = function_exists( 'get_site' ) ? get_site( $_GET['site'] ) : null;
		if ( is_null( $site ) ) {
			exit;
		}

		switch_to_blog( $site->id );
		try {
			delete_option( 'patchstack_log_schema_retry_after' );
			delete_option( 'patchstack_log_schema_attempts' );
			$success = $this->plugin->activation->migrate() && $this->plugin->activation->migrate_check();
		} finally {
			restore_current_blog();
		}
		if ( ! $success ) {
			wp_die( esc_html__( 'The database migration could not be completed. Please try again in a few minutes.', 'patchstack' ) );
		}

		wp_safe_redirect( add_query_arg( [ 'success' => '1', 'site' => $site->id ], remove_query_arg( [ 'PatchstackNonce', 'site' ] ) ) );
		exit;
	}
}
