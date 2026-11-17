<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Output the form and table.
require_once dirname( __FILE__ ) . '/../../admin/multisite-table.php';
?>
<div class="patchstack-font">
	<?php
		if ( isset( $_GET['success'], $_GET['site'] ) && ctype_digit( $_GET['site'] ) ) {
			$site = get_site( $_GET['site'] );
			echo '<div class="notice notice-success inline" style="margin: 20px 0 0 0;"><p><strong>The database migration has been re-run for the site: ' . esc_url( $site->siteurl ) . '</strong></p></div>';
		}
	?>

	<div class="notice notice-success inline" style="margin: 20px 0 0 0;">
		<p>
			<strong>In order to activate Patchstack on a site, go to the <a href="admin.php?page=patchstack-multisite-settings">activation page.</a></strong>
		</p>
	</div>

	<form method="GET" style="display: table;">
		<div class="wrap">
			<h2>Patchstack - Available Sites</h2>
		</div>
		<input type="hidden" name="page" value="<?php echo esc_attr( $_REQUEST['page'] ); ?>" />
		<?php
			$table = new Patchstack_Network_Sites_Table();
			$table->prepare_items();
		?>
	</form>
	<?php
		$table->display();
	?>
	<?php if ( is_main_network() && current_user_can( 'manage_network_options' ) ) : ?>
		<form method="post" action="<?php echo esc_url( network_admin_url( 'edit.php?action=patchstack_network_plugin_updates' ) ); ?>" class="wrap">
			<?php if ( isset( $_GET['settings-updated'] ) && $_GET['settings-updated'] === '1' ) : ?>
				<div class="notice notice-success inline"><p><?php esc_html_e( 'Remote management setting saved.', 'patchstack' ); ?></p></div>
			<?php endif; ?>
			<label>
				<input type="checkbox" name="patchstack_network_plugin_updates" value="1" <?php checked( get_site_option( 'patchstack_network_plugin_updates', 0 ), 1 ); ?>>
				<?php esc_html_e( 'Allow remote management from the primary site’s Patchstack dashboard', 'patchstack' ); ?>
			</label>
			<p class="description"><?php esc_html_e( 'Anyone with the primary site’s Patchstack signing key can then update WordPress, themes and plugins, switch plugins on or off, delete plugins, and reset 2FA and the cache for this network.', 'patchstack' ); ?></p>
			<p class="description"><strong><?php esc_html_e( 'Only switch this on if you trust every administrator of the primary site.', 'patchstack' ); ?></strong> <?php esc_html_e( 'An administrator there can connect the site to a different Patchstack account and run these commands from it, without being a network administrator.', 'patchstack' ); ?></p>
			<?php
			wp_nonce_field( 'patchstack_network_plugin_updates', 'patchstack_network_updates_nonce', false );
			submit_button( __( 'Save changes', 'patchstack' ), 'secondary' );
			?>
		</form>
	<?php endif; ?>
</div>
