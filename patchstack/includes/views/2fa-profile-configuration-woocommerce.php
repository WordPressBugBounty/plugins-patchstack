<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<br>
<fieldset>
	<input type="hidden" name="patchstack_2fa_profile" value="1">
	<legend><?php esc_attr_e( 'Two Factor Authentication Configuration', 'patchstack' ); ?></legend>
	<p class="woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide">
		<label for="patchstack_2fa_enabled"><?php esc_attr_e( 'Enable 2FA', 'patchstack' ); ?></label>
		<input class="woocommerce-Input" name="patchstack_2fa_enabled" type="checkbox" id="patchstack_2fa_enabled" value="1" <?php checked( $enabled ); ?>>
	</p>
	<?php if ( ! $enabled ) { ?>
	<p class="woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide">
		<label for="patchstack_2fa_secretkey"><?php esc_attr_e( 'Secret Key', 'patchstack' ); ?></label>
		<input class="woocommerce-Input woocommerce-Input--text input-text" type="text" id="patchstack_2fa_secretkey" value="<?php echo esc_attr( $secret ); ?>" disabled="disabled">
	</p>
	<p class="woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide">
		<label for="qrcode"><?php esc_attr_e( 'QR Code Image', 'patchstack' ); ?> (<?php esc_attr_e( 'Scan this image with your 2FA app', 'patchstack' ); ?>)</label>
		<div id="qrcode"></div><br />
		<script src="<?php echo esc_url( $this->plugin->url . '/assets/js/qrcode.min.js' ); ?>" type="text/javascript"></script>
		<script type="text/javascript">
			jQuery(function(){
				new QRCode(document.getElementById("qrcode"), {
					text: "<?php echo 'otpauth://totp/WordPress:' . rawurlencode( get_bloginfo( 'name' ) ) . '?secret=' . rawurlencode( $secret ) . '&issuer=WordPress'; ?>",
					width: 128,
					height: 128,
				});
			});
		</script>
	</p>
	<?php } ?>
	<p class="woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide woocommerce-form-patchstack-verification">
		<label for="patchstack_2fa_secretkey_verification">
			<?php
			if ( $enabled ) {
				esc_html_e( 'Enter the current code from your 2FA app to disable 2FA', 'patchstack' );
			} else {
				esc_html_e( 'Enter the current code from your 2FA app to enable 2FA', 'patchstack' );
			}
			?>
		</label>
		<input class="woocommerce-Input woocommerce-Input--text input-text" name="patchstack_2fa_secretkey_verification" type="text" id="patchstack_2fa_secretkey_verification" autocomplete="off">
	</p>
</fieldset>
