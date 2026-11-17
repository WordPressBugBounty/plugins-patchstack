<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
?>
<h2><?php esc_attr_e( 'Two Factor Authentication Configuration', 'patchstack' ); ?></h2>
<input type="hidden" name="patchstack_2fa_profile" value="1">
<table class="form-table">
	<tbody>
		<tr>
			<th scope="row"><?php esc_attr_e( 'Enable 2FA', 'patchstack' ); ?></th>
			<td>
				<fieldset>
					<legend class="screen-reader-text"><span><?php esc_attr_e( 'Enable 2FA', 'patchstack' ); ?></span></legend>
					<label for="patchstack_2fa_enabled"><input name="patchstack_2fa_enabled" type="checkbox" id="patchstack_2fa_enabled" value="1" <?php checked( $enabled ); ?>> <?php esc_attr_e( 'Enable 2FA on your account', 'patchstack' ); ?></label><br />
				</fieldset>
			</td>
		</tr>
		<?php if ( ! $enabled ) { ?>
		<tr>
			<th scope="row"><?php esc_attr_e( 'Secret Key', 'patchstack' ); ?></th>
			<td>
				<fieldset>
					<legend class="screen-reader-text"><span><?php esc_attr_e( 'Secret Key', 'patchstack' ); ?></span></legend>
					<label for="patchstack_2fa_secretkey"><input type="text" id="patchstack_2fa_secretkey" value="<?php echo esc_attr( $secret ); ?>" readonly="readonly"></label><br />
				</fieldset>
			</td>
		</tr>
		<tr>
			<th scope="row"><?php esc_attr_e( 'QR Code Image', 'patchstack' ); ?></th>
			<td>
				<fieldset>
					<legend class="screen-reader-text"><span><?php esc_attr_e( 'QR Code Image', 'patchstack' ); ?></span></legend>
					<div id="qrcode"></div><br />
					<?php esc_attr_e( 'Scan this image with your 2FA app.', 'patchstack' ); ?>
					<script type="text/javascript">
						jQuery(function(){
							new QRCode(document.getElementById("qrcode"), {
								text: "<?php echo 'otpauth://totp/WordPress:' . rawurlencode( get_bloginfo( 'name' ) ) . '?secret=' . rawurlencode( $secret ) . '&issuer=WordPress'; ?>",
								width: 128,
								height: 128,
							});
						})
					</script>
				</fieldset>
			</td>
		</tr>
		<?php } ?>
		<tr>
			<th scope="row"><label for="patchstack_2fa_secretkey_verification"><?php esc_attr_e( '2FA Code', 'patchstack' ); ?></label></th>
			<td>
				<input name="patchstack_2fa_secretkey_verification" type="text" id="patchstack_2fa_secretkey_verification" value="" autocomplete="off">
				<p class="description">
					<?php
					if ( $enabled ) {
						esc_html_e( 'Enter the current code from your 2FA app to disable 2FA. Enabling it again will set up a new secret key.', 'patchstack' );
					} else {
						esc_html_e( 'Enter the current code from your 2FA app to enable 2FA.', 'patchstack' );
					}
					?>
				</p>
			</td>
		</tr>
	</tbody>
</table>
