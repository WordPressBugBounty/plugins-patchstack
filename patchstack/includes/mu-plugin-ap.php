<?php

// Do not run if already executed.
if ( defined( 'PS_FW_MU_RAN' ) ) {
    return;
}

// Attempt to load config file. A replacement over SFTP that was cut off leaves the previous
// config under its backup name until the next refresh.
$ps_config = __DIR__ . '/../../../pslogs/config.php';
if ( ! file_exists( $ps_config ) ) {
    $ps_config = __DIR__ . '/../../../pslogs/config.backup.php';
}
if ( ! file_exists( $ps_config ) || ! file_exists ( __DIR__ . '/../lib/patchstack/vendor/autoload.php' ) ) {
    return;
}

// Define path to pslogs.
define( 'PS_LOGS', __DIR__ . '/../../../pslogs/' );
define( 'PS_PATH', __DIR__ . '/../' );

// Parse options.
$ps_options = @include( $ps_config );
if ( ! is_array( $ps_options ) || count( $ps_options ) === 0 ) {
    return;
}

// Include the helper functions.
require_once __DIR__ . '/mu-plugin-helper.php';

// Attempt to load the proper config, if on multisite.
if ( count( $ps_options ) != 1 ) {
    $ps_options = patchstack_get_active_domain( $ps_options );
} else {
    $ps_options = $ps_options[0];
}

// Do not run if we're not supposed to.
if ( ! patchstack_get_should_run( $ps_options ) ) {
    return;
}

// Initialize and launch.
try {
    // Load the extension.
    require_once __DIR__ . '/../lib/patchstack/vendor/autoload.php';
    $extension = new Patchstack\Extensions\WordPress\ExtensionAP( $ps_options );

    // Initiate the firewall processor with our settings.
    $firewall = new Patchstack\Processor(
        $extension,
        json_decode( base64_decode( $ps_options['patchstack_firewall_rules_v3_ap'] ), true ),
        [],
        ['mustUsePluginCall' => true],
        [],
        []
    );

    // Launch the firewall.
    $firewall->launch();
} catch ( \Exception $e ) {
    //
}
