<?php

/**
 * Based on the current path and domain name, determine which option index we should use.
 * 
 * @param array $options
 * @return integer
 */
function patchstack_get_active_domain( $options )
{
    // Essential server variables must be set.
    if ( ! isset( $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'] ) ) {
        return $options[0];
    }

    $host = strtolower(rtrim(preg_replace('/:(?:80|443)$/D', '', $_SERVER['HTTP_HOST']), '.'));
    $target = explode('?', $_SERVER['REQUEST_URI'], 2);
    // WordPress looks a site's path up case-insensitively, so /SHOP/ and /shop/ are the same site.
    // It also strips backslashes and skips empty and "0" segments before the lookup.
    $segments = array_filter( explode( '/', strtolower( stripslashes( $target[0] ) ) ) );
    $path = '/' . implode( '/', $segments ) . ( $segments && substr( $target[0], -1 ) === '/' ? '/' : '' );

    // WordPress also serves a site's bare domain under its www. alias. An exact host wins.
    $hosts = [ $host ];
    if ( strpos( $host, 'www.' ) === 0 ) {
        $hosts[] = substr( $host, 4 );
    }

    // Prefer the most specific matching home or core path. Home wins a tie.
    foreach ( $hosts as $candidate ) {
        $selected = null;
        $length = -1;
        foreach ( [ 'home_url', 'site_url'] as $base ) {
            foreach ( $options as $option ) {
                if ( ! isset( $option[$base] ) || ! is_string( $option[$base] ) ) {
                    continue;
                }
                $parts = explode('/', $option[$base], 2);
                if ( strtolower(rtrim(preg_replace('/:(?:80|443)$/D', '', $parts[0]), '.')) !== $candidate ) {
                    continue;
                }
                $site_path = isset($parts[1]) ? strtolower(rtrim('/' . $parts[1], '/')) : '';
                if ( ($path === $site_path || strpos($path, $site_path . '/') === 0) && strlen($site_path) > $length ) {
                    $selected = $option;
                    $length = strlen($site_path);
                }
            }
        }
        if ($selected !== null) {
            return $selected;
        }
    }

    // Return first options set by default.
    return $options[0];
}

/**
 * Given the option values, determine if the WAF should run.
 * 
 * @param array $options
 * @return boolean
 */
function patchstack_get_should_run( $options )
{
    // A stale config from an older version may be missing keys; treat anything
    // absent as "do not run" and avoid undefined-key warnings before WordPress loads.
    if ( ! isset( $options['patchstack_license_activated'] ) || $options['patchstack_license_activated'] == 0 ) {
        return false;
    }

    if ( ! isset( $options['patchstack_basic_firewall'] ) || $options['patchstack_basic_firewall'] != 1 ) {
        return false;
    }

    if ( ! isset( $options['patchstack_license_free'] ) || $options['patchstack_license_free'] == 1 ) {
        return false;
    }

    if ( ! isset( $options['patchstack_firewall_rules_v3_ap'] ) ) {
        return false;
    }

    $rules = base64_decode( $options['patchstack_firewall_rules_v3_ap'] );
    if ( $rules == '' || $rules == '[]' ) {
        return false;
    }

    return true;
}
