<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Create firewall log table.
$firewall_table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $prefix . 'patchstack_firewall_log' ) ) );
if ( $wpdb->last_error ) {
	return false;
}
$sql = 'CREATE TABLE IF NOT EXISTS `' . $prefix . "patchstack_firewall_log` (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    ip tinytext NOT NULL,
    flag tinytext NOT NULL,
    fid mediumint(4),
    request_uri tinytext,
    user_agent tinytext,
    method tinytext,
    post_data LONGTEXT,
    log_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    apply_ban INT NOT NULL DEFAULT '1',
    block_type VARCHAR(255) NOT NULL DEFAULT '',
    block_params VARCHAR(255) NOT NULL DEFAULT '',
	PRIMARY KEY (id),
    UNIQUE KEY id (id),
    KEY ps_ban_lookup (ip(45),apply_ban,block_type(5),log_date)
) $charset_collate;";
dbDelta( $sql );
if ( $wpdb->last_error ) {
	return false;
}
if ( ! $firewall_table_exists ) {
	delete_option( 'patchstack_log_schema_retry_after' );
	delete_option( 'patchstack_log_schema_attempts' );
	// A newly created table starts a new ID sequence.
	update_option( 'patchstack_firewall_log_lastid', 0 );
}

// Create logic table that will store the firewall rules descriptions.
$sql = 'CREATE TABLE IF NOT EXISTS `' . $prefix . "patchstack_logic` (
    id mediumint(9) NOT NULL,
    cname varchar(20),
    description tinytext,
    log_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY (id),
    UNIQUE KEY id (id)
) $charset_collate;";
dbDelta( $sql );
if ( $wpdb->last_error ) {
	return false;
}

// Create table that will store all events.
$event_table_exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $prefix . 'patchstack_event_log' ) ) );
if ( $wpdb->last_error ) {
	return false;
}
$sql = 'CREATE TABLE IF NOT EXISTS `' . $prefix . "patchstack_event_log` (
    id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
    author tinytext  NULL,
    ip tinytext  NULL,
    flag tinytext NULL,
    object tinytext  NULL,
    object_id tinytext  NULL,
    object_name text  NULL,
    action tinytext NULL,
    date datetime  NULL,
    PRIMARY KEY  (id),
    UNIQUE KEY id (id)
    ) $charset_collate;";
dbDelta( $sql );
if ( $wpdb->last_error ) {
	return false;
}
if ( ! $event_table_exists ) {
	delete_option( 'patchstack_log_schema_retry_after' );
	delete_option( 'patchstack_log_schema_attempts' );
	update_option( 'patchstack_eventlog_lastid', 0 );
}

// Insert base firewall rules.
$result = $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $prefix . 'patchstack_logic' );
if ( ! $result ) {
	$logics = [
		[
			'id'          => 400,
			'cname'       => 'Bad Request',
			'description' => 'The server cannot or will not process the request due to an apparent client error',
		],
		[
			'id'          => 401,
			'cname'       => 'Unauthorized',
			'description' => 'Authentication is required and has failed or has not yet been provided.',
		],
		[
			'id'          => 402,
			'cname'       => 'Invalid URL',
			'description' => 'Payment Required. Reserved for future use.',
		],
		[
			'id'          => 403,
			'cname'       => 'Forbidden',
			'description' => 'The request was valid, but the server is refusing action.',
		],
		[
			'id'          => 404,
			'cname'       => 'Not Found',
			'description' => 'The requested resource could not be found but may be available in the future.',
		],
		[
			'id'          => 405,
			'cname'       => 'Not Allowed',
			'description' => 'A request method is not supported for the requested resource.',
		],
		[
			'id'          => 410,
			'cname'       => 'Gone',
			'description' => 'Indicates that the resource requested is no longer available and will not be available again.',
		],
		[
			'id'          => 411,
			'cname'       => 'String Injection',
			'description' => 'A request strings attack.',
		],
		[
			'id'          => 501,
			'cname'       => 'Pingback',
			'description' => 'Pingback protection.',
		],
		[
			'id'          => 502,
			'cname'       => 'Unauthorized',
			'description' => 'Blocked debug log access',
		],
		[
			'id'          => 101,
			'cname'       => 'Restricted Files',
			'description' => 'Trying to access readme file.',
		],
		[
			'id'          => 102,
			'cname'       => 'Restricted Files',
			'description' => 'Trying to access license file.',
		],
		[
			'id'          => 103,
			'cname'       => 'Restricted Files',
			'description' => 'Trying to access wp-config file.',
		],
		[
			'id'          => 104,
			'cname'       => 'Restricted Files',
			'description' => 'Trying to access robots_txt file.',
		],
		[
			'id'          => 108,
			'cname'       => 'Bad Char',
			'description' => 'Advanced character string filtered.',
		],
		[
			'id'          => 109,
			'cname'       => 'Gone',
			'description' => 'Trying to access readme files htaccess, htpasswd, errordocs or logs.',
		],
		[
			'id'          => 2,
			'cname'       => 'Dir Exploit',
			'description' => 'Blocked restricted wordpres file access.',
		],
		[
			'id'          => 3,
			'cname'       => 'Dir Exploit',
			'description' => 'Blacklist Bots detected.',
		],
		[
			'id'          => 4,
			'cname'       => 'HTTP Ref Attack',
			'description' => 'Abusive HTTP Referrer Blocking.',
		],
		[
			'id'          => 5,
			'cname'       => 'Blacklist',
			'description' => 'Known blacklist attacks.',
		],
		[
			'id'          => 6,
			'cname'       => 'Trace',
			'description' => 'Trace and track method detected.',
		],
		[
			'id'          => 7,
			'cname'       => 'Proxy Commenting',
			'description' => 'Forbid proxy comment posting.',
		],
		[
			'id'          => 8,
			'cname'       => 'SQLI',
			'description' => 'Deny bad query strings.',
		],
		[
			'id'          => 10,
			'cname'       => 'SQLI',
			'description' => 'Deny bad query strings.',
		],
		[
			'id'          => 11,
			'cname'       => 'Request',
			'description' => 'Deny bad query strings.',
		],
		[
			'id'          => 12,
			'cname'       => 'Referrers',
			'description' => 'Deny bad query strings.',
		],
		[
			'id'          => 13,
			'cname'       => 'Request',
			'description' => 'Deny bad query strings.',
		],
		[
			'id'          => 16,
			'cname'       => 'RFI',
			'description' => 'Forbid RFI.',
		],
		[
			'id'          => 17,
			'cname'       => 'Spam',
			'description' => 'Block spambot.',
		],
		[
			'id'          => 18,
			'cname'       => 'Hotlinks',
			'description' => 'Image hotlinking.',
		],
		[
			'id'          => 19,
			'cname'       => 'readme',
			'description' => 'Readme.txt Scan.',
		],
		[
			'id'          => 22,
			'cname'       => 'Bots',
			'description' => 'Deny bad bots.',
		],
		[
			'id'          => 23,
			'cname'       => 'XSS',
			'description' => 'Cross site scripting.',
		]
	];

	foreach ( $logics as $logic ) {
		$result = $wpdb->get_var( $wpdb->prepare( 'SELECT COUNT(*) FROM ' . $prefix . 'patchstack_logic WHERE id = %s', $logic['id'] ) );
		if ( ! $result ) {
			$wpdb->insert(
				$prefix . 'patchstack_logic',
				[
					'id'          => $logic['id'],
					'cname'       => $logic['cname'],
					'description' => $logic['description'],
				]
			);
		}
	}
}

add_option( 'patchstack_firewall_log_lastid', 0 );
add_option( 'patchstack_eventlog_lastid', 0 );
add_option( 'patchstack_db_version', $this->plugin->version );
