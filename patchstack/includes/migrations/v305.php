<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( (int) get_option( 'patchstack_log_schema_attempts', 0 ) >= 3 || (int) get_option( 'patchstack_log_schema_retry_after', 0 ) > time() ) {
	return false;
}

// A lease limits concurrent DDL and expires if a request dies before releasing it.
$lock_name = 'patchstack_log_schema_lock';
$options_table = '`' . str_replace( '`', '``', $wpdb->options ) . '`';
$lock = get_option( $lock_name, '' );
if ( $lock ) {
	if ( (int) $lock > time() ) {
		return false;
	}
	$wpdb->query( $wpdb->prepare( "DELETE FROM $options_table WHERE option_name = %s AND option_value = %s", $lock_name, $lock ) );
	wp_cache_delete( $lock_name, 'options' );
}
$lock = ( time() + 15 * MINUTE_IN_SECONDS ) . ':' . wp_generate_uuid4();
if ( $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO $options_table (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $lock_name, $lock ) ) !== 1 ) {
	return false;
}
wp_cache_delete( $lock_name, 'options' );
wp_cache_delete( 'notoptions', 'options' );

// Persist the attempt before DDL so an interrupted rebuild also counts toward the cap.
update_option( 'patchstack_log_schema_attempts', (int) get_option( 'patchstack_log_schema_attempts', 0 ) + 1, false );
update_option( 'patchstack_log_schema_retry_after', time() + 5 * MINUTE_IN_SECONDS, false );

$complete = false;
$lock_wait_timeout = null;
try {
	// SHOW returns no row on older servers that lack metadata-lock timeouts.
	$timeout = $wpdb->get_row( "SHOW SESSION VARIABLES LIKE 'lock_wait_timeout'" );
	if ( $wpdb->last_error ) {
		return false;
	}
	if ( $timeout ) {
		$lock_wait_timeout = $timeout->Value;
		if ( ! ctype_digit( (string) $lock_wait_timeout ) || $wpdb->query( 'SET SESSION lock_wait_timeout = 5' ) === false ) {
			return false;
		}
	}

	foreach ( [ 'patchstack_event_log', 'patchstack_firewall_log' ] as $log_table ) {
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $prefix . $log_table ) ) );
		if ( $wpdb->last_error ) {
			return false;
		}
		// Missing tables are created with the current schema by activation or repair.
		if ( ! $exists ) {
			continue;
		}
		$table = '`' . str_replace( '`', '``', $prefix . $log_table ) . '`';
		$id = $wpdb->get_row( "SHOW COLUMNS FROM $table WHERE Field = 'id'" );
		if ( ! $id || $wpdb->last_error || ! preg_match( '/^(tinyint|smallint|mediumint|int|bigint)(\([0-9]+\))?( unsigned)?$/i', $id->Type ) || stripos( $id->Extra, 'auto_increment' ) === false ) {
			return false;
		}

		$changes = [];
		if ( stripos( $id->Type, 'bigint' ) !== 0 ) {
			// Keep signedness so manually inserted negative IDs cannot be coerced to zero.
			$unsigned = stripos( $id->Type, 'unsigned' ) !== false ? ' unsigned' : '';
			$changes[] = 'MODIFY COLUMN id bigint(20)' . $unsigned . ' NOT NULL AUTO_INCREMENT';
		}

		if ( $log_table === 'patchstack_firewall_log' ) {
			$indexes = $wpdb->get_results( "SHOW INDEX FROM $table WHERE Key_name = 'ps_ban_lookup'" );
			if ( $wpdb->last_error || ! is_array( $indexes ) ) {
				return false;
			}
			if ( $indexes ) {
				$definition = [];
				foreach ( $indexes as $index ) {
					if ( $index->Index_type !== 'BTREE' || ( isset( $index->Visible ) && $index->Visible === 'NO' ) || ( isset( $index->Ignored ) && $index->Ignored === 'YES' ) ) {
						return false;
					}
					$definition[(int) $index->Seq_in_index] = $index->Column_name . ( $index->Sub_part === null ? '' : '(' . $index->Sub_part . ')' );
				}
				ksort( $definition );
				// Leave an unexpected host-defined index untouched for manual review.
				if ( array_values( $definition ) !== [ 'ip(45)', 'apply_ban', 'block_type(5)', 'log_date' ] ) {
					return false;
				}
			} else {
				// Prefixes fit the 767-byte limit of older utf8mb4 InnoDB tables.
				$changes[] = 'ADD KEY ps_ban_lookup (ip(45),apply_ban,block_type(5),log_date)';
			}
		}

		// Combining changes avoids rebuilding the firewall table twice.
		if ( $changes && $wpdb->query( "ALTER TABLE $table " . implode( ', ', $changes ) ) === false ) {
			return false;
		}
	}

	if ( version_compare( (string) get_option( 'patchstack_db_version', '0' ), '3.0.5', '<' ) ) {
		update_option( 'patchstack_db_version', '3.0.5' );
	}
	$complete = version_compare( (string) get_option( 'patchstack_db_version', '0' ), '3.0.5', '>=' );
	if ( $complete ) {
		delete_option( 'patchstack_log_schema_retry_after' );
		delete_option( 'patchstack_log_schema_attempts' );
	}
	return $complete;
} finally {
	if ( ctype_digit( (string) $lock_wait_timeout ) ) {
		$wpdb->query( 'SET SESSION lock_wait_timeout = ' . $lock_wait_timeout );
	}
	if ( ! $complete ) {
		// Do not repeat a failed ALTER on every page request.
		update_option( 'patchstack_log_schema_retry_after', time() + 5 * MINUTE_IN_SECONDS, false );
	}
	// Delete only this request's lease; an expired lease may already have a new owner.
	$wpdb->query( $wpdb->prepare( "DELETE FROM $options_table WHERE option_name = %s AND option_value = %s", $lock_name, $lock ) );
	wp_cache_delete( $lock_name, 'options' );
}
