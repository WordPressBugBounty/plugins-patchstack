<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to perform interactions with the
 * .htaccess file.
 */
class P_Htaccess extends P_Core {

	/**
	 * The settings that select .htaccess rules from the API.
	 *
	 * @var array
	 */
	private $rule_options = [ 'patchstack_prevent_default_file_access', 'patchstack_basic_firewall', 'patchstack_block_debug_log_access', 'patchstack_block_fake_bots', 'patchstack_index_views', 'patchstack_proxy_comment_posting', 'patchstack_image_hotlinking', 'patchstack_basicscanblock' ];

	/**
	 * Add the actions required for htaccess interactions.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );

		if ( $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		add_action( 'updated_option', [ $this, 'update_option_extras' ], 10, 3 );

		// The settings are network options. On a single site those are stored as ordinary
		// options and the action above already covers them.
		if ( is_multisite() ) {
			add_action( 'update_site_option', [ $this, 'update_site_option_extras' ], 10, 3 );
		}
	}

	/**
	 * If a network option is updated, write to .htaccess file. The action passes the new
	 * value before the old one.
	 *
	 * @param string $option_name
	 * @param mixed  $value
	 * @param mixed  $old_value
	 * @return void
	 */
	public function update_site_option_extras( $option_name, $value, $old_value ) {
		$this->update_option_extras( $option_name, $old_value, $value );
	}

	/**
	 * If option is updated, write to .htaccess file.
	 *
	 * @param string $option_name
	 * @param string $option_name
	 * @param mixed  $value
	 * @return void
	 */
	public function update_option_extras( $option_name, $old_value, $value ) {
		if ( ! in_array( $option_name, array_merge( $this->rule_options, [ 'patchstack_pingback_protection', 'patchstack_trace_and_track', 'patchstack_firewall_custom_rules' ] ), true ) ) {
			return;
		}

		if ( $old_value == $value ) {
			return;
		}

		$this->plugin->rules->post_firewall_rules( true );
	}

	/**
	 * Get the turned on .htaccess firewall settings.
	 *
	 * @return array
	 */
	public function get_firewall_rule_settings() {
		$settings = [];
		foreach ( $this->rule_options as $option ) {
			if ( get_site_option( $option ) ) {
				$settings[] = ( $option == 'patchstack_basicscanblock' ? 'webarx_wpscan_block' : str_replace( 'patchstack_', 'webarx_', $option ) );
			}
		}

		return $settings;
	}

	/**
	 * Remove the API rules from the .htaccess file, keeping the custom rules.
	 *
	 * @return boolean Whether the file now holds no API rules.
	 */
	public function remove_api_rules() {
		// The writer also returns false when the file already matches, so the stored
		// fingerprint tells whether the removal is in place.
		$this->write_to_htaccess( '' );
		return get_site_option( 'patchstack_htaccess_rules_hash', '' ) === sha1( $this->get_managed_rules( '' ) );
	}

	/**
	 * Whether any .htaccess firewall setting was ever saved on this site. With none saved,
	 * an empty selection says nothing about what the site owner turned off.
	 *
	 * @return boolean
	 */
	public function has_stored_rule_settings() {
		foreach ( $this->rule_options as $option ) {
			if ( get_site_option( $option, null ) !== null ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Determine the current state of the firewall.
	 *
	 * @return boolean
	 */
	public function firewall() {
		// Get the firewall state.
		$sum_of_firewall = 0;
		foreach ( [ 'patchstack_prevent_default_file_access', 'patchstack_basic_firewall', 'patchstack_pingback_protection', 'patchstack_block_debug_log_access', 'patchstack_block_fake_bots', 'patchstack_index_views', 'patchstack_trace_and_track', 'patchstack_proxy_comment_posting', 'patchstack_image_hotlinking' ] as $option ) {
			$value = get_site_option( $option, 0 );
			$sum_of_firewall  += empty( $value ) ? 0 : 1;
		}

		// Update the options.
		$onoff           = $sum_of_firewall > 1 ? 0 : 1;
		foreach ( [ 'patchstack_prevent_default_file_access', 'patchstack_basic_firewall', 'patchstack_block_debug_log_access', 'patchstack_index_views', 'patchstack_proxy_comment_posting' ] as $option ) {
			update_site_option( $option, $onoff );
		}
		update_site_option( 'patchstack_block_fake_bots', 0 );
		update_site_option( 'patchstack_image_hotlinking', 0 );

		// Pull the rules or cleanup the .htaccess file?
		if ( $onoff == 1 ) {
			$this->plugin->rules->post_firewall_rules();
		} else {
			$this->cleanup_htaccess_file();
		}

		return true;
	}

	/**
	 * Write the .htaccess firewall rules to the .htaccess file.
	 *
	 * @param string $rules
	 * @return void
	 */
	public function write_rules_to_htaccess( $rules = '' ) {
		if ( ! $this->is_server_supported() || get_site_option( 'patchstack_disable_htaccess', 0 ) || ( defined( 'PS_DISABLE_HTACCESS' ) && PS_DISABLE_HTACCESS ) ) {
			return false;
		}

		$rules = $this->adapt_rules_to_layout( $rules );
		if ( $rules === false || $rules === null ) {
			return false;
		}

		// Determine if the .htaccess file exists.
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
		$fs = new WP_Filesystem_Direct( '' );
		$path = $this->get_htaccess_path();
		if ( ! $fs->exists( $path ) ) {
			$fs->touch( $path );

			// Don't continue if .htaccess does not exist or cannot be written to.
			if ( ! $fs->exists( $path ) ) {
				return false;
			}
		}

		// Get the current rules.
		$current = $old = $fs->get_contents( $path );
		if ( $old === false ) {
			return false;
		}
		$current = $this->delete_all_between( '# Patchstack Firewall Start', '# Patchstack Firewall End', $current );

		// If no rules, then we delete the old ones.
		if ( $rules != '' ) {
			$current = "# Patchstack Firewall Start\r\n<IfModule mod_rewrite.c>\r\nRewriteEngine On\r\n" . $rules . "\r\n</IfModule>\r\n# Patchstack Firewall End\r\n" . $current;
		}

		// Put the contents into the .htaccess file.
		if ( ! $fs->put_contents( $path, $current, FS_CHMOD_FILE ) ) {
			$fs->put_contents( $path, $old, FS_CHMOD_FILE );
			return false;
		}

		// Check if the new rules work.
		// 500 internal server error - did not work. Restore old rules.
		$status = $this->get_site_status_code();
		if ( $status == '' || $status >= 500 ) {
			$fs->put_contents( $path, $old, FS_CHMOD_FILE );
			return false;
		}

		return true;
	}

	/**
	 * Write given rules to the .htaccess file.
	 *
	 * @param string $rules
	 * @return boolean
	 */
	public function write_to_htaccess( $rules = '' ) {
		if ( ! is_string( $rules ) || ! $this->is_server_supported() || get_site_option( 'patchstack_disable_htaccess', 0 ) || ( defined( 'PS_DISABLE_HTACCESS' ) && PS_DISABLE_HTACCESS ) ) {
			return false;
		}

		// Some rule adjustments.
		$rewrites = [
			'RedirectMatch 409 .(htaccess|htpasswd|errordocs|logs)$' => 'RedirectMatch 403 \.(htaccess|htpasswd|errordocs|logs)$',
			"\n  RewriteCond %{HTTP_COOKIE} !^.*wordpress_logged_in.*$ [NC]" => '',
			"\n  RewriteCond %{REMOTE_ADDR} !=18.221.197.243" => '',
			'^wp-includes/[^/]+.php$' => '^wp-includes/.*\.php$',
			// In .htaccess the pattern sees the path from the site root, so it must allow a directory
			// in front of debug.log: WordPress writes the log to wp-content/debug.log by default.
			'RewriteRule ^debug*.*log$ ' => 'RewriteRule (^|/)debug\.log$ ',
			// Last, because the entries above match the rule text as the API sends it.
			'*.*' => '\.'
		];

		foreach ($rewrites as $find => $replace) {
			$rules = str_replace($find, $replace, $rules);
		}

		return $this->plugin->htaccess->self_check( $rules );
	}

	/**
	 * Resolve the front-controller directory independently of the current PHP entry point.
	 *
	 * @return string
	 */
	public function get_htaccess_dir() {
		$core = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$root = $core;
		$blog_id = is_multisite() ? get_main_site_id() : null;
		$home = $blog_id ? get_blog_option( $blog_id, 'home' ) : get_option( 'home' );
		$site = $blog_id ? get_blog_option( $blog_id, 'siteurl' ) : get_option( 'siteurl' );
		$home_path = untrailingslashit( rawurldecode( (string) parse_url( $home, PHP_URL_PATH ) ) );
		$site_path = untrailingslashit( rawurldecode( (string) parse_url( $site, PHP_URL_PATH ) ) );

		if ( parse_url( $home, PHP_URL_HOST ) === parse_url( $site, PHP_URL_HOST ) && strpos( $site_path, $home_path . '/' ) === 0 ) {
			$relative = substr( $site_path, strlen( $home_path ) );
			if ( $relative !== '/' && substr( $core, -strlen( $relative ) ) === $relative ) {
				$candidate = substr( $core, 0, -strlen( $relative ) );
				if ( is_file( $candidate . '/index.php' ) ) {
					$root = $candidate;
				}
			}
		}

		$filtered = apply_filters( 'patchstack_htaccess_dir', $root );
		$filtered = is_string( $filtered ) ? wp_normalize_path( $filtered ) : '';
		if ( preg_match( '~^(?:[a-z]:/|/)~i', $filtered ) && is_dir( $filtered ) ) {
			$root = untrailingslashit( $filtered );
		}
		return $root;
	}

	public function get_htaccess_path() {
		return $this->get_htaccess_dir() . '/.htaccess';
	}

	/**
	 * Adapt only API RewriteRule patterns; filenames in Files directives and custom rules are separate.
	 *
	 * @param string $rules
	 * @param string|null $root Directory containing the target .htaccess.
	 * @return string|false
	 */
	public function adapt_rules_to_layout( $rules, $root = null ) {
		$root = $root === null ? $this->get_htaccess_dir() : $root;
		$core = untrailingslashit( wp_normalize_path( ABSPATH ) );
		$content = untrailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		if ( $core !== $root && strpos( $core, $root . '/' ) !== 0 ) {
			return false;
		}
		$core = $core === $root ? '' : substr( $core, strlen( $root ) + 1 ) . '/';
		$content = strpos( $content, $root . '/' ) === 0 ? substr( $content, strlen( $root ) + 1 ) . '/' : null;
		if ( preg_match( '/\s/', $core . $content ) ) {
			return false;
		}
		$config_parent = $core !== '' && dirname( $core ) !== '.' ? preg_quote( dirname( $core ) . '/', '~' ) . '|' : '';
		$core = preg_quote( $core, '~' );
		$content = $content === null ? null : preg_quote( $content, '~' );

		return preg_replace_callback( '/^([\t ]*RewriteRule[\t ]+)(\^?)(\S+)([\t ]+.*)$/mi', function ( $match ) use ( $core, $content, $config_parent ) {
			$pattern = $match[3];
			if ( $content !== null && strpos( $pattern, 'wp-content/' ) === 0 ) {
				$pattern = $content . substr( $pattern, strlen( 'wp-content/' ) );
			} elseif ( $core !== '' && preg_match( '~^wp-config(?:\\\\)?\.~', $pattern ) ) {
				// WordPress allows wp-config.php in either the core directory or its parent.
				$pattern = '(?:' . $config_parent . $core . ')?' . $pattern;
			} elseif ( $core !== '' && preg_match( '~^(?:wp-admin/|wp-includes/|(?:readme|license|xmlrpc|wp-(?:login|signup|activate|trackback|comments-post|cron|links-opml|load|mail|settings|blog-header))(?:\\\\)?\.)~', $pattern ) ) {
				$pattern = $core . $pattern;
			}
			return $match[1] . $match[2] . $pattern . $match[4];
		}, $rules );
	}

	/**
	 * Get the web-server type.
	 *
	 * @return boolean
	 */
	public function is_server_supported() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? strtolower( $_SERVER['SERVER_SOFTWARE'] ) : '';
		foreach ( [ 'apache', 'nginx', 'litespeed' ] as $webserver ) {
			if ( strstr( $server, $webserver ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Write .htaccess directly without causing a server missconfiguration (500)
	 * (PHP will end the process even if the browser-window was closed.)
	 *
	 * @param string $new_rules
	 * @return boolean
	 */
	public function self_check( $new_rules ) {
		// An empty string removes the API rules while retaining configured custom rules.
		if ( ! is_string( $new_rules ) ) {
			return false;
		}
		// Keep the stored fingerprint independent of layout and output formatting.
		$rules_hash = sha1( $this->get_managed_rules( $new_rules ) );

		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
		$fs = new WP_Filesystem_Direct( '' );
		$path = $this->get_htaccess_path();
		$old = $fs->exists( $path ) ? $fs->get_contents( $path ) : '';
		if ( $old === false ) {
			return false;
		}

		if ( get_site_option( 'patchstack_htaccess_rules_hash', '' ) == $rules_hash ) {
			$existing = $old;
			$legacy = untrailingslashit( wp_normalize_path( ABSPATH ) ) . '/.htaccess';
			if ( $path !== $legacy && $fs->exists( $legacy ) ) {
				$legacy_rules = $fs->get_contents( $legacy );
				if ( $legacy_rules === false ) {
					return false;
				}
				$existing .= "\n" . $legacy_rules;
			}
			if ( stripos( $existing, 'begin webarx' ) !== false || stripos( $existing, 'begin patchstack' ) !== false ) {
				return false;
			}
		}

		$api_rules = str_replace( 'RewriteRule ^debug\.log$', 'RewriteRule debug\.log$', $new_rules );
		$new_rules = $this->adapt_rules_to_layout( $api_rules );
		if ( $new_rules === false || $new_rules === null ) {
			return false;
		}
		$new_rules = $this->get_managed_rules( $new_rules );
		$current_rules = $this->delete_all_between( '# BEGIN WebARX', '# END WebARX', $old );
		$current_rules = $this->delete_all_between( '# BEGIN Patchstack', '# END Patchstack', $current_rules );
		$current_rules = $this->delete_all_between( '# CUSTOM WEBARX RULES', '# END CUSTOM WEBARX RULES', $current_rules );
		$current_rules = $this->delete_all_between( '# CUSTOM PATCHSTACK RULES', '# END CUSTOM PATCHSTACK RULES', $current_rules );

		// Save the new rules and adjust # and newline of our own rules.
		$new_rules = preg_replace( "/[\r\n]+/", "\r\n", $new_rules );
		$new_rules = preg_replace( '/#/', "\r\n#", $new_rules );

		// In order to support all Patchstack plugin versions with newline fix, we have to remove this part ourselves.
		$new_rules = str_replace( "\r\n\r\n# BEGIN Patchstack", '# BEGIN Patchstack', $new_rules );
		$new_rules = str_replace( "# END Patchstack\r\n", '# END Patchstack', $new_rules );

		// Remove RewriteBase / from the Patchstack rules.
		$new_rules = str_replace( "\r\n  RewriteBase /", '', $new_rules );
		$new_rules = str_replace( '/index.php', 'index.php', $new_rules );

		// Determine if the Patchstack rules starts on its own line.
		$lines = explode( "\n", $new_rules );
		foreach ( $lines as $line ) {
			if ( stripos( $line, 'begin patchstack' ) !== false && trim( strtolower( $line ) ) != '# begin patchstack' ) {
				$new_rules = str_replace( '# BEGIN Patchstack', "\r\n# BEGIN Patchstack", $new_rules );
			}
		}

		// Merge the rules together.
		$new_rules = $new_rules . "\n" . $current_rules;

		// Put the contents into the .htaccess file.
		if ( ! $fs->put_contents( $path, $new_rules, FS_CHMOD_FILE ) ) {
			$fs->put_contents( $path, $old, FS_CHMOD_FILE );
			return false;
		}

		// Check if the new rules work.
		// 500 internal server error - did not work. Restore old rules.
		$status = $this->get_site_status_code();
		if ( $status == '' || $status >= 500 ) {
			$fs->put_contents( $path, $old, FS_CHMOD_FILE );
			return false;
		}

		if ( ! $this->sync_legacy_htaccess( $fs, $path, $api_rules ) ) {
			$fs->put_contents( $path, $old, FS_CHMOD_FILE );
			return false;
		}
		update_site_option( 'patchstack_htaccess_rules_hash', $rules_hash );
		return true;
	}

	private function get_managed_rules( $rules ) {
		$rules = PHP_EOL . PHP_EOL . '# BEGIN Patchstack' . PHP_EOL . $rules . PHP_EOL . '# END Patchstack' . PHP_EOL . PHP_EOL;
		$rules = $this->delete_all_between( '# BEGIN WordPress', '# END WordPress', $rules );
		$custom = $this->get_custom_rules();
		return get_site_option( 'patchstack_firewall_custom_rules_loc', 'bottom' ) == 'top' ? $custom . $rules : $rules . $custom;
	}

	/**
	 * Retrieve the custom .htaccess rules and inject into the .htaccess file.
	 *
	 * @return string
	 */
	public function get_custom_rules() {
		$custom = get_site_option( 'patchstack_firewall_custom_rules', '' );
		if ( empty( $custom ) || is_array( $custom ) || $custom == 'Array' ) {
			$custom = '';
		}

		// Do we have any custom rules to inject?
		$tmp = '';
		if ( $custom != '' ) {
			$tmp  = PHP_EOL . '# CUSTOM PATCHSTACK RULES' . PHP_EOL;
			$tmp .= $custom . PHP_EOL;
			$tmp .= '# END CUSTOM PATCHSTACK RULES';
		}
		return $tmp;
	}

	/**
	 * Retrieve the status code of the site.
	 * This is done to determine if the .htaccess rules do not trigger an error.
	 *
	 * @return integer
	 */
	public function get_site_status_code( $core = false ) {
		$blog_id = is_multisite() ? get_main_site_id() : null;
		$response = wp_remote_get( $core ? get_site_url( $blog_id ) : get_home_url( $blog_id ) );
		$http_code = wp_remote_retrieve_response_code( $response );
		return $http_code;
	}

	/**
	 * Remove all Patchstack rules from the .htaccess file.
	 *
	 * @return void
	 */
	public function cleanup_htaccess_file() {
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
		$fs = new WP_Filesystem_Direct( '' );
		$path = $this->get_htaccess_path();
		$this->update_managed_file( $fs, $path );
		$this->sync_legacy_htaccess( $fs, $path );
	}

	private function sync_legacy_htaccess( $fs, $path, $rules = '' ) {
		$legacy = untrailingslashit( wp_normalize_path( ABSPATH ) ) . '/.htaccess';
		return $legacy === $path || $this->update_managed_file( $fs, $legacy, $rules );
	}

	private function update_managed_file( $fs, $path, $api_rules = '' ) {
		if ( ! $fs->exists( $path ) ) {
			return true;
		}
		$old = $fs->get_contents( $path );
		if ( $old === false ) {
			return false;
		}
		$rules = $old;
		foreach ( [
			[ '# BEGIN WebARX', '# END WebARX' ],
			[ '# BEGIN Patchstack', '# END Patchstack' ],
			[ '# CUSTOM WEBARX RULES', '# END CUSTOM WEBARX RULES' ],
			[ '# CUSTOM PATCHSTACK RULES', '# END CUSTOM PATCHSTACK RULES' ],
			[ '# Patchstack Firewall Start', '# Patchstack Firewall End' ],
		] as $markers ) {
			$rules = $this->delete_all_between( $markers[0], $markers[1], $rules );
		}
		// A child rewrite configuration overrides the parent's rules in Apache.
		if ( $api_rules !== '' && preg_match( '/^[\t ]*Rewrite(?:Engine|Rule|Cond|Base|Options)[\t ]/mi', $rules ) ) {
			$core_rules = $this->adapt_rules_to_layout( $api_rules, dirname( $path ) );
			if ( $core_rules === false || $core_rules === null ) {
				return false;
			}
			$core_rules = $this->delete_all_between( '# BEGIN WordPress', '# END WordPress', $core_rules );
			$core_rules = preg_replace( '/^[\t ]*RewriteBase[^\r\n]*/mi', '', $core_rules );
			$home = get_home_url( is_multisite() ? get_main_site_id() : null );
			$front = untrailingslashit( (string) parse_url( $home, PHP_URL_PATH ) ) . '/index.php';
			$core_rules = preg_replace_callback( '~([\t ]+)/?index\.php(?=[?\t ])~', function ( $match ) use ( $front ) {
				return $match[1] . $front;
			}, $core_rules );
			$rules = "# BEGIN Patchstack\n" . $core_rules . "\n# END Patchstack\n" . $rules;
		}
		if ( $rules === $old ) {
			return true;
		}
		if ( ! $fs->put_contents( $path, $rules, FS_CHMOD_FILE ) ) {
			$fs->put_contents( $path, $old, FS_CHMOD_FILE );
			return false;
		}
		if ( $api_rules !== '' ) {
			$status = $this->get_site_status_code( true );
			if ( $status == '' || $status >= 500 ) {
				$fs->put_contents( $path, $old, FS_CHMOD_FILE );
				return false;
			}
		}
		return true;
	}

	/**
	 * Delete characters between a begin and end string.
	 *
	 * @param string $begin
	 * @param string $end
	 * @param string $string
	 * @return string
	 */
	public function delete_all_between( $begin, $end, $string ) {
		$begin_pos = strpos( $string, $begin );
		$end_pos   = $begin_pos === false ? false : strpos( $string, $end, $begin_pos + strlen( $begin ) );
		if ( $begin_pos === false || $end_pos === false ) {
			return $string;
		}

		$end_pos += strlen( $end );

		// Consume any trailing newline characters so the block is removed cleanly
		// regardless of CRLF/LF line endings and repeated writes don't stack blank lines.
		while ( isset( $string[ $end_pos ] ) && ( $string[ $end_pos ] === "\r" || $string[ $end_pos ] === "\n" ) ) {
			$end_pos++;
		}

		$delete = substr( $string, $begin_pos, $end_pos - $begin_pos );
		return str_replace( $delete, '', $string );
	}
}
