<?php

// Do not allow the file to be called directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class is used to pull the firewall/whitelist rules from our API.
 */
class P_Rules extends P_Core {

	/**
	 * Add the actions required to pull the rules.
	 *
	 * @param Patchstack $core
	 * @return void
	 */
	public function __construct( $core ) {
		parent::__construct( $core );
		add_action( 'patchstack_post_firewall_rules', [ $this, 'post_firewall_rules' ] );
		add_action( 'patchstack_post_dynamic_firewall_rules', [ $this, 'dynamic_firewall_rules' ] );
	}

	/**
	 * Pull the hardening .htaccess rules from the API.
	 * Then apply it to the .htaccess file after we create a backup.
	 *
	 * @param boolean $settings_changed Whether a hardening setting was just changed on this site.
	 * @return void
	 */
	public function post_firewall_rules( $settings_changed = false ) {
		if ( $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		// Check if server is supported and if htaccess modifications are disabled.
		if ( get_site_option( 'patchstack_disable_htaccess', 0 ) || ( defined( 'PS_DISABLE_HTACCESS' ) && PS_DISABLE_HTACCESS ) ) {
			return;
		}

		$rules    = $this->plugin->htaccess->get_firewall_rule_settings();

		// The API rejects an empty selection, which would leave the rules of the option that
		// was turned off last in place, so turning the last one off removes them here. Only a
		// settings change asks for that: a scheduled refresh leaves an existing installation
		// as it is, and so does a site whose options were never stored. A removal that could
		// not be written stays pending, so later refreshes retry it until it succeeds.
		if ( empty( $rules ) ) {
			if ( $settings_changed === true && $this->plugin->htaccess->has_stored_rule_settings() ) {
				update_site_option( 'patchstack_htaccess_removal_pending', 1 );
			}
			if ( get_site_option( 'patchstack_htaccess_removal_pending', 0 ) && $this->plugin->htaccess->remove_api_rules() ) {
				delete_site_option( 'patchstack_htaccess_removal_pending' );
			}
			return;
		}

		// An option was turned back on before a pending removal went through.
		if ( get_site_option( 'patchstack_htaccess_removal_pending', 0 ) ) {
			delete_site_option( 'patchstack_htaccess_removal_pending' );
		}

		$settings = json_encode( $rules );
		$results  = $this->plugin->api->post_firewall_rule( [ 'settings' => $settings ] );

		// Only an explicit rules string may replace the installed hardening, including an empty one.
		if ( is_array( $results ) && ! isset( $results['error'] ) && ! isset( $results['errors'] ) && isset( $results['rules'] ) && is_string( $results['rules'] ) ) {
			$this->plugin->htaccess->write_to_htaccess( $results['rules'] );
		}
	}

	/**
	 * Pull the firewall/whitelist rules from the API.
	 *
	 * @return void
	 */
	public function dynamic_firewall_rules() {
		if ( $this->get_option( 'patchstack_license_free', 0 ) == 1 ) {
			return;
		}

		// Get the firewall and whitelist rules.
		$results = $this->plugin->api->post_firewall_rule_json();
		if ( ! is_array( $results ) || ! isset( $results['firewall'] ) || ! is_array( $results['firewall'] ) ) {
			return;
		}

		// Separate the new firewall engine rules from the old ones.
		$newRules = [];
		$newRulesAP = [];
		$oldRules = [];

		// Counters for displaying purposes on the API key page.
		$vPatchCount = 0;
		$ruleCount = 0;

		// Parse the rules.
		foreach ( $results['firewall'] as $rule ) {
			if ( ! is_array( $rule ) || ( isset( $rule['rule_v2'] ) && ( ! isset( $rule['title'] ) || ! is_string( $rule['title'] ) ) ) ) {
				return;
			}
			if ( isset( $rule['rule_v2'] ) ) {
				$rule['rules'] = $rule['rule_v2'];
				unset( $rule['rule_v2'] );

				// Mark vPatches based on substring.
				if ( stripos( $rule['title'], ' vulnerabilit' ) !== false && stripos( $rule['title'], 'block ' ) !== false ) {
					$vPatchCount++;
				} else {
					$ruleCount++;
				}

				// Differentiate between auto prepend rules and regular ones.
				if ( isset( $rule['ap'] ) && !empty( $rule['ap'] ) ) {
					$newRulesAP[] = $rule;
				} else {
					$newRules[] = $rule;
				}
			} else {
				$ruleCount++;
				$oldRules[] = $rule;
			}
		}

		// Update firewall rules.
		update_option( 'patchstack_firewall_rules', json_encode( $oldRules ), true );
		update_option( 'patchstack_firewall_rules_v3', json_encode( $newRules ), true );
		if ( ! update_option( 'patchstack_firewall_rules_v3_ap', json_encode( $newRulesAP ), true ) && get_option( 'patchstack_firewall_ap_error', '' ) !== '' ) {
			// Unchanged rules do not fire updated_option, but a failed config still needs a retry.
			$this->plugin->activation->auto_prepend_injection( true );
		}

		// Update the counters.
		update_option( 'patchstack_vpatches_present', $vPatchCount );
		update_option( 'patchstack_non_vpatches_present', $ruleCount );

		// Separate the new firewall engine rules from the old ones. Only touch the
		// stored whitelists when the API actually returned them, otherwise a partial
		// response would wipe the existing whitelist rules.
		if ( isset( $results['whitelists'] ) && is_array( $results['whitelists'] ) ) {
			$newRules = [];
			$oldRules = [];
			foreach ( $results['whitelists'] as $rule ) {
				if ( isset( $rule['rule_v2'] ) ) {
					$rule['rules'] = $rule['rule_v2'];
					unset( $rule['rule_v2'] );
					$newRules[] = $rule;
				} else {
					$oldRules[] = $rule;
				}
			}

			// Update whitelist rules.
			update_option( 'patchstack_whitelist_rules', json_encode( $oldRules ), true );
			update_option( 'patchstack_whitelist_rules_v3', json_encode( $newRules ), true );
		}

		// Update the whitelisted keys.
		if ( isset( $results['whitelist_keys'] ) && is_array( $results['whitelist_keys'] ) ) {
			update_option( 'patchstack_whitelist_keys_rules', json_encode( $results['whitelist_keys'] ), true );
		}
	}
}
