<?php

namespace WPSPCORE\Sanctum\Guards;

class SessionGuard {

	/**
	 * Authenticate via session
	 * Returns authenticated user or null
	 */
	public function authenticate() {
		// Check if WordPress session exists
		if (!is_user_logged_in()) {
			return null;
		}

		$wpUser = wp_get_current_user();

		// Try to get Eloquent user if available
		if (class_exists('\WPSP\app\Models\UsersModel')) {
			$user = \WPSP\app\Models\UsersModel::find($wpUser->ID);
			if ($user) {
				return $user;
			}
		}

		// Return WP_User
		return $wpUser;
	}

	/**
	 * Check if request is from same origin (SPA)
	 */
	public function isFromSPA(): bool {
		$referer = $_SERVER['HTTP_REFERER'] ?? '';
		$origin  = $_SERVER['HTTP_ORIGIN'] ?? '';
		$siteUrl = get_site_url();

		return (strpos($referer, $siteUrl) === 0 || strpos($origin, $siteUrl) === 0);
	}

}