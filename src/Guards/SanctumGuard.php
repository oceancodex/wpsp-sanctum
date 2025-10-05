<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Sanctum\Database\TokenDatabase;
use WPSPCORE\Sanctum\Sanctum;

class SanctumGuard {

	private $database;
	private $user  = null;
	private $token = null;

	public function __construct(TokenDatabase $database) {
		$this->database = $database;
	}

	public function authenticate($user_id) {
		// If already authenticated by WordPress, return that
		if ($user_id) {
			return $user_id;
		}

		// Try to authenticate via token
		$token_string = Sanctum::getTokenFromRequest();

		if (!$token_string) {
			return $user_id;
		}

		$token = $this->database->findToken($token_string);

		if (!$token || $token->isExpired()) {
			return $user_id;
		}

		$this->token = $token;
		$this->user  = $token->user();

		// Update last used timestamp
		$this->database->updateLastUsed($token->id);

		return $this->user ? $this->user->ID : $user_id;
	}

	public function restAuthenticate($result) {
		// If already authenticated or has error, return
		if ($result !== null) {
			return $result;
		}

		$token_string = Sanctum::getTokenFromRequest();

		if (!$token_string) {
			return $result;
		}

		$token = $this->database->findToken($token_string);

		if (!$token) {
			return new \WP_Error(
				'sanctum_invalid_token',
				__('Invalid authentication token.', 'wpspcore-sanctum'),
				['status' => 401]
			);
		}

		if ($token->isExpired()) {
			return new \WP_Error(
				'sanctum_token_expired',
				__('Authentication token has expired.', 'wpspcore-sanctum'),
				['status' => 401]
			);
		}

		$this->token = $token;
		$this->user  = $token->user();

		if (!$this->user) {
			return new \WP_Error(
				'sanctum_user_not_found',
				__('User not found.', 'wpspcore-sanctum'),
				['status' => 401]
			);
		}

		// Update last used timestamp
		$this->database->updateLastUsed($token->id);

		// Set current user
		wp_set_current_user($this->user->ID);

		return true;
	}

	public function user() {
		return $this->user;
	}

	public function currentAccessToken() {
		return $this->token;
	}

	public function check() {
		return $this->user !== null;
	}

	public function guest() {
		return !$this->check();
	}

}