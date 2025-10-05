<?php

namespace WPSPCORE\Sanctum\Traits;

use WPSPCORE\Sanctum\Database\TokenDatabase;

trait HasApiTokens {

	protected $tokenDatabase = null;

	protected function getTokenDatabase() {
		if ($this->tokenDatabase === null) {
			$this->tokenDatabase = new TokenDatabase();
		}
		return $this->tokenDatabase;
	}

	/**
	 * Create a new personal access token
	 *
	 * @param string         $name       Token name
	 * @param array          $abilities  Token abilities/permissions
	 * @param \DateTime|null $expires_at Expiration date
	 *
	 * @return array
	 */
	public function createToken($name, array $abilities = ['*'], $expires_at = null) {
		$user_id = $this->ID ?? get_current_user_id();

		if ($expires_at instanceof \DateTime) {
			$expires_at = $expires_at->format('Y-m-d H:i:s');
		}

		return $this->getTokenDatabase()->createToken($user_id, $name, $abilities, $expires_at);
	}

	/**
	 * Get all tokens for the user
	 *
	 * @return array
	 */
	public function tokens() {
		$user_id = $this->ID ?? get_current_user_id();
		return $this->getTokenDatabase()->getUserTokens($user_id);
	}

	/**
	 * Get the current access token
	 *
	 * @return \WPSPCORE\Sanctum\Models\PersonalAccessToken|null
	 */
	public function currentAccessToken() {
		$sanctum = \WPSPCORE\Sanctum\Sanctum::getInstance();
		return $sanctum->getGuard()->currentAccessToken();
	}

	/**
	 * Revoke a specific token
	 *
	 * @param int $token_id
	 *
	 * @return bool
	 */
	public function revokeToken($token_id) {
		return $this->getTokenDatabase()->deleteToken($token_id);
	}

	/**
	 * Revoke all tokens for the user
	 *
	 * @return bool
	 */
	public function revokeAllTokens() {
		$user_id = $this->ID ?? get_current_user_id();
		return $this->getTokenDatabase()->revokeAllTokens($user_id);
	}

	/**
	 * Check if user has a specific ability on current token
	 *
	 * @param string $ability
	 *
	 * @return bool
	 */
	public function tokenCan($ability) {
		$token = $this->currentAccessToken();

		if (!$token) {
			return false;
		}

		return $token->can($ability);
	}

}