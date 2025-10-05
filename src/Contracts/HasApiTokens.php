<?php

namespace WPSPCORE\Sanctum\Contracts;

interface HasApiTokens {

	/**
	 * Create a new personal access token
	 *
	 * @param string         $name
	 * @param array          $abilities
	 * @param \DateTime|null $expires_at
	 *
	 * @return array
	 */
	public function createToken($name, array $abilities = ['*'], $expires_at = null);

	/**
	 * Get all tokens for the user
	 *
	 * @return array
	 */
	public function tokens();

	/**
	 * Get the current access token
	 *
	 * @return \WPSPCORE\Sanctum\Models\PersonalAccessToken|null
	 */
	public function currentAccessToken();

	/**
	 * Revoke a specific token
	 *
	 * @param int $token_id
	 *
	 * @return bool
	 */
	public function revokeToken($token_id);

	/**
	 * Revoke all tokens for the user
	 *
	 * @return bool
	 */
	public function revokeAllTokens();

	/**
	 * Check if user has a specific ability on current token
	 *
	 * @param string $ability
	 *
	 * @return bool
	 */
	public function tokenCan($ability);

}