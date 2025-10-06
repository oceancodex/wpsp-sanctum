<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Sanctum\Database\TokenDatabase;
use WPSPCORE\Sanctum\Database\TokenRepository;
use WPSPCORE\Sanctum\Models\PersonalAccessToken;

class TokenGuard {

	private $repository;
	private $currentToken = null;

	public function __construct(bool $useEloquent = true) {
		if ($useEloquent && class_exists('\WPSPCORE\Database\Eloquent')) {
			$this->repository = new TokenRepository();
		}
		else {
			$this->repository = new TokenDatabase();
		}
	}

	/**
	 * Authenticate via Bearer token
	 * Returns authenticated user object with token attached
	 */
	public function authenticate(string $plainToken) {
		$token = $this->repository->findByToken($plainToken);

		if (!$token || $this->isExpired($token)) {
			return null;
		}

		// Update last used
		$this->repository->updateLastUsed($token['id'] ?? $token->id);

		// Get user
		$userId = $token['tokenable_id'] ?? $token->tokenable_id;
		$user   = $this->getUserById($userId);

		if (!$user) {
			return null;
		}

		// Attach token to user
		$this->currentToken       = $token;
		$user->currentAccessToken = $token;

		return $user;
	}

	/**
	 * Get current token
	 */
	public function currentToken() {
		return $this->currentToken;
	}

	/**
	 * Check if token is expired
	 */
	private function isExpired($token): bool {
		$expiresAt = $token['expires_at'] ?? ($token->expires_at ?? null);
		if (!$expiresAt) return false;

		$expiresTimestamp = is_string($expiresAt) ? strtotime($expiresAt) : $expiresAt->getTimestamp();
		return $expiresTimestamp < time();
	}

	/**
	 * Get user by ID
	 */
	private function getUserById(int $userId) {
		// Try Eloquent first
		if (class_exists('\WPSP\app\Models\UsersModel')) {
			return \WPSP\app\Models\UsersModel::find($userId);
		}

		// Fallback to WP_User
		return get_user_by('id', $userId);
	}

}