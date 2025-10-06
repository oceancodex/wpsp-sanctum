<?php

namespace WPSPCORE\Sanctum\Guards;

use WPSPCORE\Sanctum\Database\DBPersonalAccessToken;
use WPSPCORE\Sanctum\Database\TokenEloquent;
use WPSPCORE\Sanctum\Models\PersonalAccessToken;

class TokenGuard {

	private $repository;
	private $currentToken = null;

	public function __construct() {
		if (class_exists('\WPSPCORE\Database\Eloquent')) {
			$this->repository = new TokenEloquent();
		}
		else {
			$this->repository = new DBPersonalAccessToken();
		}
	}

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
		$this->currentToken = $token;
		$user->accessToken  = $token;

		return $user;
	}

	public function currentToken() {
		return $this->currentToken;
	}

	private function isExpired($token): bool {
		$expiresAt = $token['expires_at'] ?? ($token->expires_at ?? null);
		if (!$expiresAt) return false;

		$expiresTimestamp = is_string($expiresAt) ? strtotime($expiresAt) : $expiresAt->getTimestamp();
		return $expiresTimestamp < time();
	}

	private function getUserById(int $userId) {
		// Try Eloquent first
		if (class_exists('\WPSP\app\Models\UsersModel')) {
			return \WPSP\app\Models\UsersModel::find($userId);
		}

		// Fallback to WP_User
		return get_user_by('id', $userId);
	}

}