<?php

namespace WPSPCORE\Sanctum\Traits;

use WPSPCORE\Sanctum\Database\TokenDatabase;
use WPSPCORE\Sanctum\Database\TokenRepository;

trait HasSanctumTokens {

	public $currentAccessToken;

	public function createToken(string $name, array $abilities = ['*'], $expiresAt = null): array {
		$repository = $this->getTokenRepository();

		$userId = $this->id ?? $this->ID;
		return $repository->createToken($userId, $name, $abilities, $expiresAt);
	}

	public function tokens() {
		$repository = $this->getTokenRepository();
		$userId     = $this->id ?? $this->ID;
		return $repository->getUserTokens($userId);
	}

	public function tokenCan(string $ability): bool {
		if (!$this->currentAccessToken) {
			return false;
		}

		$abilities = $this->currentAccessToken['abilities'] ?? ($this->currentAccessToken->abilities ?? []);

		if (in_array('*', $abilities)) {
			return true;
		}

		return in_array($ability, $abilities);
	}

	private function getTokenRepository() {
		if (class_exists('\WPSPCORE\Database\Eloquent')) {
			return new TokenRepository();
		}
		return new TokenDatabase();
	}

}