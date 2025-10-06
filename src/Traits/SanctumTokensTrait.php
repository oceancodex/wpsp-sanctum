<?php

namespace WPSPCORE\Sanctum\Traits;

use DateTimeInterface;
use Illuminate\Support\Str;
use WPSP\app\Models\PersonalAccessTokenModel;
use WPSPCORE\Sanctum\NewAccessToken;

trait SanctumTokensTrait {

	public function findByToken(string $plainToken): ?PersonalAccessTokenModel {
		$plainToken  = explode('|', $plainToken);
		$hashedToken = hash('sha256', $plainToken[1]);
		return $this->tokens()->where('token', $hashedToken)->first();
	}

	public function findByTokenName(string $name): ?PersonalAccessTokenModel {
		return $this->tokens()->where('name', $name)->first();
	}

	public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null) {
		$exitsToken = $this->findByTokenName($name);
		if (!$exitsToken) {
			$plainToken = sprintf(
				'%s%s%s',
				$this->funcs->_config('sanctum.token_prefix', ''),
				$tokenEntropy = Str::random(40),
				hash('crc32b', $tokenEntropy)
			);

			$token = $this->tokens()->create([
				'name'       => $name,
				'token'      => hash('sha256', $plainToken),
				'abilities'  => $abilities,
				'expires_at' => $expiresAt,
			]);

			return new NewAccessToken($token, $token->getKey() . '|' . $plainToken);
		}
		else {
			return null;
		}
	}

	public function tokens() {
		return $this->morphMany(PersonalAccessTokenModel::class, 'tokenable');
	}

	public function tokenCan(string $ability): bool {
		$plainToken = $this->funcs->_getBearerToken();
		if (!$plainToken) {
			return false;
		}
		$token = $this->findByToken($plainToken);
		if (!$token) {
			return false;
		}
		return $token->can($ability);
	}

	public function tokenCant(string $ability): bool {
		return !$this->tokenCan($ability);
	}

	/*
	 *
	 */

	public function updateTokenLastUsed(int $tokenId): void {
		$this->tokens()->where('id', $tokenId)->update([
			'last_used_at' => current_time('mysql'),
		]);
	}

	public function revokeCurrentToken(): bool {
		if (!$this->accessToken) {
			return false;
		}

		$tokenId = $this->accessToken['id']
			?? ($this->accessToken->id ?? null);

		if (!$tokenId) {
			return false;
		}

		return $this->tokens()->delete($tokenId) > 0;
	}

	public function revokeToken(int $tokenId): bool {
		return $this->tokens()->delete($tokenId) > 0;
	}

	public function revokeAllTokens(): int {
		$userId = $this->id ?? $this->ID;
		return $this->tokens()->where('tokenable_id', $userId)->delete();
	}

	public function revokeTokenByName(string $name): int {
		$userId = $this->id ?? $this->ID;
		return $this->tokens()->where('tokenable_id', $userId)
			->where('name', $name)
			->delete();
	}

}