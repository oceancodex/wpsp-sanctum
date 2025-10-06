<?php

namespace WPSPCORE\Sanctum\Traits;

use DateTimeInterface;
use Illuminate\Support\Str;
use WPSP\app\Models\PersonalAccessTokenModel;
use WPSPCORE\Sanctum\NewAccessToken;

trait SanctumTokensTrait {

	public $accessToken;

	public static function findByToken(string $plainToken): ?PersonalAccessTokenModel {
		$hashedToken = hash('sha256', $plainToken);
		return PersonalAccessTokenModel::where('token', $hashedToken)->first();
	}

	public function createToken(string $name, array $abilities = ['*'], ?DateTimeInterface $expiresAt = null) {
		$plainTextToken = $this->generateTokenString();

		$token = $this->tokens()->create([
			'name'       => $name,
			'token'      => hash('sha256', $plainTextToken),
			'abilities'  => $abilities,
			'expires_at' => $expiresAt,
		]);

		return new NewAccessToken($token, $token->getKey() . '|' . $plainTextToken);
	}

	public function generateTokenString() {
		return sprintf(
			'%s%s%s',
			wpsp_config('sanctum.token_prefix', ''),
			$tokenEntropy = Str::random(40),
			hash('crc32b', $tokenEntropy)
		);
	}

	public function tokens() {
		return $this->morphMany(PersonalAccessTokenModel::class, 'tokenable');
	}

	public function tokenCan(string $ability): bool {
		return $this->accessToken && $this->accessToken->can($ability);
	}

	public function tokenCant(string $ability): bool {
		return !$this->tokenCan($ability);
	}

	public function currentAccessToken() {
		return $this->accessToken;
	}

	public function withAccessToken($accessToken) {
		$this->accessToken = $accessToken;
		return $this;
	}

	/*
	 *
	 */

	public function updateTokenLastUsed(int $tokenId): void {
		PersonalAccessTokenModel::where('id', $tokenId)->update([
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

		return PersonalAccessTokenModel::destroy($tokenId) > 0;
	}

	public function revokeToken(int $tokenId): bool {
		return PersonalAccessTokenModel::destroy($tokenId) > 0;
	}

	public function revokeAllTokens(): int {
		$userId = $this->id ?? $this->ID;
		return PersonalAccessTokenModel::where('tokenable_id', $userId)->delete();
	}

	public function revokeTokenByName(string $name): int {
		$userId = $this->id ?? $this->ID;
		return PersonalAccessTokenModel::where('tokenable_id', $userId)
			->where('name', $name)
			->delete();
	}

}