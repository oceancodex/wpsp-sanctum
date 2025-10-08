<?php

namespace WPSPCORE\Sanctum\Traits;

use Carbon\Carbon;
use Carbon\CarbonInterval;
use Illuminate\Support\Str;
use WPSP\app\Models\PersonalAccessTokenModel;
use WPSPCORE\Sanctum\NewAccessToken;

trait SanctumTokensTrait {

	public function findByToken(string $plainToken) {
		$plainToken  = explode('|', $plainToken);
		$hashedToken = hash('sha256', $plainToken[1]);
		return $this->tokens()->where('token', $hashedToken)->first();
	}

	public function findByTokenName(string $name) {
		return $this->tokens()->where('name', $name)->first();
	}

	public function createToken(string $name, array $abilities = ['*'], $expiresAt = null) {
		$exitsToken = $this->findByTokenName($name);
		if (!$exitsToken) {
			$plainToken = sprintf(
				'%s%s%s',
				$this->funcs->_config('sanctum.token_prefix', ''),
				$tokenEntropy = Str::random(64),
				hash('crc32b', $tokenEntropy)
			);

			$plainRefreshToken = sprintf(
				'%s%s%s',
				$this->funcs->_config('sanctum.token_prefix', ''),
				$tokenEntropy = Str::random(64),
				hash('crc32b', $tokenEntropy)
			);

			$token        = hash('sha256', $plainToken);
			$refreshToken = hash('sha256', $plainRefreshToken);

			$expiresAt             = $this->normalizeDateTime($expiresAt);
			$refreshTokenExpiresAt = $expiresAt->copy()->addDays(30);

			$token = $this->tokens()->create([
				'name'                     => $name,
				'token'                    => $token,
				'refresh_token'            => $refreshToken,
				'abilities'                => $abilities,
				'expires_at'               => $expiresAt,
				'refresh_token_expires_at' => $refreshTokenExpiresAt,
			]);

			return [
				'token'         => $token->getKey() . '|' . $plainToken,
				'refresh_token' => $plainRefreshToken,
			];
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

	/*
	 *
	 */

	public function normalizeDateTime($value): \DateTimeInterface {
		$now     = new \DateTimeImmutable('now', wp_timezone()); // hoặc new \DateTimeImmutable('now')
		$default = $now->modify('+7 days');

		// Nếu null hoặc rỗng → +7 ngày
		if (empty($value)) {
			return $default;
		}

		// Nếu đã là DateTimeInterface (DateTime, DateTimeImmutable, ...)
		if ($value instanceof \DateTimeInterface) {
			return $value;
		}

		// Nếu là timestamp (số)
		if (is_numeric($value)) {
			try {
				return (new \DateTimeImmutable('@' . (int)$value))->setTimezone(wp_timezone());
			}
			catch (\Exception) {
				return $default;
			}
		}

		// Nếu là chuỗi định dạng ngày chuẩn (YYYY-MM-DD, v.v.)
		try {
			$parsed = new \DateTimeImmutable($value, wp_timezone());
			if ($parsed >= $now) {
				return $parsed;
			}
		}
		catch (\Exception) {
			// bỏ qua, thử kiểu khác
		}

		// Nếu là chuỗi tự nhiên như “1 year”, “6 months”, “2 weeks”, v.v.
		$timestamp = strtotime($value, $now->getTimestamp());
		if ($timestamp !== false && $timestamp >= $now->getTimestamp()) {
			return (new \DateTimeImmutable('@' . $timestamp))->setTimezone(wp_timezone());
		}

		// Nếu không parse được → mặc định +7 ngày
		return $default;
	}

}