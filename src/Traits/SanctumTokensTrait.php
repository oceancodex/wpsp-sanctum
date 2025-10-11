<?php

namespace WPSPCORE\Sanctum\Traits;

use Illuminate\Support\Str;

trait SanctumTokensTrait {

	public function personalAccessTokensModel() {
		return $this->funcs->_config('sanctum.model_class');
	}

	/*
	 *
	 */

	public function createToken($name, $abilities = ['*'], $expiresAt = null, $checkDuplicate = false) {
		// Kiểm tra nếu token đã tồn tại theo tên
		if ($checkDuplicate) {
			$exitsToken = $this->findByTokenName($name);
		}

		if (!isset($exitsToken) || !$exitsToken) {
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

			$expiresAt             = $this->funcs->_normalizeDateTime($expiresAt);
			$refreshTokenExpiresAt = $expiresAt->modify('+30 days');

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
		return $this->morphMany($this->personalAccessTokensModel(), 'tokenable');
	}

	public function tokenCan($ability) {
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

	public function tokenCant($ability) {
		return !$this->tokenCan($ability);
	}

	/*
	 *
	 */

	public function updateTokenLastUsed($tokenId) {
		$this->tokens()->where('id', $tokenId)->update([
			'last_used_at' => current_time('mysql'),
		]);
	}

	public function revokeCurrentToken() {
		$plainToken = $this->funcs->_getBearerToken();
		if (!$plainToken) {
			return false;
		}
		$token = $this->findByToken($plainToken);

		if (!$token) {
			return false;
		}

		return $this->tokens()->delete($token->id ?? $token->ID ?? 0) > 0;
	}

	public function revokeToken($tokenId) {
		return $this->tokens()->delete($tokenId) > 0;
	}

	public function revokeAllTokens() {
		$userId = $this->id ?? $this->ID;
		return $this->tokens()->where('tokenable_id', $userId)->delete();
	}

	public function revokeTokenByName($name) {
		$userId = $this->id ?? $this->ID;
		return $this->tokens()->where('tokenable_id', $userId)
			->where('name', $name)
			->delete();
	}

	/*
	 *
	 */

	public function findByToken( $plainToken) {
		$plainToken  = explode('|', $plainToken);
		$hashedToken = hash('sha256', $plainToken[1]);
		return $this->tokens()->where('token', $hashedToken)->first();
	}

	public function findByTokenName($name) {
		return $this->tokens()->where('name', $name)->first();
	}

}