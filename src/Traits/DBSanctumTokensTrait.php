<?php

namespace WPSPCORE\Sanctum\Traits;

use Illuminate\Support\Str;
use WPSPCORE\Sanctum\Database\DBPersonalAccessTokens;

trait DBSanctumTokensTrait {

	private function personalAccessTokensTable(): string {
		return $this->funcs->_getDBCustomMigrationTablePrefix() . 'personal_access_tokens';
	}

	private function DBPersonalAccessTokens(): DBPersonalAccessTokens {
		return new DBPersonalAccessTokens(
			$this->funcs->_getMainPath(),
			$this->funcs->_getRootNamespace(),
			$this->funcs->_getPrefixEnv(),
			[
				'provider'     => $this->customProperties['provider'],
				'session_key'  => $this->customProperties['session_key'],
				'guard_name'   => $this->customProperties['guard_name'],
				'guard_config' => $this->customProperties['guard_config'],
			]
		);
	}

	/*
	 *
	 */

	public function createToken(string $name, array $abilities = ['*'], $expiresAt = null, $checkDuplicate = false) {
		global $wpdb;

		// Kiểm tra nếu token đã tồn tại theo tên
		if ($checkDuplicate) {
			$existingToken = $wpdb->get_row(
				$wpdb->prepare(
					"SELECT * FROM {$this->personalAccessTokensTable()} WHERE tokenable_id = %d AND name = %s LIMIT 1",
					$this->id(),
					$name
				)
			);

			if ($existingToken) {
				return null;
			}
		}

		// Sinh token & refresh token ngẫu nhiên
		$plainToken = sprintf(
			'%s%s%s',
			$this->funcs->_config('sanctum.token_prefix', ''),
			$tokenEntropy = Str::random(64),
			hash('crc32b', $tokenEntropy)
		);

		$plainRefreshToken = sprintf(
			'%s%s%s',
			$this->funcs->_config('sanctum.token_prefix', ''),
			$refreshEntropy = Str::random(64),
			hash('crc32b', $refreshEntropy)
		);

		// Băm token để lưu trữ
		$tokenHash        = hash('sha256', $plainToken);
		$refreshTokenHash = hash('sha256', $plainRefreshToken);

		// Chuẩn hóa expires_at
		$expiresAt             = $this->funcs->_normalizeDateTime($expiresAt);
		$refreshTokenExpiresAt = $expiresAt->modify('+30 days');

		// Thực hiện insert
		$wpdb->insert($this->personalAccessTokensTable(), [
			'tokenable_type'           => 'DBAuthUser',
			'tokenable_id'             => $this->id(),
			'name'                     => $name,
			'token'                    => $tokenHash,
			'refresh_token'            => $refreshTokenHash,
			'abilities'                => json_encode($abilities),
			'expires_at'               => $expiresAt->format('Y-m-d H:i:s'),
			'refresh_token_expires_at' => $refreshTokenExpiresAt->format('Y-m-d H:i:s'),
			'created_at'               => current_time('mysql'),
			'updated_at'               => current_time('mysql'),
		]);

		$tokenId = $wpdb->insert_id;

		return [
			'token'         => $tokenId . '|' . $plainToken,
			'refresh_token' => $plainRefreshToken,
		];
	}

	public function tokens() {
		global $wpdb;
		$result = $wpdb->get_results($wpdb->prepare(
			"SELECT * FROM {$this->personalAccessTokensTable()} WHERE tokenable_id = {$this->id()} LIMIT 1",
		));
		return $result ?: null;
	}

	public function tokenCan(string $ability): bool {
		$plainToken = $this->funcs->_getBearerToken();
		if (!$plainToken) {
			return false;
		}

		$token = $this->DBPersonalAccessTokens()->findByToken($plainToken);

		if (!$token) {
			return false;
		}

		// Kiểm tra token có hết hạn không
		if ($token->expires_at && strtotime($token->expires_at) < time()) {
			return false;
		}

		// Parse abilities từ JSON
		$abilities = json_decode($token->abilities, true) ?: [];

		// Nếu có '*' thì có tất cả quyền
		if (in_array('*', $abilities)) {
			return true;
		}

		// Kiểm tra ability cụ thể
		return in_array($ability, $abilities);
	}

	public function tokenCant(string $ability): bool {
		return !$this->tokenCan($ability);
	}

	/*
	 *
	 */

	public function updateTokenLastUsed(int $tokenId): void {
		global $wpdb;
		$wpdb->update($this->personalAccessTokensTable(), [
			'last_used_at' => current_time('mysql'),
		], ['id' => $tokenId]);
	}

	public function revokeToken(int $tokenId): bool {
		global $wpdb;
		return (bool)$wpdb->delete($this->personalAccessTokensTable(), ['id' => $tokenId]);
	}

	public function revokeAllTokens(): int {
		global $wpdb;
		return (bool)$wpdb->delete($this->personalAccessTokensTable(), ['tokenable_id' => $this->id()]);
	}

	public function revokeTokenByName(string $name): int {
		global $wpdb;
		return (bool)$wpdb->delete($this->personalAccessTokensTable(), ['tokenable_id' => $this->id(), 'name' => $name]);
	}

}