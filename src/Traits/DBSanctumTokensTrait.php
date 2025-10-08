<?php

namespace WPSPCORE\Sanctum\Traits;

use Illuminate\Support\Str;

trait DBSanctumTokensTrait {

	public function table(): string {
		return $this->funcs->_getDBCustomMigrationTablePrefix() . 'personal_access_tokens';
	}

	public function findByToken(string $plainToken) {
		echo '<pre>'; print_r($this->id()); echo '</pre>'; die();
		global $wpdb;
		$plainToken  = explode('|', $plainToken);
		$hashedToken = hash('sha256', $plainToken[1]);
		$result      = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table()} WHERE tokenable_id = {$this->id()} AND token = %s LIMIT 1",
			$hashedToken
		));
		return $result ?: null;
	}

	public function findByTokenName(string $name) {
		global $wpdb;
		$result = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table()} WHERE tokenable_id = {$this->id()} AND name = %s LIMIT 1",
			$name
		));
		return $result ?: null;
	}

	public function createToken(string $name, array $abilities = ['*'], $expiresAt = null) {
		global $wpdb;

		// Kiểm tra nếu token đã tồn tại theo tên
		$existingToken = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$this->table()} WHERE tokenable_id = %d AND name = %s LIMIT 1",
				$this->id(),
				$name
			)
		);

		if ($existingToken) {
			return null;
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
		$expiresAt             = $this->normalizeDateTime($expiresAt);
		$refreshTokenExpiresAt = $expiresAt->modify('+30 days');

		// Thực hiện insert
		$wpdb->insert($this->table(), [
			'tokenable_type'           => 'DBAuthUser',
			'tokenable_id'             => $this->id(),
			'name'                     => $name,
			'token'                    => $tokenHash,
			'refresh_token'            => $refreshTokenHash,
			'abilities'                => json_encode($abilities),
			'expires_at'               => $expiresAt,
			'refresh_token_expires_at' => $refreshTokenExpiresAt,
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
			"SELECT * FROM {$this->table()} WHERE tokenable_id = {$this->id()} LIMIT 1",
		));
		return $result ?: null;
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
		$wpdb->update($this->table(), [
			'last_used_at' => current_time('mysql'),
		], ['id' => $tokenId]);
	}

	public function revokeCurrentToken(): bool {
		return true;
	}

	public function revokeToken(int $tokenId): bool {
		global $wpdb;
		return (bool)$wpdb->delete($this->table(), ['id' => $tokenId]);
	}

	public function revokeAllTokens(): int {
		global $wpdb;
		return (bool)$wpdb->delete($this->table(), ['tokenable_id' => $this->id()]);
	}

	public function revokeTokenByName(string $name): int {
		global $wpdb;
		return (bool)$wpdb->delete($this->table(), ['tokenable_id' => $this->id(), 'name' => $name]);
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