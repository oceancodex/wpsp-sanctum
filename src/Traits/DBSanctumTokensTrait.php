<?php

namespace WPSPCORE\Sanctum\Traits;

use DateTimeInterface;
use Illuminate\Support\Str;
use WPSPCORE\Sanctum\NewAccessToken;

trait DBSanctumTokensTrait {

	public function table(): string {
		return $this->funcs->_getDBCustomMigrationTablePrefix() . 'personal_access_tokens';
	}

	public function findByToken(string $plainToken) {
		global $wpdb;
		$plainToken  = explode('|', $plainToken);
		$hashedToken = hash('sha256', $plainToken[1]);
		$result      = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table()} WHERE tokenable_id = {$this->id()} WHERE token = %s LIMIT 1",
			$hashedToken
		));
		return $result ?: null;
	}

	public function findByTokenName(string $name) {
		global $wpdb;
		$result = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table()} WHERE tokenable_id = {$this->id()} WHERE name = %s LIMIT 1",
			$name
		));
		return $result ?: null;
	}

	public function createToken(string $name, array $abilities = ['*'], $expiresAt = null) {
		global $wpdb;

		$plainToken = sprintf(
			'%s%s%s',
			$this->funcs->_config('sanctum.token_prefix', ''),
			$tokenEntropy = Str::random(40),
			hash('crc32b', $tokenEntropy)
		);

		$wpdb->insert($this->table(), [
			'tokenable_type' => 'DBAuthUser',
			'tokenable_id'   => $this->id(),
			'name'           => $name,
			'token'          => hash('sha256', $plainToken),
			'abilities'      => json_encode($abilities),
			'expires_at'     => $expiresAt,
			'created_at'     => current_time('mysql'),
			'updated_at'     => current_time('mysql'),
		]);

		$tokenId = $wpdb->insert_id;

		return new NewAccessToken($tokenId . '|' . $plainToken, $plainToken);

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

}