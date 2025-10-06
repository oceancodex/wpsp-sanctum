<?php

namespace WPSPCORE\Sanctum\Database;

use WPSPCORE\Base\BaseInstances;

class DBPersonalAccessToken extends BaseInstances {

	private $tableName;

	public function afterInstanceConstruct() {
		global $wpdb;
		$this->tableName = $wpdb->prefix . $this->funcs->_getAppShortName() . 'cm_personal_access_tokens';
	}

	public function findByToken(string $plainToken): ?array {
		global $wpdb;

		$hashedToken = hash('sha256', $plainToken);

		$result = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->tableName} WHERE token = %s LIMIT 1",
			$hashedToken
		), ARRAY_A);

		return $result ?: null;
	}

	public function createToken(int $userId, string $name, array $abilities = ['*'], $expiresAt = null): array {
		global $wpdb;

		// 🔥 XÓA TOKEN CŨ CÓ CÙNG NAME
		$this->deleteTokenByName($userId, $name);

		$plainToken  = bin2hex(random_bytes(40));
		$hashedToken = hash('sha256', $plainToken);

		$wpdb->insert($this->tableName, [
			'tokenable_type' => 'User',
			'tokenable_id'   => $userId,
			'name'           => $name,
			'token'          => $hashedToken,
			'abilities'      => json_encode($abilities),
			'expires_at'     => $expiresAt,
			'created_at'     => current_time('mysql'),
			'updated_at'     => current_time('mysql'),
		]);

		$tokenId = $wpdb->insert_id;

		return [
			'plain_token'  => $plainToken,
			'access_token' => $wpdb->get_row("SELECT * FROM {$this->tableName} WHERE id = {$tokenId}", ARRAY_A),
		];
	}

	private function deleteTokenByName(int $userId, string $name): void {
		global $wpdb;
		$wpdb->delete($this->tableName, [
			'tokenable_id' => $userId,
			'name'         => $name,
		], ['%d', '%s']);
	}

	public function updateLastUsed(int $tokenId): void {
		global $wpdb;
		$wpdb->update($this->tableName, [
			'last_used_at' => current_time('mysql'),
		], ['id' => $tokenId]);
	}

	public function deleteToken(int $tokenId): bool {
		global $wpdb;
		return (bool)$wpdb->delete($this->tableName, ['id' => $tokenId]);
	}

	public function getUserTokens(int $userId): array {
		global $wpdb;

		$results = $wpdb->get_results($wpdb->prepare(
			"SELECT * FROM {$this->tableName} WHERE tokenable_id = %d ORDER BY created_at DESC",
			$userId
		), ARRAY_A);

		return $results ?: [];
	}

	public function createSingleToken(int $userId, string $name, array $abilities = ['*'], $expiresAt = null): array {
		global $wpdb;

		// Xóa TẤT CẢ token của user
		$wpdb->delete($this->tableName, [
			'tokenable_id' => $userId,
		], ['%d']);

		$plainToken  = bin2hex(random_bytes(40));
		$hashedToken = hash('sha256', $plainToken);

		$wpdb->insert($this->tableName, [
			'tokenable_type' => 'User',
			'tokenable_id'   => $userId,
			'name'           => $name,
			'token'          => $hashedToken,
			'abilities'      => json_encode($abilities),
			'expires_at'     => $expiresAt,
			'created_at'     => current_time('mysql'),
			'updated_at'     => current_time('mysql'),
		]);

		$tokenId = $wpdb->insert_id;

		return [
			'plain_token'  => $plainToken,
			'access_token' => $wpdb->get_row("SELECT * FROM {$this->tableName} WHERE id = {$tokenId}", ARRAY_A),
		];
	}

}