<?php

namespace WPSPCORE\Sanctum\Database;

use WPSPCORE\Sanctum\Models\PersonalAccessToken;

class TokenDatabase {

	private $table_name;

	public function __construct() {
		global $wpdb;
		$this->table_name = 'wp_wpsp_cm_personal_access_tokens';
	}

	public function findToken($token) {
		global $wpdb;

		// QUAN TRỌNG: Hash plain token trước khi query
		$hashed_token = hash('sha256', $token);

		// Query database với hashed token
		$result = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT * FROM {$this->table_name} WHERE token = %s LIMIT 1",
				$hashed_token  // ← Sử dụng hashed token
			),
			ARRAY_A
		);

		if (!$result) {
			return null;
		}

		return new PersonalAccessToken($result);
	}

	public function createToken($user_id, $name, $abilities = ['*'], $expires_at = null) {
		global $wpdb;

		$plain_token  = bin2hex(random_bytes(32));
		$hashed_token = hash('sha256', $plain_token);

		$now = current_time('mysql');

		$wpdb->insert(
			$this->table_name,
			[
				'tokenable_type' => 'WP_User',
				'tokenable_id'   => $user_id,
				'name'           => $name,
				'token'          => $hashed_token,
				'abilities'      => json_encode($abilities),
				'expires_at'     => $expires_at,
				'created_at'     => $now,
				'updated_at'     => $now,
			],
			['%s', '%d', '%s', '%s', '%s', '%s', '%s', '%s']
		);

		$token_id = $wpdb->insert_id;

		return [
			'token_id'       => $token_id,
			'plainTextToken' => $plain_token,
			'accessToken'    => new PersonalAccessToken([
				'id'             => $token_id,
				'tokenable_type' => 'WP_User',
				'tokenable_id'   => $user_id,
				'name'           => $name,
				'token'          => $hashed_token,
				'abilities'      => json_encode($abilities),
				'expires_at'     => $expires_at,
				'created_at'     => $now,
				'updated_at'     => $now,
			]),
		];
	}

	public function updateLastUsed($token_id) {
		global $wpdb;

		$wpdb->update(
			$this->table_name,
			['last_used_at' => current_time('mysql')],
			['id' => $token_id],
			['%s'],
			['%d']
		);
	}

	public function deleteToken($token_id) {
		global $wpdb;

		return $wpdb->delete(
			$this->table_name,
			['id' => $token_id],
			['%d']
		);
	}

	public function getUserTokens($user_id) {
		global $wpdb;

		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$this->table_name} WHERE tokenable_id = %d AND tokenable_type = 'WP_User'",
				$user_id
			),
			ARRAY_A
		);

		return array_map(function($row) {
			return new PersonalAccessToken($row);
		}, $results);
	}

	public function revokeAllTokens($user_id) {
		global $wpdb;

		return $wpdb->delete(
			$this->table_name,
			[
				'tokenable_id'   => $user_id,
				'tokenable_type' => 'WP_User',
			],
			['%d', '%s']
		);
	}

}