<?php

namespace WPSPCORE\Sanctum\Database;

use WPSP\app\Models\PersonalAccessTokenModel;

class TokenEloquent {

	public function findByToken(string $plainToken): ?PersonalAccessTokenModel {
		$hashedToken = hash('sha256', $plainToken);
		return PersonalAccessTokenModel::where('token', $hashedToken)->first();
	}

	public function createToken(int $userId, string $name, array $abilities = ['*'], $expiresAt = null): array {
		// 🔥 XÓA TOKEN CŨ CÓ CÙNG NAME (nếu tồn tại)
		try {
			PersonalAccessTokenModel::where('tokenable_id', $userId)
				->where('name', $name)
				->delete();
		}
		catch (\Exception $e) {
			// Ignore if no token exists
		}

		// Tạo token mới
		$plainToken  = bin2hex(random_bytes(40));
		$hashedToken = hash('sha256', $plainToken);

		$token = PersonalAccessTokenModel::create([
			'tokenable_type' => 'User',
			'tokenable_id'   => $userId,
			'name'           => $name,
			'token'          => $hashedToken,
			'abilities'      => $abilities,
			'expires_at'     => $expiresAt,
		]);

		return [
			'token'          => $token,
			'plainTextToken' => $plainToken,
		];
	}

	public function updateLastUsed(int $tokenId): void {
		PersonalAccessTokenModel::where('id', $tokenId)->update([
			'last_used_at' => current_time('mysql'),
		]);
	}

	public function deleteToken(int $tokenId): bool {
		return PersonalAccessTokenModel::destroy($tokenId) > 0;
	}

	public function getUserTokens(int $userId) {
		return PersonalAccessTokenModel::where('tokenable_id', $userId);
	}

	public function createSingleToken(int $userId, string $name, array $abilities = ['*'], $expiresAt = null): array {
		// Xóa TẤT CẢ token của user
		PersonalAccessTokenModel::where('tokenable_id', $userId)->delete();

		$plainToken  = bin2hex(random_bytes(40));
		$hashedToken = hash('sha256', $plainToken);

		$token = PersonalAccessTokenModel::create([
			'tokenable_type' => 'User',
			'tokenable_id'   => $userId,
			'name'           => $name,
			'token'          => $hashedToken,
			'abilities'      => $abilities,
			'expires_at'     => $expiresAt,
		]);

		return [
			'token'          => $token,
			'plainTextToken' => $plainToken,
		];
	}

}