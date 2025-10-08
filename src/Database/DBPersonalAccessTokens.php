<?php

namespace WPSPCORE\Sanctum\Database;

use WPSPCORE\Base\BaseInstances;

class DBPersonalAccessTokens extends BaseInstances {

	private string $table;

	/*
	 *
	 */

	public function afterInstanceConstruct() {
		$this->table = $this->funcs->_getDBCustomMigrationTablePrefix() . 'personal_access_tokens';
	}

	/*
	 *
	 */

	public function findByToken(string $plainToken) {
		global $wpdb;
		$plainToken  = explode('|', $plainToken);
		$hashedToken = hash('sha256', $plainToken[1]);
		$result      = $wpdb->get_row($wpdb->prepare(
			"SELECT * FROM {$this->table} WHERE token = %s LIMIT 1",
			$hashedToken
		));
		return $result ?: null;
	}

}