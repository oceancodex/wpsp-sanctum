<?php

namespace WPSPCORE\Sanctum\Models;

use WPSPCORE\Base\BaseInstances;

class DBPersonalAccessTokensModel extends BaseInstances {

	public $accessToken;
	public $provider;
	public $sessionKey;
	public $guardName;
	public $guardConfig;

	/*
	 *
	 */

	public function afterInstanceConstruct() {
		$this->accessToken = $this->customProperties['access_token'];
		$this->provider    = $this->customProperties['provider'];
		$this->sessionKey  = $this->customProperties['session_key'];
		$this->guardName   = $this->customProperties['guard_name'];
		$this->guardConfig = $this->customProperties['guard_config'];
	}

	/*
	 *
	 */

	public function user() {
		global $wpdb;

		// Xây dựng điều kiện WHERE với các dbIdFields
		$whereConditions = [];
		$prepareValues   = [];

		foreach ($this->provider->dbIdFields as $field) {
			$whereConditions[] = "$field = %d";
			$prepareValues[]   = $this->accessToken->tokenable_id;
		}

		$whereClause = implode(' OR ', $whereConditions);

		$query = "SELECT * FROM {$this->provider->table} WHERE {$whereClause} LIMIT 1";

		// Thêm query vào đầu mảng prepareValues để tương thích PHP 7.4
		array_unshift($prepareValues, $query);

		$result = call_user_func_array([$wpdb, 'prepare'], $prepareValues);
		$result = $wpdb->get_row($result);

		return $result;
	}

}