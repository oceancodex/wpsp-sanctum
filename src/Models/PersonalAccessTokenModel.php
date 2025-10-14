<?php

namespace WPSPCORE\Sanctum\Models;

use Illuminate\Database\Eloquent\SoftDeletes;
use WPSPCORE\Database\Base\BaseModel;
use WPSPCORE\Traits\ObserversTrait;

class PersonalAccessTokenModel extends BaseModel {

	use SoftDeletes, ObserversTrait;

	protected $connection = 'wordpress';
//	protected $prefix     = 'wp_wpsp_';
	protected $table      = 'cm_personal_access_tokens';                  // If this table created by custom migration, you need to add prefix "cm_" to the table name, like this: "cm_"
//	protected $primaryKey = 'id';

//	protected $appends;
//	protected $attributeCastCache;
//	protected $attributes;
	protected $casts      = [
		'abilities'                => 'json',
		'last_used_at'             => 'datetime',
		'expires_at'               => 'datetime',
		'refresh_token_expires_at' => 'datetime',
	];
//	protected $changes;
//	protected $classCastCache;
//	protected $dateFormat;
//	protected $dispatchesEvents;
//	protected $escapeWhenCastingToString;
	protected $fillable   = [
		'name',
		'token',
		'refresh_token',
		'abilities',
		'expires_at',
		'refresh_token_expires_at',
	];
//	protected $forceDeleting;
	protected $guarded    = [];
	protected $hidden     = [
		'token',
	];
//	protected $keyType;
//	protected $observables;
//	protected $original;
//	protected $perPage;
//	protected $relations;
//	protected $touches;
//	protected $visible;
//	protected $with;
//	protected $withCount;

//	public    $exists;
//	public    $incrementing;
//	public    $preventsLazyLoading;
//	public    $timestamps;
//	public    $usesUniqueIds;
//	public    $wasRecentlyCreated;

//	protected static $observers = [
//		\WPSP\app\Observers\PersonalAccessTokenModelObserver::class,
//	];

//	public function __construct($attributes = []) {
//		$this->getConnection()->setTablePrefix('wp_wpsp_');
//		$this->setConnection('wordpress');
//		parent::__construct($attributes);
//	}

}
