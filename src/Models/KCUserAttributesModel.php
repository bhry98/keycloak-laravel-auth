<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class KCUserAttributesModel extends Model
{
    protected $table = 'users_attributes';

    public $timestamps = false;

    /** @var list<string> */
    protected $fillable = [
        'id',
        'user_id',
        'key',
        'value',
    ];

    public function user(): BelongsTo
    {
        /** @var class-string<Model> $model */
        $model = config('bhry98-keycloak.users_model', KCUserModel::class);

        return $this->belongsTo($model, 'user_id');
    }
}
