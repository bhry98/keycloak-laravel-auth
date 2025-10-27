<?php

namespace Bhry98\KeycloakAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasOne;

class KCUserAttributesModel extends Model
{
    protected $table = 'users_attributes';
    protected $fillable = [
        'id',
        'user_id',
        'key',
        'value',
    ];

    public function user(): HasOne
    {
        return $this->hasOne(KCUserModel::class, 'id', 'user_id');
    }
}
