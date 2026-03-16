<?php

namespace Bhry98\KeycloakAuth\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Creativeorange\Gravatar\Facades\Gravatar;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class KCUserModel extends Authenticatable
{
    protected $table = 'users';
    use HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        "id",
        "global_id",
        "keycloak_id",
        "keycloak_realm",
        "first_name",
        "last_name",
        "name",
        "email",
        "username",
        "avatar",
        "type",
        "locale",
        "email_verified",
        "account_enable",
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected $casts = [
        'email_verified_at' => 'datetime',
        'password' => 'hashed',
        'account_enable' => 'boolean',
    ];

    public function avatarUrl(): Attribute
    {
        return new Attribute(
            get: function () {
                if (!empty($this->avatar)) return $this->avatar;
                return Gravatar::get($this->email, ['size' => 200]);
            }
        );
    }

    public function realmRoles(): Attribute
    {
        return new Attribute(
            get: fn() => session("keycloak_realm_roles", [])
        );
    }

    public function clientRoles(): Attribute
    {
        return new Attribute(
            get: fn() => session("keycloak_client_roles", [])
        );
    }

}
