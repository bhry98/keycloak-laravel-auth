<?php

namespace Bhry98\KeycloakAuth\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Creativeorange\Gravatar\Facades\Gravatar;
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
        "first_name",
        "last_name",
        "name",
        "email",
        "avatar",
        "locale",
        "email_verified",
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

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function getAvatarUrlAttribute(): string
    {
        // If the user already has a custom avatar, use it
        if (!empty($this->avatar)) return $this->avatar;
        return Gravatar::get($this->email, ['size' => 200]);
    }

}
