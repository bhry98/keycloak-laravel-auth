<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Models;

use Bhry98\KeycloakAuth\Concerns\HasKeycloakRoles;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

/**
 * Default users model. Point `bhry98-keycloak.users_model` at your own
 * model (and `use HasKeycloakRoles;` on it) to replace it.
 *
 * @property int $id
 * @property string $keycloak_id
 * @property string|null $email
 * @property-read string $avatar_url
 * @property-read array<int, string> $realm_roles
 * @property-read array<int, string> $client_roles
 */
class KCUserModel extends Authenticatable
{
    use HasFactory, HasKeycloakRoles, Notifiable;

    protected $table = 'users';

    /** @var list<string> */
    protected $fillable = [
        'id',
        'global_id',
        'keycloak_id',
        'keycloak_realm',
        'first_name',
        'last_name',
        'name',
        'email',
        'username',
        'avatar',
        'type',
        'locale',
        'email_verified',
        'account_enable',
    ];

    /** @var list<string> */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'email_verified' => 'boolean',
            'account_enable' => 'boolean',
        ];
    }

    public function keycloakAttributes(): HasMany
    {
        return $this->hasMany(KCUserAttributesModel::class, 'user_id');
    }

    /** Keycloak picture claim, falling back to Gravatar. */
    protected function avatarUrl(): Attribute
    {
        return Attribute::get(function (): string {
            if (! empty($this->avatar)) {
                return (string) $this->avatar;
            }

            $hash = hash('sha256', strtolower(trim((string) $this->email)));

            return "https://www.gravatar.com/avatar/{$hash}?s=200&d=identicon";
        });
    }

    protected function realmRoles(): Attribute
    {
        return Attribute::get(fn (): array => $this->keycloakToken()?->realmRoles() ?? (array) session('keycloak_realm_roles', []));
    }

    protected function clientRoles(): Attribute
    {
        return Attribute::get(fn (): array => $this->keycloakToken()?->clientRoles() ?? (array) session('keycloak_client_roles', []));
    }
}
