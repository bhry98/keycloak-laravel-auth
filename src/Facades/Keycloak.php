<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Facades;

use Bhry98\KeycloakAuth\KeycloakManager;
use Illuminate\Support\Facades\Facade;

/**
 * @method static \Bhry98\KeycloakAuth\Support\RealmConfig realm(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Token\KeycloakToken validate(string $jwt, \Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Token\KeycloakToken|null check(string $jwt, \Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Token\KeycloakToken decode(string $jwt, \Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Token\KeycloakToken|null token(\Illuminate\Http\Request|null $request = null)
 * @method static void setToken(\Bhry98\KeycloakAuth\Token\KeycloakToken $token, \Illuminate\Http\Request|null $request = null)
 * @method static \Bhry98\KeycloakAuth\Oidc\OidcClient oidc(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Admin\AdminClient admin(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Admin\Resources\Users users(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Admin\Resources\Roles roles(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Admin\Resources\Groups groups(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\Admin\Resources\Clients clients(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null)
 * @method static string serviceToken(\Bhry98\KeycloakAuth\Support\RealmConfig|string|null $guard = null, string|null $scope = null)
 * @method static \Bhry98\KeycloakAuth\Services\KeycloakSocialiteProvider socialite(string|null $guard = null)
 * @method static \Bhry98\KeycloakAuth\KeycloakManager resolveUserUsing(callable $callback)
 * @method static \Bhry98\KeycloakAuth\Auth\UserProvisioner provisioner()
 * @method static void flushCache()
 * @method static void forgetResolved()
 * @method static \Bhry98\KeycloakAuth\Testing\FakeKeycloak fake()
 * @method static array<int, string> guards()
 * @method static string defaultGuard()
 *
 * @see KeycloakManager
 */
class Keycloak extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return KeycloakManager::class;
    }
}
