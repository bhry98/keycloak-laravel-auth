<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Auth;

use Bhry98\KeycloakAuth\Events\UserProvisioned;
use Bhry98\KeycloakAuth\KeycloakManager;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;

/**
 * Turns a Keycloak token into an application user.
 *
 * With provisioning enabled the user row is created / updated from the
 * claims. To keep API requests cheap, the write is skipped while the
 * claims are unchanged (`provisioning.sync_ttl`): a hot request costs a
 * single primary-key lookup.
 */
class UserProvisioner
{
    /** @var (Closure(KeycloakToken, string): ?Authenticatable)|null */
    protected ?Closure $resolver = null;

    public function __construct(protected KeycloakManager $keycloak) {}

    /** @param  callable(KeycloakToken, string): ?Authenticatable  $resolver */
    public function using(callable $resolver): void
    {
        $this->resolver = Closure::fromCallable($resolver);
    }

    public function enabled(?string $guard = null): bool
    {
        $override = $guard !== null ? $this->keycloak->realm($guard)->get('provisioning') : null;

        return (bool) ($override ?? $this->keycloak->config('provisioning.enabled', true));
    }

    /**
     * The user for a token: custom resolver, synced model, or stateless user.
     */
    public function resolve(KeycloakToken $token, ?bool $provision = null): ?Authenticatable
    {
        if ($this->resolver !== null) {
            return ($this->resolver)($token, $token->guard());
        }

        $provision ??= $this->enabled($token->guard());

        // Service accounts usually have no e-mail and no local row.
        if (! $provision || $token->isServiceAccount() || $token->subject() === null) {
            return new KeycloakUser($token);
        }

        return $this->sync($token);
    }

    /**
     * Create or update the local user row from the token claims.
     */
    public function sync(KeycloakToken $token): Model&Authenticatable
    {
        /** @var class-string<Model&Authenticatable> $modelClass */
        $modelClass = $this->keycloak->config('users_model');
        $attributes = $this->attributes($token);
        $hash = md5((string) json_encode($attributes));
        $cache = $this->keycloak->cache();
        $cacheKey = $this->keycloak->cachePrefix().':user_sync:'.md5($modelClass.'|'.$token->subject());
        $ttl = (int) $this->keycloak->config('provisioning.sync_ttl', 300);

        $cached = $ttl > 0 ? $cache->get($cacheKey) : null;

        if (is_array($cached) && ($cached['hash'] ?? null) === $hash) {
            /** @var (Model&Authenticatable)|null $user */
            $user = $modelClass::query()->find($cached['id']);

            if ($user !== null) {
                return $user;
            }
        }

        /** @var (Model&Authenticatable)|null $user */
        $user = $modelClass::query()->where('keycloak_id', $token->subject())->first();

        if ($user === null && ! empty($attributes['email'])) {
            // Adopt a pre-existing row (created before Keycloak, or by an older version).
            $user = $modelClass::query()->where('email', $attributes['email'])->first();
        }

        $created = $user === null;
        $user ??= new $modelClass;
        $user->forceFill($attributes);

        if ($created || $user->isDirty()) {
            $user->save();
            UserProvisioned::dispatch($user, $token, $created);
        }

        if ($ttl > 0) {
            $cache->put($cacheKey, ['id' => $user->getKey(), 'hash' => $hash], $ttl);
        }

        return $user;
    }

    /**
     * Column values for a token, from `provisioning.attributes`.
     *
     * @return array<string, mixed>
     */
    public function attributes(KeycloakToken $token): array
    {
        $map = (array) $this->keycloak->config('provisioning.attributes', []);
        $claims = $token->claims();
        $values = [];

        foreach ($map as $column => $claim) {
            $value = $claim instanceof Closure ? $claim($token) : Arr::get($claims, (string) $claim);

            if ($value !== null) {
                $values[$column] = $value;
            }
        }

        if (array_key_exists('name', $map) && empty($values['name'])) {
            $values['name'] = $token->name() ?? $token->username() ?? $token->email() ?? (string) $token->subject();
        }

        if (isset($values['locale'])) {
            $values['locale'] = mb_substr((string) $values['locale'], 0, 5);
        }

        if (isset($values['email_verified'])) {
            $values['email_verified'] = (bool) $values['email_verified'];
        }

        if (array_key_exists('keycloak_id', $map)) {
            $values['keycloak_realm'] = $this->keycloak->realm($token->guard())->realm;
        }

        return $values;
    }
}
