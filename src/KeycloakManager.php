<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth;

use Bhry98\KeycloakAuth\Admin\AdminClient;
use Bhry98\KeycloakAuth\Admin\Resources\Clients;
use Bhry98\KeycloakAuth\Admin\Resources\Groups;
use Bhry98\KeycloakAuth\Admin\Resources\Roles;
use Bhry98\KeycloakAuth\Admin\Resources\Users;
use Bhry98\KeycloakAuth\Auth\UserProvisioner;
use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\Oidc\OidcClient;
use Bhry98\KeycloakAuth\Services\KeycloakSocialiteProvider;
use Bhry98\KeycloakAuth\Support\RealmConfig;
use Bhry98\KeycloakAuth\Testing\FakeKeycloak;
use Bhry98\KeycloakAuth\Token\JwksProvider;
use Bhry98\KeycloakAuth\Token\KeycloakToken;
use Bhry98\KeycloakAuth\Token\TokenValidator;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use Throwable;

/**
 * Entry point of the package (the `Keycloak` facade).
 */
class KeycloakManager
{
    public const TOKEN_ATTRIBUTE = 'keycloak_token';

    /** @var array<string, RealmConfig> */
    protected array $realms = [];

    /** @var array<string, OidcClient> */
    protected array $oidc = [];

    /** @var array<string, AdminClient> */
    protected array $admins = [];

    protected ?JwksProvider $jwks = null;

    protected ?TokenValidator $validator = null;

    protected ?FakeKeycloak $fake = null;

    public function __construct(protected Application $app) {}

    /* ---------------------------------------------------------------
     | Configuration
     * ------------------------------------------------------------- */

    public function config(?string $key = null, mixed $default = null): mixed
    {
        $config = $this->app['config'];

        return $key === null ? $config->get('bhry98-keycloak', []) : $config->get("bhry98-keycloak.{$key}", $default);
    }

    public function defaultGuard(): string
    {
        return (string) ($this->config('default_guard') ?: 'web');
    }

    /** @return array<int, string> */
    public function guards(): array
    {
        return array_keys((array) $this->config('guard', []));
    }

    /**
     * Resolved realm + client settings of a guard. Unknown guard names fall
     * back to the top-level realm / client settings.
     */
    public function realm(RealmConfig|string|null $guard = null): RealmConfig
    {
        if ($guard instanceof RealmConfig) {
            return $guard;
        }

        $guard ??= $this->defaultGuard();

        return $this->realms[$guard] ??= RealmConfig::fromArray(
            $guard,
            (array) $this->config("guard.{$guard}", []),
            (array) $this->config(),
        );
    }

    /* ---------------------------------------------------------------
     | Tokens
     * ------------------------------------------------------------- */

    /**
     * Verify an access token (signature, expiry, issuer, audience) offline.
     *
     * @throws TokenValidationException
     */
    public function validate(string $jwt, RealmConfig|string|null $guard = null): KeycloakToken
    {
        return $this->validator()->validate($jwt, $this->realm($guard));
    }

    /** Like validate(), but returns null instead of throwing. */
    public function check(string $jwt, RealmConfig|string|null $guard = null): ?KeycloakToken
    {
        try {
            return $this->validate($jwt, $guard);
        } catch (TokenValidationException) {
            return null;
        }
    }

    /** Read a token's claims WITHOUT verifying it. */
    public function decode(string $jwt, RealmConfig|string|null $guard = null): KeycloakToken
    {
        $realm = $this->realm($guard);

        $token = KeycloakToken::fromJwtUnverified($jwt, $realm->name);

        return new KeycloakToken($token->claims(), $jwt, $realm->name, $this->roleClients($realm, $token->claims()));
    }

    /**
     * The token of the current request: the verified bearer token on API
     * routes, or the session token on web routes.
     */
    public function token(?Request $request = null): ?KeycloakToken
    {
        $request ??= $this->app->bound('request') ? $this->app['request'] : null;

        if ($request === null) {
            return null;
        }

        $token = $request->attributes->get(self::TOKEN_ATTRIBUTE);

        if ($token instanceof KeycloakToken) {
            return $token;
        }

        if ($request->hasSession() && is_string($jwt = $request->session()->get('keycloak_token')) && $jwt !== '') {
            try {
                $token = $this->decode($jwt, $request->session()->get('keycloak_guard'));
            } catch (Throwable) {
                return null;
            }

            $request->attributes->set(self::TOKEN_ATTRIBUTE, $token);

            return $token;
        }

        return null;
    }

    public function setToken(KeycloakToken $token, ?Request $request = null): void
    {
        $request ??= $this->app['request'];
        $request->attributes->set(self::TOKEN_ATTRIBUTE, $token);
    }

    /**
     * Clients whose roles count for hasRole() on tokens of this guard.
     *
     * @param  array<string, mixed>  $claims
     * @return array<int, string>
     */
    public function roleClients(RealmConfig $realm, array $claims = []): array
    {
        $configured = $realm->get('role_clients', $this->config('roles.clients'));

        if ($configured !== null) {
            return array_values((array) $configured);
        }

        return array_values(array_unique(array_filter([$realm->clientId, $claims['azp'] ?? null])));
    }

    public function validator(): TokenValidator
    {
        return $this->validator ??= new TokenValidator($this, $this->jwks());
    }

    public function jwks(): JwksProvider
    {
        return $this->jwks ??= new JwksProvider($this);
    }

    /* ---------------------------------------------------------------
     | Clients
     * ------------------------------------------------------------- */

    /** OpenID Connect endpoints (login, refresh, introspection, service tokens, ...). */
    public function oidc(RealmConfig|string|null $guard = null): OidcClient
    {
        $realm = $this->realm($guard);

        return $this->oidc[$realm->name.'|'.$realm->fingerprint()] ??= new OidcClient($this, $realm);
    }

    /**
     * Admin REST API client managing the realm of $guard, authenticated
     * with the `admin.guard` service account.
     */
    public function admin(RealmConfig|string|null $guard = null): AdminClient
    {
        $target = $this->realm($guard);
        $credentials = $this->realm((string) $this->config('admin.guard', 'admin'));

        return $this->admins[$target->fingerprint().'|'.$credentials->fingerprint()] ??= new AdminClient($this, $target, $credentials);
    }

    public function users(RealmConfig|string|null $guard = null): Users
    {
        return $this->admin($guard)->users();
    }

    public function roles(RealmConfig|string|null $guard = null): Roles
    {
        return $this->admin($guard)->roles();
    }

    public function groups(RealmConfig|string|null $guard = null): Groups
    {
        return $this->admin($guard)->groups();
    }

    public function clients(RealmConfig|string|null $guard = null): Clients
    {
        return $this->admin($guard)->clients();
    }

    /** A cached client-credentials token for calling other services. */
    public function serviceToken(RealmConfig|string|null $guard = null, ?string $scope = null): string
    {
        return $this->oidc($guard)->serviceToken($scope);
    }

    /** The Socialite driver of a guard. */
    public function socialite(?string $guard = null): KeycloakSocialiteProvider
    {
        /** @var KeycloakSocialiteProvider $driver */
        $driver = $this->app->make(SocialiteFactory::class)->driver('keycloak.'.($guard ?? $this->defaultGuard()));

        return $driver;
    }

    /* ---------------------------------------------------------------
     | Users
     * ------------------------------------------------------------- */

    public function provisioner(): UserProvisioner
    {
        return $this->app->make(UserProvisioner::class);
    }

    /**
     * Customise how a token becomes a user (return any Authenticatable).
     *
     * @param  callable(KeycloakToken, string): ?Authenticatable  $callback
     */
    public function resolveUserUsing(callable $callback): static
    {
        $this->provisioner()->using($callback);

        return $this;
    }

    /* ---------------------------------------------------------------
     | Infrastructure
     * ------------------------------------------------------------- */

    public function http(): PendingRequest
    {
        $http = (array) $this->config('http', []);

        return Http::timeout((int) ($http['timeout'] ?? 10))
            ->connectTimeout((int) ($http['connect_timeout'] ?? 5))
            ->withOptions(['verify' => (bool) ($http['verify'] ?? true)])
            ->retry(
                max(1, (int) ($http['retries'] ?? 2) + 1),
                (int) ($http['retry_delay'] ?? 100),
                fn (Throwable $e) => $e instanceof ConnectionException,
                throw: false,
            );
    }

    public function cache(): CacheRepository
    {
        return $this->app['cache']->store($this->config('cache.store'));
    }

    public function cachePrefix(): string
    {
        return (string) $this->config('cache.prefix', 'bhry98_keycloak');
    }

    /**
     * Forget cached keys and tokens (JWKS, admin & service tokens, discovery)
     * of every configured guard.
     */
    public function flushCache(): void
    {
        foreach ($this->guards() as $guard) {
            $realm = $this->realm($guard);
            $this->jwks()->forget($realm);
            $this->admin($guard)->forgetToken();
            $this->oidc($guard)->forgetServiceToken();
            $this->cache()->forget($this->cachePrefix().':discovery:'.md5($realm->realmUrl()));
        }

        $this->forgetResolved();
    }

    /** Drop in-memory state (useful in long-running workers and tests). */
    public function forgetResolved(): void
    {
        $this->realms = [];
        $this->oidc = [];
        $this->admins = [];
        $this->jwks?->flushMemo();
        $this->validator?->flushMemo();
    }

    /* ---------------------------------------------------------------
     | Testing
     * ------------------------------------------------------------- */

    /**
     * Sign tokens locally and trust them, without a Keycloak server.
     */
    public function fake(): FakeKeycloak
    {
        $this->forgetResolved();

        return $this->fake = new FakeKeycloak($this);
    }

    public function faked(): ?FakeKeycloak
    {
        return $this->fake;
    }
}
