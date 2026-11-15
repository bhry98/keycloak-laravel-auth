<?php

use Bhry98\KeycloakAuth\Http\Middleware\VerifyKeycloakTokenForApiAgent;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;

beforeEach(function () {
    config()->set('bhry98-keycloak.provisioning.enabled', false);

    Route::middleware(['keycloak.api', 'keycloak.role:admin,api-app:manager'])->get('/any-role', fn () => 'ok');
    Route::middleware(['keycloak.api', 'keycloak.roles:admin,auditor'])->get('/all-roles', fn () => 'ok');
    Route::middleware(['keycloak.api', 'keycloak.scope:orders:read'])->get('/scope', fn () => 'ok');
    Route::middleware(['keycloak.api', 'keycloak.permission:invoice#read'])->get('/permission', fn () => 'ok');
    Route::middleware('keycloak.role:admin')->get('/no-auth', fn () => 'ok');
    Route::middleware('keycloak.api')->get('/gate', fn () => Gate::allows('keycloak-role', 'admin') && Gate::allows('keycloak-scope', ['x', 'openid']) ? 'ok' : abort(403));
    Route::middleware(VerifyKeycloakTokenForApiAgent::class)->get('/agent', fn (Request $r) => $r->input('auth_user.sub'));
});

it('checks any-of roles, including client roles', function () {
    $this->actingAsKeycloakUser(['roles' => ['user']])->get('/any-role')->assertForbidden();
    $this->actingAsKeycloakUser(['roles' => ['admin']])->get('/any-role')->assertOk();
    $this->actingAsKeycloakUser(['client_roles' => ['api-app' => ['manager']]])->get('/any-role')->assertOk();
});

it('checks all-of roles', function () {
    $this->actingAsKeycloakUser(['roles' => ['admin']])->get('/all-roles')->assertForbidden();
    $this->actingAsKeycloakUser(['roles' => ['admin', 'auditor']])->get('/all-roles')->assertOk();
});

it('checks scopes', function () {
    $this->actingAsKeycloakUser(['scopes' => ['openid']])->get('/scope')->assertForbidden();
    $this->actingAsKeycloakUser(['scopes' => ['openid', 'orders:read']])->get('/scope')->assertOk();
});

it('returns 401 from role middleware when nobody is authenticated', function () {
    $this->getJson('/no-auth')->assertUnauthorized();
});

it('registers gates', function () {
    $this->actingAsKeycloakUser(['roles' => ['user']])->get('/gate')->assertForbidden();
    $this->actingAsKeycloakUser(['roles' => ['admin']])->get('/gate')->assertOk();
});

it('asks keycloak authorization services for permissions and caches the decision', function () {
    Http::fake([$this->oidcUrl('token') => Http::sequence()->push(['result' => true])->push(['error' => 'access_denied'], 403)]);

    $jwt = $this->keycloakToken();
    $this->withToken($jwt)->get('/permission')->assertOk();
    $this->withToken($jwt)->get('/permission')->assertOk(); // cached

    Http::assertSentCount(1);
    Http::assertSent(fn ($request) => str_contains($request->body(), 'permission=invoice%23read')
        && str_contains($request->body(), 'response_mode=decision')
        && $request->hasHeader('Authorization', 'Bearer '.$jwt));

    $this->actingAsKeycloakUser()->get('/permission')->assertForbidden();
});

it('keeps the 1.x agent middleware working', function () {
    $this->actingAsKeycloakUser(['sub' => 'agent-1'])->get('/agent')->assertOk()->assertSee('agent-1');
});
