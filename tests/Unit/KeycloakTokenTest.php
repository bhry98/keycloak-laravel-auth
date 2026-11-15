<?php

use Bhry98\KeycloakAuth\Exceptions\TokenValidationException;
use Bhry98\KeycloakAuth\Token\KeycloakToken;

enum TestRole: string
{
    case Admin = 'admin';
}

function token(array $claims, array $clients = ['web-app']): KeycloakToken
{
    return new KeycloakToken($claims, 'jwt', 'web', $clients);
}

it('reads realm and client roles', function () {
    $token = token([
        'realm_access' => ['roles' => ['admin', 'user']],
        'resource_access' => [
            'web-app' => ['roles' => ['editor']],
            'billing' => ['roles' => ['invoice-viewer']],
        ],
    ]);

    expect($token->realmRoles())->toBe(['admin', 'user'])
        ->and($token->clientRoles())->toBe(['editor'])
        ->and($token->clientRoles('billing'))->toBe(['invoice-viewer'])
        ->and($token->roles())->toBe(['admin', 'user', 'editor'])
        ->and($token->hasRole('editor'))->toBeTrue()
        ->and($token->hasRole('invoice-viewer'))->toBeFalse()
        ->and($token->hasRole('billing:invoice-viewer'))->toBeTrue()
        ->and($token->hasRole(TestRole::Admin))->toBeTrue()
        ->and($token->hasAnyRole(['nope', 'user']))->toBeTrue()
        ->and($token->hasAnyRole('nope, user'))->toBeTrue()
        ->and($token->hasAllRoles(['admin', 'editor']))->toBeTrue()
        ->and($token->hasAllRoles(['admin', 'nope']))->toBeFalse()
        ->and($token->hasRealmRole('editor'))->toBeFalse()
        ->and($token->hasClientRole('editor'))->toBeTrue()
        ->and($token->allClientRoles())->toBe(['web-app' => ['editor'], 'billing' => ['invoice-viewer']]);
});

it('reads scopes and groups', function () {
    $token = token(['scope' => 'openid orders:read', 'groups' => ['/company/engineering', '/admins']]);

    expect($token->scopes())->toBe(['openid', 'orders:read'])
        ->and($token->hasScope('orders:read'))->toBeTrue()
        ->and($token->hasAnyScope(['x', 'openid']))->toBeTrue()
        ->and($token->hasAllScopes(['openid', 'x']))->toBeFalse()
        ->and($token->inGroup('engineering'))->toBeTrue()
        ->and($token->inGroup('/company/engineering'))->toBeTrue()
        ->and($token->inGroup('company'))->toBeFalse();
});

it('exposes identity and lifetime helpers', function () {
    $token = token([
        'sub' => 'abc', 'email' => 'a@b.c', 'preferred_username' => 'ab',
        'given_name' => 'A', 'family_name' => 'B', 'exp' => time() + 60, 'azp' => 'web-app',
    ]);

    expect($token->id())->toBe('abc')
        ->and($token->name())->toBe('A B')
        ->and($token->username())->toBe('ab')
        ->and($token->email)->toBe('a@b.c')
        ->and($token->isExpired())->toBeFalse()
        ->and($token->expiresIn())->toBeGreaterThan(50)
        ->and($token->isServiceAccount())->toBeFalse();

    expect(token(['preferred_username' => 'service-account-billing'])->isServiceAccount())->toBeTrue()
        ->and(token(['exp' => time() - 5])->isExpired())->toBeTrue();
});

it('decodes an unverified jwt and rejects garbage', function () {
    $jwt = 'eyJhbGciOiJub25lIn0.'.rtrim(strtr(base64_encode(json_encode(['sub' => 'x', 'azp' => 'c'])), '+/', '-_'), '=').'.sig';

    expect(KeycloakToken::fromJwtUnverified($jwt)->subject())->toBe('x');
    KeycloakToken::fromJwtUnverified('not-a-jwt');
})->throws(TokenValidationException::class);
