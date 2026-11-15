<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Exceptions;

/**
 * An OpenID Connect endpoint (token, userinfo, introspection, ...) returned an error.
 */
class OidcException extends KeycloakException {}
