<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Exceptions;

/**
 * The access token is missing, malformed, expired or not trusted.
 */
class TokenValidationException extends KeycloakException {}
