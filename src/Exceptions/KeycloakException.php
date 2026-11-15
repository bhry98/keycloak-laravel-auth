<?php

declare(strict_types=1);

namespace Bhry98\KeycloakAuth\Exceptions;

use Illuminate\Http\Client\Response;
use RuntimeException;
use Throwable;

/**
 * @phpstan-consistent-constructor
 *
 * Base exception for every error raised by the package.
 */
class KeycloakException extends RuntimeException
{
    public function __construct(
        string $message = '',
        int $code = 0,
        ?Throwable $previous = null,
        protected ?Response $response = null,
    ) {
        parent::__construct($message, $code, $previous);
    }

    public static function fromResponse(string $context, Response $response): static
    {
        $error = $response->json('error');
        $description = $response->json('error_description') ?? $response->json('errorMessage');
        $detail = is_string($description) ? $description : (is_string($error) ? $error : mb_substr($response->body(), 0, 500));

        return new static(
            trim("{$context} (HTTP {$response->status()}): {$detail}"),
            $response->status(),
            null,
            $response,
        );
    }

    public function response(): ?Response
    {
        return $this->response;
    }

    /** HTTP status Keycloak answered with, or 0 when there was no response. */
    public function status(): int
    {
        return $this->response?->status() ?? 0;
    }

    /** The OAuth `error` code (e.g. "invalid_grant"), when Keycloak returned one. */
    public function error(): ?string
    {
        $error = $this->response?->json('error');

        return is_string($error) ? $error : null;
    }

    public function errorDescription(): ?string
    {
        $description = $this->response?->json('error_description') ?? $this->response?->json('errorMessage');

        return is_string($description) ? $description : null;
    }
}
