<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Exception;

use JsonSerializable;
use Psr\Http\Message\ResponseInterface;
use Throwable;

class OAuth2Exception extends RuntimeException implements JsonSerializable
{
    /** @var string */
    private $error;
    /** @var null|string */
    private $description;
    /** @var null|string */
    private $errorUri;

    /**
     * @param ResponseInterface $response
     * @param Throwable|null $previous
     * @throws RemoteException
     * @return self
     */
    public static function fromResponse(ResponseInterface $response, Throwable $previous = null): OAuth2Exception
    {
        $data = \json_decode($response->getBody()->getContents(), true);

        if (! \is_array($data) || ! isset($data['error'])) {
            throw new RemoteException($response, $response->getReasonPhrase(), $response->getStatusCode(), $previous);
        }

        return self::fromParameters($data);
    }

    /**
     * @param array $params
     * @param Throwable|null $previous
     * @return self
     */
    public static function fromParameters(array $params, Throwable $previous = null): self
    {
        if (! \array_key_exists('error', $params)) {
            throw new RuntimeException('Invalid OAuth2 exception', 0, $previous);
        }

        return new self(
            $params['error'],
            $params['error_description'] ?? null,
            $params['error_uri'] ?? null,
            0,
            $previous
        );
    }

    public function __construct(
        string $error,
        ?string $description = null,
        ?string $errorUri = null,
        int $code = 0,
        Throwable $previous = null
    )
    {
        $message = $error;
        if ($description) {
            $message = sprintf('%s (%s)', $description, $error);
        }

        parent::__construct($message, $code, $previous);
        $this->error = $error;
        $this->description = $description;
        $this->errorUri = $errorUri;
    }

    /**
     * @return string
     */
    public function getError(): string
    {
        return $this->error;
    }

    /**
     * @return string|null
     */
    public function getDescription(): ?string
    {
        return $this->description;
    }

    /**
     * @return string|null
     */
    public function getErrorUri(): ?string
    {
        return $this->errorUri;
    }

    public function jsonSerialize(): array
    {
        $data = [
            'error' => $this->getError(),
            'error_description' => $this->getDescription(),
            'error_uri' => $this->getErrorUri(),
        ];

        return \array_filter($data);
    }
}
