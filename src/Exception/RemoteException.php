<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Exception;

use Psr\Http\Message\ResponseInterface;
use Throwable;

class RemoteException extends RuntimeException
{
    /** @var ResponseInterface */
    private $response;

    public function __construct(ResponseInterface $response, string $message = '', int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
        $this->response = $response;
    }

    /**
     * @return ResponseInterface
     */
    public function getResponse(): ResponseInterface
    {
        return $this->response;
    }
}
