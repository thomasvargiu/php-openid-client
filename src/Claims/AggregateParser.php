<?php

declare(strict_types=1);

namespace TMV\OpenIdClient\Claims;

use function array_filter;
use function is_array;
use Throwable;
use TMV\OpenIdClient\Client\ClientInterface;

final class AggregateParser extends AbstractClaims implements AggregatedParserInterface
{
    public function unpack(ClientInterface $client, array $claims): array
    {
        $claimSources = $claims['_claim_sources'] ?? null;
        $claimNames = $claims['_claim_names'] ?? null;

        if (! is_array($claimSources)) {
            return $claims;
        }

        if (! is_array($claimNames)) {
            return $claims;
        }

        $aggregatedSources = array_filter($claimSources, static function ($value) {
            return null !== ($value['JWT'] ?? null);
        });

        $claimPayloads = [];
        foreach ($aggregatedSources as $sourceName => $source) {
            try {
                $claimPayloads[$sourceName] = $this->claimJWT($client, (string) $source['JWT']);
                unset($claims['_claim_sources'][$sourceName]);
            } catch (Throwable $e) {
            }
        }

        return $this->cleanClaims($this->assignClaims($claims, $claimNames, $claimPayloads));
    }
}
