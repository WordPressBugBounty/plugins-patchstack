<?php

namespace Patchstack;

/**
 * Strips request data out of firewall log entries for sites that opted in to log redaction,
 * so credentials caught by a false positive never reach the local log table or the Patchstack API.
 */
class LogRedactor
{
    /**
     * Stored in place of the POST/raw payload, so a redacted entry is not mistaken for an empty request.
     *
     * @var string
     */
    const PAYLOAD = '{"redacted":true}';

    /**
     * Drop the query string, keep the path.
     *
     * @param  string $uri
     * @return string
     */
    public static function uri($uri)
    {
        if (!is_string($uri)) {
            return '';
        }

        $parts = explode('?', $uri, 2);
        return $parts[0];
    }
}
