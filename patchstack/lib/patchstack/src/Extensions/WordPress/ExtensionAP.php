<?php

namespace Patchstack\Extensions\WordPress;

use Patchstack\Extensions\ExtensionInterface;
use Patchstack\LogRedactor;

class ExtensionAP implements ExtensionInterface
{
    /**
     * WordPress specific options that we need to remember.
     *
     * @var array
     */
    public $options = [
        'patchstack_firewall_ip_header' => 'REMOTE_ADDR',
        'patchstack_log_redaction' => 0
    ];

    /**
     * Creates a new extension instance.
     */
    public function __construct($options)
    {
        $this->options = array_merge($this->options, $options);
    }

    /**
     * Log the HTTP request.
     *
     * @param  int    $ruleId
     * @param  array  $request
     * @param  string $logType
     * @return void
     */
    public function logRequest($ruleId, $request, $logType = 'BLOCK')
    {
        // Transform raw payload.
        if (is_array($request) && array_key_exists('raw', $request)) {
            $request['raw'] = isset($request['raw']) && is_array($request['raw']) ? $request['raw'][0] : $request['raw'];

            // Remove raw payload if not present.
            if ((is_array($request['raw']) && count($request['raw']) == 0) || empty($request['raw'])) {
                unset($request['raw']);
            }
        }

        // Remove files payload if not present.
        if (isset($request['files']) && is_array($request['files']) && count($request['files']) == 0) {
            unset($request['files']);
        }

        // Remove post payload if not present.
        if (isset($request['post']) && is_array($request['post']) && count($request['post']) == 0) {
            unset($request['post']);
        }

        if (!defined('PS_LOGS')) {
            return;
        }

        // The site imports this file every 15 minutes. Stop adding to it at 5 MiB, so a site
        // whose import does not run cannot have its disk filled by blocked requests.
        clearstatcache(true, PS_LOGS . 'logs.php');
        if (@filesize(PS_LOGS . 'logs.php') > 5 * 1024 * 1024) {
            return;
        }

        $requestUri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        $postData = json_encode($request);
        if (!empty($this->options['patchstack_log_redaction'])) {
            // Skip the entry rather than store the raw request if the redactor is missing (incomplete update).
            if (!class_exists('Patchstack\LogRedactor')) {
                return;
            }

            $requestUri = LogRedactor::uri($requestUri);
            $postData = LogRedactor::PAYLOAD;
        }

        // A value that is not valid UTF-8 cannot be encoded, and the block would not be recorded.
        $entry = json_encode([
            'ip'          => $this->logText($this->getIpAddress()),
            'request_uri' => $this->logText($requestUri),
            'user_agent'  => $this->logText(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''),
            'method'      => $this->logText(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : ''),
            'fid'         => '55' . $ruleId,
            'post_data'   => is_string($postData) ? $postData : '',
            'site_id'     => $this->options['site_id'],
            'log_date'    => date('Y-m-d H:i:s'),
            // log_date is in the server's timezone, which the importer cannot know.
            'time'        => time()
        ]);
        if (!is_string($entry)) {
            return;
        }

        @file_put_contents(PS_LOGS . 'logs.php', base64_encode($entry) . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /**
     * Replace the bytes of a request value that are not valid UTF-8.
     *
     * @param  mixed $value
     * @return string
     */
    private function logText($value)
    {
        $value = is_scalar($value) ? (string) $value : '';
        if ($value !== '' && @preg_match('//u', $value) !== 1) {
            $value = function_exists('mb_convert_encoding') ? mb_convert_encoding($value, 'UTF-8', 'UTF-8') : preg_replace('/[^\x20-\x7e]/', '?', $value);
        }
        return (string) $value;
    }

    /**
     * Determine if the current visitor can bypass the firewall.
     * If $isMuCall is true, we MUST avoid any function calls that checks the current authorization of the user,
     * this includes current_user_can. Otherwise, a fatal error is thrown.
     *
     * @param bool $isMuCall
     * @return bool
     */
    public function canBypass($isMuCall)
    {
        return false;
    }

    /**
     * Determine if the visitor is blocked from the website.
     *
     * @param  int $minutes
     * @param  int $blockTime
     * @param  int $attempts
     * @return bool
     */
    public function isBlocked($minutes, $blockTime, $attempts)
    {
        return false;
    }

    /**
     * The response to return when a request has been blocked.
     *
     * @param  int $fid
     * @return void
     */
    public function forceExit($fid)
    {
        header( 'HTTP/1.0 403 Forbidden' );
        header( 'X-Content-Type-Options: nosniff' );
        header( 'Cache-Control: no-cache, must-revalidate, max-age=0, no-store, private' );
        header( 'Expires: Wed, 11 Jan 1984 05:00:00 GMT' );

		// Supported by a number of popular caching plugins.
		if (!defined( 'DONOTCACHEPAGE')) {
			define('DONOTCACHEPAGE', true);
		}

        include_once PS_PATH . 'includes/views/access-denied-ap.php';
        exit;
    }

    /**
     * Get the IP address of the request.
     *
     * @return string
     */
    public function getIpAddress()
    {
        if (isset($_SERVER[$this->options['patchstack_firewall_ip_header']])) {
            return $_SERVER[$this->options['patchstack_firewall_ip_header']];
        }

        return $_SERVER['REMOTE_ADDR'];
    }

    /**
     * Get the hostname of the environment.
     * This is only used for open redirect vulnerabilities.
     * 
     * @return string
     */
    public function getHostName()
    {
        return $_SERVER['HTTP_HOST'];
    }

    /**
     * Determine if the request is whitelisted.
     *
     * @param array $whitelistRules
     * @param array $request
     * @return boolean
     */
    public function isWhitelisted($whitelistRules, $request)
    {
        return false;
    }

    /**
     * Determine if the current request is a file upload request.
     *
     * @return boolean
     */
    public function isFileUploadRequest()
    {
        return isset($_FILES) && count($_FILES) > 0;
    }
}
