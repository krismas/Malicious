<?php
/**
 * A "plugin" to track PHP files with exec(), system()...
 *
 * @copyright Ackwa.fr - 2014
 * @see       https://github.com/mikestowe/Malicious-Code-Scanner
 */
class execCheck extends evalCheck {
    function description() {
        return 'PHP files with exec(), system()...';
    }
    function __construct() {
        $this->lRegex = array(
            'mail\s*\('                 =>  1,
            'exec\s*\('                 => 10,
            'pcntl_exec\s*\('           => 11,
            'system\s*\('               => 12,
            'popen\s*\('                => 13,
            'proc_pen\s*\('             => 14,
            'passthru\s*\('             => 15,
            'fsockopen\s*\('            => 16,
            'pfsockopen\s*\('           => 17,
            'stream_socket_client\s*\(' => 18
        );
    }
}