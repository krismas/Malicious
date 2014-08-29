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
            '`[\S\s]*`'                 => 11,
            'pcntl_exec\s*\('           => 12,
            'system\s*\('               => 13,
            'popen\s*\('                => 14,
            'proc_pen\s*\('             => 15,
            'passthru\s*\('             => 16,
            'fsockopen\s*\('            => 17,
            'pfsockopen\s*\('           => 18,
            'stream_socket_client\s*\(' => 19
        );
    }
}