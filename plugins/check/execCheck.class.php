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
            'shell_exec\s*\('           => 11,
            '`[\S\s]*`'                 => 12,
            'pcntl_exec\s*\('           => 13,
            'system\s*\('               => 14,
            'popen\s*\('                => 15,
            'proc_pen\s*\('             => 16,
            'passthru\s*\('             => 17,
            'fsockopen\s*\('            => 18,
            'pfsockopen\s*\('           => 19,
            'stream_socket_client\s*\(' => 20
        );
    }
}