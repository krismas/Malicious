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
            'exec\s*\('     => 1,
            'system\s*\('   => 2,
            'popen\s*\('    => 3,
            'proc_pen\s*\(' => 4,
            'passthru\s*\(' => 5
        );
    }
}