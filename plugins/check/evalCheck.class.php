<?php
/**
 * A "plugin" to track PHP files with suspect "eval()"
 */
class evalCheck extends maliciousCheck {
    function filter($sPath) {
        return (('php' == $this->extension($sPath)) ? true : false);
    }
    function needFileContent() {
        return true;
    }
    function __construct() {
        $this->lRegex = array(
            'eval\s*\(\s*$_',
            'eval\s*\(\s*base64',
            'eval\s*\(gzinflate\s*\(base64');
    }
    function check($sPath, $sContent = null) {
        $this->iCount++;
        if ($sContent) {
            foreach($this->lRegex as $sRegex) {
                if (preg_match('/'.$sRegex.'/i', $sContent)) {
                    $this->lFiles[$sPath] = 10;
                    break;
                }
            }
        }
        return false;
    }
}