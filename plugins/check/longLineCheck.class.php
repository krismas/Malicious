<?php
/**
 * A "plugin" to track PHP files with very long lines
 *
 * @copyright Ackwa.fr - 2014
 */
class longLineCheck extends maliciousCheck {
    function description() {
        return 'files with very long lines (> 10 000 characters)';
    }
    function filter($sPath) {
        return (('php' == $this->extension($sPath)) ? true : false);
    }
    function needFileContent() {
        return true;
    }
    function check($sPath, $sContent = null) {
        $this->iCount++;
        $this->iSize+= strlen($sContent);
        if ($sContent) {
            $aContent = explode("\n", $sContent);
            foreach($aContent as $sLine) {
                if (strlen($sLine) > 10000) {
                    $this->lFiles[$sPath] = strlen($sLine);
                    break;
                }
            }
        }
        return false;
    }
}