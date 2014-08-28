<?php
/**
 * A "plugin" to track PHP files with very long lines
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
        if ($sContent) {
            $aContent = explode("\n", $sContent);
            foreach($aContent as $sLine) {
                if (strlen($sLine) > 10000) {
                    $this->lFiles[$sPath] = 10;
                    break;
                }
            }
        }
        return false;
    }
}