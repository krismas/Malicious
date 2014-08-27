<?php
/**
 * A "plugin" to track hidden files and directories (.xxx)
 *
 * @copyright Ackwa.fr - 2014
 */
class hiddenCheck extends maliciousCheck {
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if ('.' == substr(basename($sPath), 0, 1)) $this->lFiles[$sPath] = 1;
        return false;
    }
}