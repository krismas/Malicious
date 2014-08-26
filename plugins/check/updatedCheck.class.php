<?php
/**
 * A "plugin" to check if file has been updated since last check
 *
 * @copyright Ackwa.fr - 2014
 */
class updatedCheck extends maliciousCheck {
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if (filemtime($sPath) > filemtime(__FILE__)) $this->lFiles[$sPath] = 1;
        return false;
    }
    function __destruct() {
        touch(__FILE__);
    }
}