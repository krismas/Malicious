<?php
/**
 * A "plugin" to check if file is empty
 *
 * @copyright Ackwa.fr - 2014
 */
class emptyCheck extends maliciousCheck {
    function description() {
        return 'Empty files';
    }
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if (!filesize($sPath)) $this->lFiles[$sPath] = 1;
        return false;
    }
}