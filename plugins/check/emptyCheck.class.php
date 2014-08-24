<?php
/**
 * A "plugin" to check if file is empty
 */
class emptyCheck extends maliciousCheck {
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if (!filesize($sPath)) $this->lFiles[$sPath] = 1;
        return false;
    }
}