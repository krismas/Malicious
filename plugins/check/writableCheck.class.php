<?php
/**
 * A "plugin" to check if file is writable
 */
class writableCheck extends maliciousCheck {
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if (!is_writable($sPath)) $this->lFiles[$sPath] = true;
        return false;
    }
}
