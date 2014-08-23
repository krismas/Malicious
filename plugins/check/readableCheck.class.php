<?php
/**
 * A "plugin" to check if file is readable
 */
class readableCheck extends maliciousCheck {
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if (!is_readable($sPath)) $this->lFiles[$sPath] = true;
        return (isset($this->lFiles[$sPath]) ? true : false);  // STOP if not readable
    }
}