<?php
/**
 * A "plugin" to check if file has been updated since last check
 *
 * @copyright Ackwa.fr - 2014
 */
class updatedCheck extends maliciousCheck {
    function description() {
        return 'Files updated since last check';
    }
    function check($sPath, $aContent = null) {
        $this->iCount++;
        if (filemtime($sPath) > filemtime(__FILE__)) $this->lFiles[$sPath] = date('Y/m/d H:i:s', filemtime($sPath));
        return ($this->lFiles[$sPath] ? false : true); // If file "has not been updated" do not continue testing...
    }
    function __destruct() {
        touch(__FILE__);
    }
}