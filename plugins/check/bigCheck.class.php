<?php
/**
 * A "plugin" to check for big files and files larger "than post_max_size"
 *
 * @copyright Ackwa.fr - 2014
 */
class bigCheck extends maliciousCheck {
    function description() {
        return 'Big files (>'.MCS_MAXFS.') or files larger than "post_max_size" (>'.bytes(ini_get('post_max_size')).')';
    }
    function check($sPath, $aContent = null) {
        $this->iCount++;
        $iFS = filesize($sPath);
        if (($iFS > MCS_MAXFS) || ($iFS > bytes(ini_get('post_max_size')))) $this->lFiles[$sPath] = $iFS;
        return ($this->lFiles[$sPath] ? true : false);
    }
}