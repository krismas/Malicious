<?php
/**
 * A "plugin" to track PHP files in regards of PHP Shell Detector database
 */
class shelldbCheck extends maliciousCheck {
    private $lFingerprints = array();
    function description() {
        return 'Files declare in Shell Detector database';
    }
    function __construct() {
        $lFoo = unserialize(base64_decode(file_get_contents(MCS_SHELLDB)));
        unset($lFoo['version']);
        foreach ($lFoo as $sFingerprint => $sShell){
            if (strpos($sFingerprint, 'bb:') !== false) $sFingerprint = base64_decode(str_replace('bb:', '', $sFingerprint));
            $this->lFingerprints['/'.preg_quote($sFingerprint, '/').'/'] = $sShell;
            //echo '<pre>'.$sShell.' : ['.base64_decode($sFingerprint).']</pre>';
        }
    }
    function needFileContent() {
        return true;
    }
    function check($sPath, $sContent = null) {
        $this->iCount++;
        $this->iSize+= strlen($sContent);
        if ($sContent) {
            $sB64Content = base64_encode($sContent);
            foreach ($this->lFingerprints as $sFingerprint => $sShell) {
                if (preg_match($sFingerprint, $sContent)) {
                    $this->lFiles[$sPath] = $sShell.'[-]';
                    break;
                }
                if (preg_match($sFingerprint, $sB64Content)) {
                    $this->lFiles[$sPath] = $sShell.'[b]';
                    break;
                }
            }
        }
        return ($this->lFiles[$sPath] ? true : false);
    }
}