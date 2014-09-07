<?php
/**
 * E-mail check results
 *
 * @copyright Ackwa.fr - 2014
 */
class mailReport extends maliciousReport {
    private $sBuff = '';
    private $sMore = '';

    function report($lChecks) {
        foreach($lChecks as $oO) {
            if (count($oO->lFiles)) {
                $this->sMore+= count($oO->lFiles);
                $this->sBuff.= sprintf("%-60s [%-12s] : %4d / %4d files - %8d bytes read\n", $oO->description(), str_replace('Check', '', get_class($oO)), count($oO->lFiles), $oO->iCount, $oO->iSize);
                if ($oO->warn()) {
                    arsort($oO->lFiles);
                    $this->sBuff.= print_r($oO->lFiles, true);
                }
            }
        }
    }
    function __destruct() {
        if (trim($this->sBuff)) mail(MCS_EMAIL, 'Malicious "'.MCS_SITE.'" report : '.$this->sMore, $this->sBuff);
    }
}