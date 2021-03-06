<?php
/**
 * Log check results to file
 *
 * @copyright Ackwa.fr - 2014
 */
class logReport extends maliciousReport {
    function report($lChecks) {
        foreach($lChecks as $oO) {
            _log(sprintf("%-70s [%-12s] : %4d / %4d files - %8d bytes read", $oO->description(), str_replace('Check', '', get_class($oO)), count($oO->lFiles), $oO->iCount, $oO->iSize));
            if (count($oO->lFiles) && $oO->warn()) {
                arsort($oO->lFiles);
                foreach($oO->lFiles as $k =>$v) _log(sprintf(" %-12s|%20s : %s", str_replace('Check', '', get_class($oO)), $v, $k));
            }
        }
    }
}