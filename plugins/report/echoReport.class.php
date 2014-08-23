<?php
/**
 * Echo check results to screen
 */
class echoReport extends maliciousReport {
    function report($lChecks) {
        if (isset($_SERVER['REMOTE_ADDR'])) echo '<pre>';
        foreach($lChecks as $oO) {
            printf("%-20s : %4d / %4d\n", get_class($oO), count($oO->lFiles), $oO->iCount);
            if (count($oO->lFiles) && $oO->warm()) print_r($oO->lFiles);
        }
        if (isset($_SERVER['REMOTE_ADDR'])) echo '</pre>';
    }
}