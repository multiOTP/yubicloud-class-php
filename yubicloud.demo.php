<?php
/**
 * @file  yubicloud.demo.php
 * @brief Yubicloud LGPLv3 PHP class demo implementation
 *
 * @mainpage
 *
 * This is a small demo implementation of the Yubicloud PHP class.
 *
 * PHP 5.3.0 or higher is supported.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   4.3.2.1
 * @date      2014-12-29
 * @since     2014-11-04
 * @copyright (c) 2014 SysCo systemes de communication sa
 * @license   GNU Lesser General Public License
 * @link      http://www.multiotp.net/
 *
 *//*
 *
 * LICENCE
 *
 *   Copyright (c) 2014 SysCo systemes de communication sa
 *   SysCo (tm) is a trademark of SysCo systemes de communication sa
 *   (http://www.sysco.ch/)
 *   All rights reserved.
 *
 *   This file is part of the Yubicloud PHP class.
 * 
 *   Yubicloud PHP class is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation, either version 3 of the License,
 *   or (at your option) any later version.
 * 
 *   Yubicloud PHP class is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 * 
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Yubicloud PHP class.
 *   If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Usage
 *
 *   You need a free Yubico API key. You can ask for your own key here:
 *     https://upgrade.yubico.com/getapikey/
 *
 *
 * Change Log
 *
 *   2014-12-29 4.3.2.1 SysCo/al Adding information about the server which answered
 *   2014-12-29 4.3.2.0 SysCo/al Some modifications for future PSR compliance (http://www.php-fig.org/)
 *   2014-12-26 4.3.1.3 SysCo/al Additional detailed information
 *   2014-12-22 4.3.1.2 SysCo/al Detailed response information
 *   2014-11-04 4.3.0.0 SysCo/al Initial release, version number is synchronized with the multiOTP project
 *********************************************************************/
    
    require_once('yubicloud.class.php');
    
    $otp_to_check = trim(isset($_POST['otp'])?$_POST['otp']:'');
    
    echo "<html>\n";
    echo "<head>\n";
    echo "<title>Yubicloud PHP class demo</title>\n";
    echo "</head>\n";
    echo "<body onload=\"document.getElementById('otp').focus();\">\n";
    echo "<form method=\"post\" action=\"yubicloud.demo.php\">\n";
    echo "<fieldset>\n";
    echo "<legend>YubiCloud demo</legend>\n";
    echo "Touch the YubiKey button:<br />\n";
    echo "<input type=\"text\" id=\"otp\" name=\"otp\" value=\"\" size=\"80\">\n";
    echo "<input type=\"submit\" value=\"Submit\">\n";
    echo "</fieldset>\n";
    echo "</form>\n";

    if (0 != strlen($otp_to_check))
    {
        $yubicloud = new Yubicloud();
        $result = $yubicloud->checkOnYubiCloud($otp_to_check);
        
        echo "<hr />";
        echo "OTP to check: <b>$otp_to_check</b>\n";
        echo "<br />";
        echo "YubiCloud result: <b>$result</b>\n";
        echo "<br /><br />\n";
        
        $response = $yubicloud->getYubiCloudLastResponse();
        ksort($response);
        echo "Detailed response: <br />\n";
        echo "<table>\n";
        foreach($response as $key=>$value) {
            echo "<tr><td>$key:</td><td><b>$value</b></td><td><i>";
            switch ($key) {
                case "otp":
                    echo "The OTP from the YubiKey, from request.";
                    break;
                case "nonce":
                    echo "Random unique data, from request.";
                    break;
                case "h":
                    echo "Signature (base64).";
                    break;
                case "now_utc":
                    echo "Unix timestamp of the PHP server in UTC.";
                    break;
                case "t":
                    echo "Timestamp of the YubiCloud server in UTC.";
                    break;
                case "t_utc":
                    echo "Unix timestamp of the Yubicloud server in UTC.";
                    break;
                case "status":
                    echo "The status of the operation, see below.";
                    break;
                case "timestamp":
                    echo "YubiKey internal timestamp value when key was pressed.";
                    break;
                case "sessioncounter":
                    echo "YubiKey internal usage counter when key was pressed.";
                    break;
                case "sessionuse":
                    echo "YubiKey internal session usage counter when key was pressed.";
                    break;
                case "sl":
                    echo "Percentage of external validation server that replied successfully (0 to 100).";
                    break;
            }
            echo "</i></td></tr>\n";
        }
        echo "</table>\n";
    }
    echo <<< EOT
<hr />
<pre>
                   OK  The OTP is valid.
              BAD_OTP  The OTP is invalid format.
         REPLAYED_OTP  The OTP has already been seen by the service.
        BAD_SIGNATURE  The HMAC signature verification failed.
    MISSING_PARAMETER  The request lacks a parameter.
       NO_SUCH_CLIENT  The request id does not exist.
OPERATION_NOT_ALLOWED  The request id is not allowed to verify OTPs.
        BACKEND_ERROR  Unexpected error in Yubico servers. Please contact them if you see this error.
   NOT_ENOUGH_ANSWERS  Server could not get requested number of syncs during before timeout.
     REPLAYED_REQUEST  Server has seen the OTP/Nonce combination before.
            BAD_NONCE  Answer Nonce is different from the request Nonce.
     CONNECTION_ERROR  Impossible to make a connection with the YubiCloud servers.
     OTP_IS_DIFFERENT  Answer OTP is different from request OTP.
   OUT_OF_TIME_WINDOW  Timestamp difference with the Yubico servers is bigger than yubicloud_max_time_window.
       SERVER_TIMEOUT  Timeout while waiting an answer from the server.
</pre>
EOT;
    echo "</body>\n";
    echo "</html>";
