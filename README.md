Yubicloud PHP class
===================

Yubicloud PHP class is a GNU LGPL class to check YubiKeys using YubiCloud.

(c) 2014 SysCo systemes de communication sa  
The Yubicloud PHP class is a subset of the multiOTP open source project.  
http://www.multiOTP.net/

Current build: 4.3.1.3 (2014-12-26)

No external file is needed (no PEAR, no PECL).


# Usage

  You need a free Yubico API key. You can ask for your own key here:
    https://upgrade.yubico.com/getapikey/
    
    <?php
        require_once('yubicloud.class.php');
        $yubicloud = new Yubicloud("my_client_id", "my_secret_key");
        $result = $yubicloud->CheckOnYubiCloud($otp_to_check);
    ?>


# Possible returned value is one of the following:  
    
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

  Check yubicloud.demo.php for a full implementation example.
