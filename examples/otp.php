<html>
<head><title>OTP</title>
</head>
<body>


<?php
/* Example of a script which can send mail/sms
 * with the next required passcode.
 * WARNING: It MUST HAVE access to ~/.pppauth of user!
 * So a default php install with php running on apache
 * user won't work! (I use suPHP, which does well).
 */


$pppauth = "/usr/bin/pppauth";
$password = "some_anti_spam_password";
$tofield = "phonenumber@sms.gate.org";
$userhome = "/home/user"; // make sure pppauth locates our userdir. 
$from = "From: OTP System\r\n";

$cmd = $pppauth . " -t -p current";


if ($_POST['password'] == $password) {
	putenv("HOME=$userhome");
	$retval = 0;
	$output = array();
	$key = exec($cmd, $retval, $output);

	if ($key == false) {
		print_r($output);
		echo("Error: Unable to execute pppauth: " . $retval);
		return;
	}
	echo ("<br/>\n");
	$message = "Use following key to login: $key";

	$err = mail($tofield, "OTP", $message, $from);

	if ($err)
		echo("SMS was successfully sent<br/>");
	else
		echo("Error while sending SMS<br/>");
} else {
?>
Enter a password:<br/>
<form method="post" action="otp.php">
<input type="password" name="password" /><br/>
<input type="submit" name="submit" value="Send" />
</form>
<?php
}


?>

</body>
</html>
