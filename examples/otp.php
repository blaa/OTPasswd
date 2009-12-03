<?php
/**********************************************************************
 * otp.php - example of how to send yourself an SMS with passcode
 * (C) 2009 by Tomasz bla Fortuna <bla@thera.be>, <bla@af.gliwice.pl>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with otpasswd. If not, see <http://www.gnu.org/licenses/>.
 **********************************************************************/
?>

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


$pppauth = "/usr/bin/otpasswd";
$password = "some_anti_spam_password";
$tofield = "phonenumber@sms.gate.org";
$userhome = "/home/user"; // make sure pppauth locates our userdir. 
$from = "From: OTP System\r\n";

$cmd = $pppauth . " -t current";


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
