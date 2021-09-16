$change = git update-index --refresh
if ( $change -ne $null) {
	$ver = python .\setup.py --version
	$array = $ver.Split('.')
	$array[2] = [string]([int]$array[2] +1)
	$newver = $array -join '.'
	(Get-Content .\setup.py).Replace($ver,$newver) | Out-File .\setup.py
	git add .
	if ( $args[0] -eq $null) {git commit -m "$ver"} else {git commit -m "$args[0]"}
	git push
}
