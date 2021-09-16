git add .
if ( $args[0] -eq $null) {git commit -m "update"} else {git commit -m "$args[0]"}
git push