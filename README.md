# WP-Backdoors
Wordpress capable PHP backdoors

# How to use

Add these php scripts to a zip file, in your wordpress admin portal, navigate to the plugin upload page, upload zip file. The plugin will complain about an error being present in the upload, however the shells are still uploaded. This error is due to the WP engine not being able to "execute" the scripts and present you with the uploaded plugin.

You may notice these are a reskin of another Wordpress backdoor, and once i find the repo again, [i will make sure to give credit for the execution of commands function that is present in these shells](https://github.com/leonjza/wordpress-shell/blob/master/shell.php#L47). I do not like to rip off code and believe that credit needs to be given where credit is due.

# Features

Due to recent popularity(yea im watching VT for this.) I will be adding an update routine to this script. The update will require some information about the system requesting the information, no code will be executed by the server that is hosting the updates, it will be a backup in the event this repo gets taken down.

# Disclaimer

I am in no way responsible for the misuse of this product, this product is distributed with no warranty in any way. These scripts exist for educational value and/or legitimate Red teaming activities where prior permission was given. Know the law in the country which you reside before using these shells.
