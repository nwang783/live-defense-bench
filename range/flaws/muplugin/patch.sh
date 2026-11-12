#!/bin/bash
# Turn the flaw OFF: take the agency's support plugin out. The folder stays, empty, as it
# would after someone deleted the file.
set -u
MU=/var/www/larkspur/wp-content/mu-plugins
rm -f "$MU/agency-support.php"
echo "muplugin: patched, no agency-support.php in $MU"
