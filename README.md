Redmine Stronger plugin
=======================

This plugin aims at grouping some security tricks for large redmine installs.
Redmine is already pretty secure by default, maybe those additional features
will some day get their way into core.

Current features
----------------

* *Anti-brute-force system* : Redmine's authentication is fragile against dictionary attacks, especially if you
  have a lot of users and can't manage their password policy. This feature locks any user account after 5 failed
  password attempts. Protection applies to every password-based authentication channel: the web login form **and**
  the API HTTP Basic authentication, which share the same failure counter. A locked account is unlocked
  automatically after a short delay (or manually by an administrator). The counter is reset on each successful
  login, so legitimate users are rarely affected.

* *Security dashboard* (Administration menu) : surfaces accounts using the API, anonymous/non-member
  issue and wiki exposure, inactive accounts and locked accounts. Tracked login/API attempts.

* *Intranet-only API* : optionally rejects API-key requests that do not originate from the intranet zone.
  Disabled by default.

* *Attachment malware scan* : optionally scans every uploaded file with ClamAV (web forms, API uploads, incoming
  emails) before it is stored, and rejects infected files. If clamd is unavailable, the file is accepted and a
  background job scans it later, notifying administrators if it turns out to be infected. Disabled by default.

  Requires a clamd daemon reachable through a local unix socket (`apt install clamav-daemon` on Debian, socket
  `/var/run/clamav/clamd.ctl`) and an ActiveJob backend for the deferred scans. The setting cannot be turned on
  while clamd does not answer on the configured socket. clamd's `StreamMaxLength`, `MaxFileSize` and `MaxScanSize`
  must be at least Redmine's maximum attachment size, otherwise larger files are accepted unscanned.

  The files already stored are scanned by a separate read-only task, which writes a CSV report of the infected,
  unscannable and missing files, and exits with status 2 when a threat is found:

      rake redmine:stronger:scan_attachments RAILS_ENV=production

  `THREADS` sets the number of parallel scans (4), `SINCE` limits the scan to the attachments created in the last
  N days, `CLAMD_SOCKET` and `REPORT` override the socket and the report path. `NOTIFY=1` emails the
  administrators a single summary per run, whatever the number of infected files; without it the task only writes
  its report. Run it once over the whole stock, then nightly from cron, since a file that is clean today can be
  recognised after a signature update.

Install
-------

This plugin is compatible with Redmine 2.1.x and later.

You can first take a look at general instructions for plugins [here](http://www.redmine.org/wiki/redmine/Plugins).

This plugin has one dependency:

* install the redmine_base_deface plugin (see [here](https://github.com/jbbarth/redmine_base_deface))

Then:

* clone this repository in your "plugins/" directory ; if you have a doubt you put it at the good level, you can check
  you have a plugins/redmine_stronger/init.rb file
* run the migrations from your redmine root directory with command : `RAILS_ENV=production rake redmine:plugins`
* install dependencies (gems) by running the following command: `bundle install`
* restart your Redmine instance (depends on how you host it)

Requirements:

    ruby >= 2.1.0

Test status
------------

| Plugin branch | Redmine Version | Test Status       |
|---------------|-----------------|-------------------|
| master        | 6.1.4           | [![6.1.4][2]][5]  |
| master        | 7.0.1           | [![7.0.1][1]][5]  |
| master        | master          | [![master][3]][5] |

[1]: https://github.com/jbbarth/redmine_stronger/actions/workflows/7_0_1.yml/badge.svg

[2]: https://github.com/jbbarth/redmine_stronger/actions/workflows/6_1_4.yml/badge.svg

[3]: https://github.com/jbbarth/redmine_stronger/actions/workflows/master.yml/badge.svg

[5]: https://github.com/jbbarth/redmine_stronger/actions

Contribute
----------

If you like this plugin, it's a good idea to contribute:

* by giving feed back on what is cool, what should be improved
* by reporting bugs : you can open issues directly on github
* by forking it and sending pull request if you have a patch or a feature you want to implement
