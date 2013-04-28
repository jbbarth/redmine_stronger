Redmine Stronger plugin
=======================

This plugin aims at grouping some security tricks for large redmine installs.
Redmine is already pretty secure by default, maybe those additional features
will some day get their way into core.

Current features
----------------

* *Basic anti-brute-force system* : the standard login form of Redmine is fragile, especially if you happen
to have a lot of users and you can't manage their password policy. This feature will lock any user account
after 5 failed password submissions. Then the user should be manually unlocked by an administrator or through
the console. For sanity, it resets the counter each time the user successfully logs in, so the feature will
only be triggered rarely.

Install
-------

This plugin is compatible with Redmine 2.1.x and 2.2.x, and should be compatible with future versions.

You can first take a look at general instructions for plugins [here](http://www.redmine.org/wiki/redmine/Plugins).

Then :
* clone this repository in your "plugins/" directory ; if you have a doubt you put it at the good level, you can check you have a plugins/redmine_stronger/init.rb file
* run the migrations from your redmine root directory with command : `RAILS_ENV=production rake redmine:plugins`
* install dependencies (gems) by running the following command: `bundle install`
* restart your Redmine instance (depends on how you host it)

Contribute
----------

If you like this plugin, it's a good idea to contribute :
* by giving feed back on what is cool, what should be improved
* by reporting bugs : you can open issues directly on github
* by forking it and sending pull request if you have a patch or a feature you want to implement
