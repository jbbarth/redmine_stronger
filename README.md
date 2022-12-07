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

This plugin is compatible with Redmine 2.1.x and later.

You can first take a look at general instructions for plugins [here](http://www.redmine.org/wiki/redmine/Plugins).

This plugin has one dependency:
* install the redmine_base_deface plugin (see [here](https://github.com/jbbarth/redmine_base_deface))

Then:
* clone this repository in your "plugins/" directory ; if you have a doubt you put it at the good level, you can check you have a plugins/redmine_stronger/init.rb file
* run the migrations from your redmine root directory with command : `RAILS_ENV=production rake redmine:plugins`
* install dependencies (gems) by running the following command: `bundle install`
* restart your Redmine instance (depends on how you host it)

Requirements:

    ruby >= 2.1.0

Test status
------------

|Plugin branch| Redmine Version   | Test Status      |
|-------------|-------------------|------------------|
|master       | 4.2.9             | [![4.2.9][1]][5] |  
|master       | 4.1.7             | [![4.1.7][2]][5] |
|master       | master            | [![master][4]][5]|

[1]: https://github.com/jbbarth/redmine_stronger/actions/workflows/4_2_9.yml/badge.svg
[2]: https://github.com/jbbarth/redmine_stronger/actions/workflows/4_1_7.yml/badge.svg
[4]: https://github.com/jbbarth/redmine_stronger/actions/workflows/master.yml/badge.svg
[5]: https://github.com/jbbarth/redmine_stronger/actions

Contribute
----------

If you like this plugin, it's a good idea to contribute:
* by giving feed back on what is cool, what should be improved
* by reporting bugs : you can open issues directly on github
* by forking it and sending pull request if you have a patch or a feature you want to implement
