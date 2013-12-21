# User Activation Email #

**Contributors:** NateJacobs   
**Tags:** user, registration, activation, email  
**Requires at least:** 3.5 
**Tested up to:** 3.8
**Stable tag:** 1.1

Require users to enter an activation code to access the site the first time. The activation code is emailed upon user registration.

## Description ##

Adds an activation code to the new user email sent once a user registers. The user must enter this activation code in addition to a username and password to log in successfully the first time. A 10 character activation code is added to the user meta when the user is registered.

The administrator may reset the activation code or enter a new one from the users profile page.

This plugin does not currently work with multi-site. Multi-site uses an activation key system for new registrations already.

## Installation ##

Extract the zip file and just drop the contents in the wp-content/plugins/ directory of your WordPress installation and then activate the Plugin from Plugins page.

## Screenshots ##

###1. Log in form###
![Log in form](https://raw.github.com/NateJacobs/User-Access-Expiration/master/screenshot-1.png)

###2. User profile page###
![User profile page](https://raw.github.com/NateJacobs/User-Access-Expiration/master/screenshot-2.png)


## Changelog ##

### 1.1 ###
* Compatible with 3.8
* Add support for WordPress language packs introduced in 3.7
* Add uninstall.php file to remove traces of the plugin once it has been deleted

### 1.0 ###
* Display date registered on user's profile page
* Bump minimum required version to 3.5
* Compatible with 3.7

### 0.4 ###
* Fixed authentication issue

### 0.3 ###
* WordPress 3.3 compatible
* Localized and available for translation

### 0.2 ###
* Added a field, shown only to admins, to the user profile that displays the activation code 

### 0.1 ###
* First version