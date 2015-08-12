#!/usr/bin/env python
#######################################
# Installation module for dictionaries
#######################################

# AUTHOR OF MODULE NAME
AUTHOR="mulm"

# DESCRIPTION OF THE MODULE
DESCRIPTION="This module will install/update watchtower - a Static Code Analysis tool."

# INSTALL TYPE GIT, SVN, FILE DOWNLOAD
# OPTIONS = GIT, SVN, FILE
INSTALL_TYPE="GIT"

# LOCATION OF THE FILE OR GIT/SVN REPOSITORY
REPOSITORY_LOCATION="https://github.com/chrisallenlane/watchtower.git"

# WHERE DO YOU WANT TO INSTALL IT
INSTALL_LOCATION="watchtower"

# DEPENDS FOR DEBIAN INSTALLS
DEBIAN="ruby"

# COMMANDS TO RUN AFTER
AFTER_COMMANDS="gem install trollop,gem install fastercsv,gem install backports"