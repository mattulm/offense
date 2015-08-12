#!/usr/bin/env python
#######################################
# Installation module for dictionaries
#######################################

# AUTHOR OF MODULE NAME
AUTHOR="mulm"

# DESCRIPTION OF THE MODULE
DESCRIPTION="This module will install/update arlandria - Simple LinkedIn scrapper for OSINT"

# INSTALL TYPE GIT, SVN, FILE DOWNLOAD
# OPTIONS = GIT, SVN, FILE
INSTALL_TYPE="GIT"

# LOCATION OF THE FILE OR GIT/SVN REPOSITORY
REPOSITORY_LOCATION="https://github.com/kussic/arlandria.git"

# WHERE DO YOU WANT TO INSTALL IT
INSTALL_LOCATION="arlandria"

# DEPENDS FOR DEBIAN INSTALLS
DEBIAN=""

# COMMANDS TO RUN AFTER
AFTER_COMMANDS="easy_install --upgrade google-api-python-client"