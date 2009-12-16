#**********************************************************************
# otpasswd -- One-time password manager and PAM module.
# Copyright (C) 2009 by Tomasz bla Fortuna <bla@thera.be>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE file for details.
##

##
# Global thingies
##

cmake_minimum_required(VERSION 2.6)

PROJECT(otpam)

SET(${PROJECT_NAME}_MAJOR_VERSION 0)
SET(${PROJECT_NAME}_MINOR_VERSION 1)

ADD_DEFINITIONS("-Wall -ggdb")

# Detect include dirs
FIND_PATH(GMP_INCLUDE_DIR gmp.h /usr/include/gmp /usr/local/include/gmp)
FIND_PATH(PAM_INCLUDE_DIR pam_modules.h /usr/include/security /usr/include/pam)
FIND_PATH(GMP_LIBRARY_DIR libgmp.so /lib /usr/lib /usr/local/lib)

INCLUDE_DIRECTORIES(${GMP_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${PAM_INCLUDE_DIR})
LINK_DIRECTORIES(${GMP_LIBRARY_DIR})

# Dependencies
INCLUDE(CheckLibraryExists)

CHECK_LIBRARY_EXISTS(gmp mpz_init "" HAVE_GMP)
CHECK_LIBRARY_EXISTS(ssl SHA256 "" HAVE_OPENSSL)
FIND_PACKAGE(OpenSSL REQUIRED)

##
# Targets
##

#SET(FILES src/crypto.c src/num.c src/ppp.c 
#	src/state.c src/print.c src/passcards.c)

ADD_LIBRARY(libotp SHARED libotp/crypto.c libotp/num.c libotp/ppp.c 
	libotp/state.c libotp/print.c libotp/passcards.c
	libotp/config.c)

# As other targets require this include directory...
INCLUDE_DIRECTORIES(libotp/)

# Pam module target
SET(CMAKE_SHARED_LIBRARY_PREFIX "")
ADD_LIBRARY(pam_otpasswd SHARED pam/pam_helpers.c pam/pam_otpasswd.c) 
TARGET_LINK_LIBRARIES(pam_otpasswd libotp gmp ssl pam)

# Password management target
ADD_EXECUTABLE(otpasswd utility/otpasswd.c utility/otpasswd_actions.c utility/testcases.c)
TARGET_LINK_LIBRARIES(otpasswd libotp gmp ssl)

# Install target
SET(CMAKE_INSTALL_PREFIX /usr)
INSTALL(TARGETS pam_otpasswd otpasswd
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION /lib/security)

INSTALL(TARGETS libotp
  LIBRARY DESTINATION /lib)

INSTALL(FILES examples/otpasswd-login DESTINATION /etc/pam.d)
INSTALL(FILES examples/otpasswd.conf DESTINATION /etc/security)
