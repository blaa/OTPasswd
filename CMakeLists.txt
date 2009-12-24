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

# -fPIC is required for .a library on x64 only!
# How to add it only to this target?
ADD_DEFINITIONS("-Wall -ggdb -fPIC")

option(PROFILE "Unable coverage tests" OFF)

# If Debug option given - enable coverage tests
IF (PROFILE)
  ADD_DEFINITIONS("-static -fprofile-arcs -ftest-coverage")
  LINK_LIBRARIES(gcov)

#  SET(ADDITIONAL_LIBS gcov -fprofile-arcs)
ENDIF (PROFILE)

# Detect system
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  ADD_DEFINITIONS("-DOS_LINUX")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  ADD_DEFINITIONS("-OS_FREEBSD")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")

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

# Module and PAM uses libotp, so add it's include to path...
INCLUDE_DIRECTORIES(libotp/)

# option( MYSQL "Generate code for MySQL database" OFF )

##
# Targets
##

# Library containing common functions
ADD_LIBRARY(otp STATIC libotp/crypto.c libotp/num.c libotp/ppp.c 
	libotp/state.c libotp/db.c libotp/print.c libotp/passcards.c
	libotp/config.c)

# Pam module target
SET(CMAKE_SHARED_LIBRARY_PREFIX "")
ADD_LIBRARY(pam_otpasswd SHARED pam/pam_helpers.c pam/pam_otpasswd.c) 

# Password management target
ADD_EXECUTABLE(otpasswd utility/otpasswd.c utility/otpasswd_actions.c utility/testcases.c utility/security.c)

# Linking targets
TARGET_LINK_LIBRARIES(pam_otpasswd otp gmp ssl pam ${ADDITIONAL_LIBS})
TARGET_LINK_LIBRARIES(otpasswd otp gmp ssl ${ADDITIONAL_LIBS})

##
# Install target
##
SET(CMAKE_INSTALL_PREFIX /usr)
INSTALL(TARGETS pam_otpasswd otpasswd
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION /lib/security)

#INSTALL(TARGETS libotp
#  LIBRARY DESTINATION /lib)

INSTALL(FILES examples/otpasswd-login DESTINATION /etc/pam.d)
INSTALL(FILES examples/otpasswd.conf DESTINATION /etc/security)

##
# Tests / Coverage
##
ENABLE_TESTING()
ADD_TEST(internal_check ./otpasswd --check)
# This may fail if user does not have state file!
# This tests are used mostly to have some rationale
# coverage test results
ADD_TEST(state_print1 ./otpasswd -t 'G10[123]')
ADD_TEST(state_print2 ./otpasswd -t '[123]')
ADD_TEST(state_print3 ./otpasswd -t '123')
ADD_TEST(state_print4 ./otpasswd -l '[123]')

ADD_TEST(state_skip1 ./otpasswd -s '[3]')
ADD_TEST(state_prompt ./otpasswd -p 'current')
ADD_TEST(state_flag1 ./otpasswd -f dont-show)
ADD_TEST(state_flag2 ./otpasswd -f codelength-12)
ADD_TEST(state_flag3 ./otpasswd -f alphabet-extended)


# Tests which should fail (but won't return incorrect status)
ADD_TEST(fail_ok1 ./otpasswd -l '[0]')
ADD_TEST(fail_ok2 ./otpasswd -l '0')
ADD_TEST(fail_ok3 ./otpasswd -t '340282366920938463463374607431768211457')
ADD_TEST(fail_ok4 ./otpasswd -s '-5')
ADD_TEST(should_fail1 ./otpasswd -a '___')


