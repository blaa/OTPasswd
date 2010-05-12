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

cmake_minimum_required(VERSION 2.4.7)

PROJECT(otpasswd)

SET(${PROJECT_NAME}_MAJOR_VERSION 0)
SET(${PROJECT_NAME}_MINOR_VERSION 5pre1)

# Cmake says this is required for locating gmp/libotp.a
if(COMMAND cmake_policy)
  cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

# FIXME: -fPIC is required for .a library on x64 only!
# How to add it only to this target?
ADD_DEFINITIONS("-Wall -ggdb -fPIC")

option(PROFILE "Enable coverage tests" OFF)
option(DEBUG "Enable additional debug information" OFF)
option(NLS "Enable National Language Support (NLS)" OFF)
# option( MYSQL "Generate code for MySQL database" OFF )
# option( LDAP "Generate code for LDAP" OFF )


# If PROFILE option given - enable coverage tests
IF (PROFILE)
  ADD_DEFINITIONS("-static -fprofile-arcs -ftest-coverage")
  LINK_LIBRARIES(gcov)
ENDIF (PROFILE)

IF (DEBUG)
  ADD_DEFINITIONS("-DDEBUG_POSITIONS=1")
ENDIF (DEBUG)

IF (NLS)
  ADD_DEFINITIONS("-DUSE_NLS=1")
ENDIF (NLS)


# Detect system
IF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  ADD_DEFINITIONS("-DOS_LINUX")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "Linux")

IF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  ADD_DEFINITIONS("-DOS_FREEBSD")
ENDIF(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")

# Detect include dirs
FIND_PATH(GMP_INCLUDE_DIR gmp.h /usr/include/gmp /usr/local/include/gmp)
FIND_PATH(PAM_INCLUDE_DIR pam_modules.h /usr/include/security /usr/include/pam)
FIND_PATH(GMP_LIBRARY_DIR libgmp.so /lib /usr/lib /usr/local/lib)

INCLUDE_DIRECTORIES(${GMP_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${PAM_INCLUDE_DIR})
LINK_DIRECTORIES(${GMP_LIBRARY_DIR})

# Module and PAM uses libotp, so add it's include to path...
INCLUDE_DIRECTORIES(libotp/ crypto/ agent/)

##
# Manuals
#   Rules for building compressed manuals
##

# See if gzip is available to compress manuals
FIND_PROGRAM(GZIP_TOOL
             NAMES gzip
             PATHS /bin
                   /usr/bin
                   /usr/local/bin)

IF(NOT GZIP_TOOL)
   MESSAGE(SEND_ERROR "Unable to find 'gzip' program")
ENDIF(NOT GZIP_TOOL)

# List manual sources
SET(man_src_1 docs/otpasswd.1    )
SET(man_src_5 docs/otpasswd.5    )
SET(man_src_8 docs/pam_otpasswd.8)
SET(man_src   "${man_src_1}" "${man_src_5}" "${man_src_8}")

# Generate list compressed manuals
STRING(REGEX REPLACE "(\\.[0-9]+)(;|$)" "\\1.gz\\2" man_gz_1 "${man_src_1}")
STRING(REGEX REPLACE "(\\.[0-9]+)(;|$)" "\\1.gz\\2" man_gz_5 "${man_src_5}")
STRING(REGEX REPLACE "(\\.[0-9]+)(;|$)" "\\1.gz\\2" man_gz_8 "${man_src_8}")
STRING(REGEX REPLACE "(\\.[0-9]+)(;|$)" "\\1.gz\\2" man_gz   "${man_src}"  )

# Generate build rules for building compressed manuals
FOREACH(man ${man_src})
  ADD_CUSTOM_COMMAND(OUTPUT ${man}.gz
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/docs
    COMMAND ${GZIP_TOOL} -c ${CMAKE_CURRENT_SOURCE_DIR}/${man} > ${CMAKE_CURRENT_BINARY_DIR}/${man}.gz
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${man}
    COMMENT "Building ${man}.gz")
ENDFOREACH(man)

##
# Targets
##

# Library containing common functions
ADD_LIBRARY(otp STATIC libotp/crypto.c libotp/num.c libotp/ppp.c 
	libotp/state.c libotp/print.c libotp/passcards.c
        libotp/db_file.c libotp/db_mysql.c libotp/db_ldap.c
	libotp/config.c crypto/polarssl_aes.c crypto/coreutils_sha256.c)

# Library containing agent functions (for both agent and its clients)
ADD_LIBRARY(agent STATIC agent/agent_interface.c agent/agent_private.c)


# Pam module target
ADD_LIBRARY(pam_otpasswd SHARED pam/pam_helpers.c pam/pam_otpasswd.c) 
SET_TARGET_PROPERTIES(pam_otpasswd PROPERTIES PREFIX "")

# Password management target
ADD_EXECUTABLE(otpasswd utility/otpasswd.c)

# Agent server
ADD_EXECUTABLE(agent_otp agent/agent.c agent/request.c agent/testcases.c agent/security.c)


# Linking targets
TARGET_LINK_LIBRARIES(pam_otpasswd  otp gmp pam)
TARGET_LINK_LIBRARIES(otpasswd      agent otp gmp)
TARGET_LINK_LIBRARIES(agent_otp     otp agent)

# Man page target
ADD_CUSTOM_TARGET(man ALL DEPENDS ${man_gz})

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
INSTALL(FILES examples/otpasswd.conf.dist DESTINATION /etc/otpasswd)

INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${man_gz_1} DESTINATION "share/man/man1")
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${man_gz_5} DESTINATION "share/man/man5")
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/${man_gz_8} DESTINATION "share/man/man8")


##
# Tests / Coverage
# WARNING: THIS TESTS MODIFY USER STATE!
##
ENABLE_TESTING()

# ADD_TEST(internal_check ./otpasswd --check) FIXME TURN THIS ON
# This may fail if user does not have state file!
# This tests are used mostly to have some rationale
# coverage test results
ADD_TEST(state_key0 "/bin/yes no | ./otpasswd -v -k")
ADD_TEST(state_flag0 ./otpasswd -v -c codelength=4)
ADD_TEST(state_print1 ./otpasswd -v -t "D10[123]")
ADD_TEST(state_print2 ./otpasswd -v -t "[123]")
ADD_TEST(state_print3 ./otpasswd -v -t "123")
ADD_TEST(state_print4 ./otpasswd -v -l "[124]")
ADD_TEST(state_print5 ./otpasswd -v -t "current")
ADD_TEST(state_print6 ./otpasswd -v -t "next")
ADD_TEST(state_print7 ./otpasswd -v -t "[next]")

ADD_TEST(state_skip1 ./otpasswd -v -s "[3]")
ADD_TEST(state_flag1 ./otpasswd -v -c show=off)
ADD_TEST(state_flag2 ./otpasswd -v -c codelength=12)
ADD_TEST(state_flag3 ./otpasswd -v -c alphabet=5)
ADD_TEST(state_flag4 ./otpasswd -v -c alphabet=2)
ADD_TEST(state_flag5 ./otpasswd -v -c alphabet=list)
ADD_TEST(state_flag6 ./otpasswd -v -i)
ADD_TEST(state_flag7 ./otpasswd -v --info-key)
ADD_TEST(state_label ./otpasswd -v -c "label=Set label")
ADD_TEST(state_contact ./otpasswd -v -c "contact=123456")
ADD_TEST(state_unset ./otpasswd -v -c contact= -c label=)
ADD_TEST(state_multi ./otpasswd -v -c contact=aAaA -c label=label)
ADD_TEST(state_warnings ./otpasswd -v -w)

# Tests which should fail
ADD_TEST(fail_ok1 ./otpasswd -v -l "[0]")
ADD_TEST(fail_ok2 ./otpasswd -v -l "0")
ADD_TEST(fail_ok3 ./otpasswd -v -t "340282366920938463463374607431768211457")
ADD_TEST(fail_ok4 ./otpasswd -v -s "-5")
ADD_TEST(fail_ok5 ./otpasswd -v -c contact="f`g")
ADD_TEST(fail_ok6 ./otpasswd -v -c label="f`g")
ADD_TEST(fail_ok7 ./otpasswd -v -c label="012345678901234567890123456789012345678901234567890")
ADD_TEST(fail_ok8 ./otpasswd -v -c contact="0123456789012345678901234567890123456789012345678900123456789")
ADD_TEST(fail_ok9 ./otpasswd -v -c codelength=17)
ADD_TEST(fail_ok10 ./otpasswd -v -c codelength=1)
ADD_TEST(fail_ok11 ./otpasswd -v -c alphabet=-1)
ADD_TEST(fail_ok12 ./otpasswd -v -c alphabet=33)
ADD_TEST(fail_ok13 ./otpasswd -v -c alphabet)
ADD_TEST(fail_ok14 ./otpasswd -v -c alphabet=2 illegal_arg)
ADD_TEST(fail_ok15 ./otpasswd -a '___')
ADD_TEST(fail_ok16 ./otpasswd --nonexisting-command a)

SET_TESTS_PROPERTIES(fail_ok1 fail_ok2 fail_ok3 fail_ok4
  fail_ok5 fail_ok6 fail_ok7 fail_ok8 fail_ok9 fail_ok10 fail_ok11
  fail_ok12 fail_ok13 fail_ok14 fail_ok15 fail_ok16
  PROPERTIES WILL_FAIL TRUE)

