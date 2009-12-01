##
# Global thingies
##

cmake_minimum_required(VERSION 2.6)

PROJECT(otpam)

SET(${PROJECT_NAME}_MAJOR_VERSION 0)
SET(${PROJECT_NAME}_MINOR_VERSION 1)

ADD_DEFINITIONS("-Wall -ggdb")

# Dependencies
INCLUDE(CheckLibraryExists)

CHECK_LIBRARY_EXISTS(gmp mpz_init "" HAVE_GMP)
CHECK_LIBRARY_EXISTS(ssl SHA256 "" HAVE_OPENSSL)
FIND_PACKAGE(OpenSSL REQUIRED)

##
# PAM Thingies
##
FIND_PATH(PAM_INCLUDE_DIR pam_modules.h /usr/include/security /usr/include/pam)
INCLUDE_DIRECTORIES(${PAM_INCLUDE_DIR})

##
# Targets
##
# Pam module target
SET(CMAKE_SHARED_LIBRARY_PREFIX "")
ADD_LIBRARY(pam_otpasswd SHARED pam_otpasswd.c crypto.c num.c ppp.c state.c print.c passcards.c)
TARGET_LINK_LIBRARIES(pam_otpasswd gmp ssl pam)

# Password management target
ADD_EXECUTABLE(otpasswd otpasswd.c otpasswd_actions.c crypto.c num.c ppp.c state.c print.c passcards.c)
TARGET_LINK_LIBRARIES(otpasswd gmp ssl)

# Install target
SET(CMAKE_INSTALL_PREFIX /usr)
INSTALL(TARGETS pam_otpasswd otpasswd 
  RUNTIME DESTINATION bin
  LIBRARY DESTINATION /lib/security)

INSTALL(FILES examples/otpasswd-login DESTINATION /etc/pam.d)
