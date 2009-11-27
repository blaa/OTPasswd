cmake_minimum_required(VERSION 2.5)

PROJECT(otpam)

SET(${PROJECT_NAME}_MAJOR_VERSION 0)
SET(${PROJECT_NAME}_MINOR_VERSION 1)

ADD_DEFINITIONS("-Wall -ggdb")

INCLUDE(CheckLibraryExists)

CHECK_LIBRARY_EXISTS(gmp mpz_init "" HAVE_GMP)
CHECK_LIBRARY_EXISTS(ssl SHA256 "" HAVE_OPENSSL)
FIND_PACKAGE(OpenSSL REQUIRED)


ADD_EXECUTABLE(otpasswd crypto.c num.c ppp.c state.c print.c otpasswd.c passcards.c)

TARGET_LINK_LIBRARIES(otpasswd gmp ssl)
