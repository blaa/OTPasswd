SET(CTEST_CUSTOM_PRE_TEST 
	"/bin/echo WARNING: THIS TESTS WILL MODIFY YOUR STATE INFORMATION. Starting in 5 seconds.
	Tests should be run with english locale, agent installed and DB=user.
	; sleep 5")

# This doesn't work yet:
SET(MemoryCheckCommand valgrind)
