AC_PREREQ([2.69])
AC_INIT([vdens], [0.1], [info@virtualsquare.org])
AM_INIT_AUTOMAKE([foreign dist-bzip2])
AC_CONFIG_SRCDIR([vdens.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([vdeplug], [vde_open_real])
AC_CHECK_LIB([cap], [cap_get_proc])
AC_CHECK_LIB([execs], [s2multiargv])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h limits.h stdlib.h sys/ioctl.h sys/capability.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
