dnl Configury specific to the libfabric zhpe_offloaded provider

dnl Called to configure this provider
dnl
dnl Arguments:
dnl
dnl $1: action if configured successfully
dnl $2: action if not configured successfully
dnl
AC_DEFUN([FI_ZHPE_OFFLOADED_CONFIGURE],
[
  # Determine if we can support the zhpe provider
  zhpe_offloaded_happy=0
  AS_IF([test x"$enable_zhpe" != x"no"],
  [
    # Set up zhpe-support paths
    zhpe_offloaded_happy=1
    FI_CHECK_PACKAGE([zhpe], [zhpeq.h], [zhpeq], [zhpeq_alloc], [],
                     [$zhpe_offloaded_PREFIX], [$zhpe_offloaded_LIBDIR],, [zhpe_offloaded_happy=0])
    # Build with Carbon stats support
    AC_ARG_WITH(
      [zhpe-sim-stats],
      [AS_HELP_STRING(
        [--with-zhpe-sim-stats],
        [Build with simulator stats support])],
      [
	zhpe_offloaded_CPPFLAGS="$zhpe_offloaded_CPPFLAGS -DHAVE_ZHPE_OFFLOADED_STATS"
	zhpe_offloaded_LIBS="$zhpe_offloaded_LIBS -lzhpe_offloaded_stats"
      ])
    # ummunotify needed for now to support registration cache
    AC_CHECK_HEADER(
      [linux/ummunotify.h],
      [zhpe_offloaded_CPPFLAGS="$zhpe_offloaded_CPPFLAGS -DHAVE_LINUX_UMMUNOTIFY_H"])
  ])
  AS_IF([test $zhpe_offloaded_happy -eq 1], [$1], [$2])
])
