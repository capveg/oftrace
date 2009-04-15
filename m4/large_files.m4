# SYNOPSIS
#
#  LARGE_FILES
#
# DESCRIPTION
#
#   set $LARGEFILES_CFLAGS and $LARGFILES_LDFLAGS to the right
#	machine specific settings (or try at least)
#
# LAST MODIFICATION
#

AC_DEFUN([LARGE_FILES],[
        LARGEFILES_CFLAGS="-D_LARGEFILE_SOURCE `getconf LFS_CFLAGS` "
	LARGEFILES_LDFLAGS="`getconf LFS_LDFLAGS` `getconf LFS_LIBS` "
])
