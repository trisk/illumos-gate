/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <libgen.h>
#include "cfga_fp.h"

/* The following are used by update_fabric_wwn_list() */
#define	COPY_EXT	".cpy."		/* Extn used in naming backup file */
#define	TMP_EXT		".tmp."		/* Extn used in naming temp file */
static char *HDR =
"#\n"
"# fabric_WWN_map\n"
"#\n"
"# The physical ap_id list of configured fabric devices.\n"
"# Do NOT edit this file by hand -- refer to the cfgadm_fp(1M)\n"
"# man page and use cfgadm(1m) instead.\n"
"#\n";

/*
 * This function searches for "srch_str" (of length "slen") in "buf" (of length
 * "buflen"). If it is not found, "write_offset" has the offset in "buf" where
 * "srch_str" would have to be added in "buf". If "srch_str" is found in "buf",
 * "write_offset" has its offset in "buf"
 *
 * ARGUMENTS :
 * buf		- buffer to search in
 * buflen	- length of buffer
 * srch_str	- string to search
 * slen		- length of srch_str
 * write_offset	- Set in function on exit
 *		- It is the offset in buf where srch_str is or should be
 * bytes_left	- Set in function on exit
 *		- It is the # of bytes left beyond write_offset in buf
 *
 * Notes :
 * -	This function assumes "buf" is sorted in ascending order
 * -	If 'buflen' is > 0, it assumes it has a header on top and skips it
 * -	"srch_str" has '\n' at the end, but when update_fabric_wwn_list() calls
 *	this function, 'slen' does not include the last `\n'
 *
 * RETURN VALUES :
 * Zero - "srch_str" found in "buf"... "write_offset" has offset in "buf"
 * > 0  - "srch_str" NOT found in "buf" ... "write_offset" has offset in "buf"
 *		where "srch_str" can fit in.
 *		"buf" had contents > "srch_str"
 * < 0  - "srch_str" NOT found in "buf" ... "write_offset" has offset in "buf"
 *		where "srch_str" can fit in.
 *		"buf" had contents < "srch_str"
 */
static int
search_line(char *buf, int buflen, char *srch_str, int slen,
				int *write_offset, int *bytes_left)
{
	int	retval, sizeof_rep_hdr = strlen(HDR);
	char	*sol;		/* Pointer to Start-Of-Line */
	char	*cur_pos;	/* current position */

	*bytes_left = buflen;
	*write_offset = 0;

	if (buf == NULL || *buf == NULL || buflen <= 0)
		return (-2);	/* Arbitrary -ve val. srch_str not found */

	if (srch_str == NULL || *srch_str == NULL || slen <= 0)
		return (0);	/* This says srch_str was found */

	sol = cur_pos = buf;
	if (buflen >= sizeof_rep_hdr) {
		/* skip header */
		sol = cur_pos = buf + sizeof_rep_hdr;
		*bytes_left -= sizeof_rep_hdr;
	}

	while (*bytes_left >= slen) {
		if ((retval = strncmp(sol, srch_str, slen)) >= 0) {
			/* strncmp will pass if srch_str is a substring */
			if ((retval == 0) && (*bytes_left > slen) &&
						(*(sol+slen) != '\n'))
				retval = 1;	/* Force it to be > 0 */
			*write_offset = sol - buf;
			return (retval);
		}

		/* retval < 0 */
		if ((cur_pos = strchr(sol, (int)'\n')) == NULL) {
			*write_offset = buflen;
			return (retval);
		}

		/* Get the length of this line */
		*cur_pos = '\0';	/* kludge to get string length */
		*bytes_left -= (strlen(sol) + 1);
		*cur_pos = '\n';	/* Put back the original char */

		sol = cur_pos = cur_pos + 1;
	}

	if (*bytes_left > 0) {
		/* In this case the bytes left will be less than slen */
		if ((retval = strncmp(sol, srch_str, *bytes_left)) >= 0) {
			*write_offset = sol - buf;
		} else {
			*write_offset = buflen;
		}
		return (retval);
	}
	*write_offset = sol - buf;
	/* Should return a value < 0 to show that search string goes to eof */
	return (-1);
}

/*
 * This function sets an advisory lock on the file pointed to by the argument
 * fd, which is a file descriptor. The lock is set using fcntl() which uses
 * flock structure.
 */
int
lock_register(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
	struct flock lock;

	lock.l_type = type;
	lock.l_start = offset;
	lock.l_whence = whence;
	lock.l_len = len;

	return (fcntl(fd, cmd, &lock));
}

/* Lot of places to cleanup - Less chance of missing out using this macro */
#define	CLEANUP_N_RET(ret)	\
			if (fd != -1) { \
				close(fd); \
			} \
			if (copy_fd != -1) { \
				close(copy_fd); \
			} \
			if (tmp_fd != -1) { \
				close(tmp_fd); \
			} \
			if (copy_rep != NULL) { \
				remove(copy_rep); \
				free(copy_rep); \
			} \
			if (tmp_rep != NULL) { \
				remove(tmp_rep); \
				free(tmp_rep); \
			} \
			if (upd_str != NULL) { \
				free(upd_str); \
			} \
			if (repbuf != NULL) { \
				munmap(repbuf, filesize); \
			} \
			if (c_repbuf != NULL) { \
				munmap(c_repbuf, filesize); \
			} \
			if (t_repbuf != NULL) { \
				munmap(t_repbuf, size); \
			} \
			return (ret)

/*
 * INPUTS:
 * cmd		- ADD_ENTRY or REMOVE_ENTRY
 * update_str	- string for repository operation
 *		- Assumed NOT to have a '\n' and that it is null terminated
 * errstring	- Pointer that will be updated by this function
 *		- Any error msgs that has to be sent back to caller
 *
 * RETURNS :
 * FPCFGA_OK on success
 * FPCFGA_LIB_ERR on error
 *
 * SYNOPSIS:
 * This function adds or deletes 'update_str' from FAB_REPOSITORY based on
 * value of 'cmd'. The repository has a warning line on the top to disallow
 * manual editing of the file. If the repository is being created fresh or if
 * it is of zero length or if it has only warning lines in it, the operation
 * speicified by 'cmd' is performed and returned. If the repository exists
 * and has some data, it is expected to be of atleast the size of the lenght
 * of the warning header. This is the only check that is performed on the
 * validity of the file. No other checks are performed. On a valid
 * repository, to perform the update, this function basically makes use of
 * 3 buffers - the original buffer (repbuf), a copy buffer (c_repbuf) and a
 * temp buffer (t_repbuf).
 * The contents of the repository are mmap-ed into the repbuf and then
 * copied into the c_repbuf. All further operations are done using the copy.
 * t_repbuf is created to be the size of c_repbuf +/- 'slen' (based on
 * whether it is add or remove operation). After adding/removing the
 * 'update_str', the c_repbuf is copied to a OLD_FAB_REPOSITORY and t_repbuf
 * is made FAB_REPOSITORY.
 *
 */
int
update_fabric_wwn_list(int cmd, const char *update_str, char **errstring)
{
	int	fd, copy_fd, tmp_fd, new_file_flag = 0;
	int	len, write_offset, bytes_left;
	int	sizeof_rep_hdr = strlen(HDR);
	char	*repbuf, *c_repbuf, *t_repbuf;
	char	*copy_rep, *tmp_rep, *upd_str;
	off_t	filesize, size;
	struct stat	stbuf;

	/* Do some initializations */
	fd = copy_fd = tmp_fd = -1;
	repbuf = c_repbuf = t_repbuf = NULL;
	copy_rep = tmp_rep = upd_str = NULL;
	size = filesize = write_offset = bytes_left = 0;

	/*
	 * Set the mode to read only.  Root user can still open as RDWR.
	 * We ignore errors in general here. But, just notice ENOENTs
	 */
	if ((chmod(FAB_REPOSITORY, S_IRUSR|S_IRGRP|S_IROTH) == -1) &&
							(errno == ENOENT)) {
		new_file_flag = 1;
		mkdirp(FAB_REPOSITORY_DIR,
				S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
	}

	/* Create the repository if its not there */
	if ((fd = open(FAB_REPOSITORY, O_RDWR | O_CREAT)) == -1) {
		cfga_err(errstring, errno, ERR_UPD_REP, 0);
		return (FPCFGA_LIB_ERR);
	}

	/* Now try to chmod again. This time we dont ignore errors */
	if (fchmod(fd, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
		close(fd);
		cfga_err(errstring, errno, ERR_UPD_REP, 0);
		return (FPCFGA_LIB_ERR);
	}

	if (lock_register(fd, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0) < 0) {
		close(fd);
		cfga_err(errstring, 0, ERR_UPD_REP, 0);
		return (FPCFGA_LIB_ERR);
	}

	if (fstat(fd, &stbuf) == -1) {
		close(fd);
		cfga_err(errstring, errno, ERR_UPD_REP, 0);
		return (FPCFGA_LIB_ERR);
	}

	filesize = size = stbuf.st_size;

	/* A very Minimal check on repository */
	if (filesize && filesize < sizeof_rep_hdr) {
		/*
		 * If there is some data, it should be atleast the size of
		 * the header
		 */
		close(fd);
		cfga_err(errstring, errno, ERR_UPD_REP, 0);
		return (FPCFGA_LIB_ERR);
	}

	if ((len = strlen(update_str)) == 0) {
		/*
		 * We are trying to add/remove a NULL string.
		 * Just return success
		 */
		close(fd);
		return (FPCFGA_OK);
	}

	if ((upd_str = calloc(1, len + 2)) == NULL) {
		close(fd);
		cfga_err(errstring, errno, ERR_UPD_REP, 0);
		return (FPCFGA_LIB_ERR);
	}

	strcpy(upd_str, update_str);
	strcat(upd_str, "\n");		/* Append a new line char */
	len = strlen(upd_str);

	if (filesize > 0) {
		if ((copy_rep = (char *)calloc(1, strlen(FAB_REPOSITORY) +
				sizeof (COPY_EXT) + sizeof (pid_t))) == NULL) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		(void) sprintf(copy_rep, "%s%s%ld", FAB_REPOSITORY, COPY_EXT,
								getpid());

		if ((copy_fd = open(copy_rep, O_RDWR | O_CREAT | O_TRUNC,
						S_IRUSR | S_IWUSR)) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if ((repbuf = (char *)mmap(0, filesize, PROT_READ,
					MAP_SHARED, fd, 0)) == MAP_FAILED) {
			close(fd);
			free(upd_str);
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			return (FPCFGA_LIB_ERR);
		}

		if (lseek(copy_fd, filesize - 1, SEEK_SET) == -1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (write(copy_fd, "", 1) != 1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if ((c_repbuf = (char *)mmap(0, filesize,
				PROT_READ | PROT_WRITE,
				MAP_SHARED, copy_fd, 0)) == MAP_FAILED) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		memcpy(c_repbuf, repbuf, filesize);
		/*
		 * We cannot close the repository since we hold a lock
		 * But we'll free up the mmap-ed area.
		 */
		munmap(repbuf, filesize);
		repbuf = NULL;
	}

	/*
	 * If we just created this file, or it was an empty repository file
	 * add a header to the beginning of file.
	 * If it had was a repository file with just the header,
	 */
	if (new_file_flag != 0 || filesize == 0 || filesize == sizeof_rep_hdr) {
		if ((filesize != sizeof_rep_hdr) &&
			(write(fd, HDR, sizeof_rep_hdr) != sizeof_rep_hdr)) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		/*
		 * We know its a new file, empty file or a file with only a
		 * header so lets get the update operation done with
		 */
		switch (cmd) {
		case ADD_ENTRY:
			/* If there is a header, we have to skip it */
			if (lseek(fd, 0, SEEK_END) == -1) {
				cfga_err(errstring, errno, ERR_UPD_REP, 0);
				CLEANUP_N_RET(FPCFGA_LIB_ERR);
			}

			if (write(fd, upd_str, len) != len) {
				cfga_err(errstring, errno, ERR_UPD_REP, 0);
				CLEANUP_N_RET(FPCFGA_LIB_ERR);
			}

			if (filesize > 0) {
				/* Now create the '.old' file */
				if (msync(c_repbuf, filesize, MS_SYNC) == -1) {
					cfga_err(errstring, errno,
								ERR_UPD_REP, 0);
					CLEANUP_N_RET(FPCFGA_LIB_ERR);
				}

				if (fchmod(copy_fd,
					S_IRUSR | S_IRGRP | S_IROTH) < 0) {
					cfga_err(errstring, errno,
								ERR_UPD_REP, 0);
					CLEANUP_N_RET(FPCFGA_LIB_ERR);
				}
				rename(copy_rep, OLD_FAB_REPOSITORY);
			}

			CLEANUP_N_RET(FPCFGA_OK);

		case REMOVE_ENTRY:
			/*
			 * So, the side effect of a remove on an empty or
			 * non-existing repository is that the repository got
			 * created
			 */
			CLEANUP_N_RET(FPCFGA_OK);

		default:
			cfga_err(errstring, 0, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}
	}

	/* Now, size and filesize are > sizeof_rep_hdr */

	switch (cmd) {
	case ADD_ENTRY:
		size += len;
		/*
		 * We'll search the full repository, header included, since
		 * we dont expect upd_str to match anything in the header.
		 */
		if (search_line(c_repbuf, filesize, upd_str,
				len - 1, &write_offset, &bytes_left) == 0) {
			/* line already exists in repository or len == 0 */
			CLEANUP_N_RET(FPCFGA_OK); /* SUCCESS */
		}

		/* construct temp file name using pid. */
		if ((tmp_rep = (char *)calloc(1, strlen(FAB_REPOSITORY) +
				sizeof (TMP_EXT) + sizeof (pid_t))) == NULL) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		(void) sprintf(tmp_rep, "%s%s%ld", FAB_REPOSITORY,
							TMP_EXT, getpid());

		/* Open tmp repository file in absolute mode */
		if ((tmp_fd = open(tmp_rep, O_RDWR|O_CREAT|O_TRUNC,
						S_IRUSR | S_IWUSR)) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (lseek(tmp_fd, size - 1, SEEK_SET) == -1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (write(tmp_fd, "", 1) != 1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if ((t_repbuf = (char *)mmap(0, size, PROT_READ|PROT_WRITE,
					MAP_SHARED, tmp_fd, 0)) == MAP_FAILED) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		memcpy(t_repbuf, c_repbuf, write_offset);
		strncpy(t_repbuf + write_offset, upd_str, len);
		if (write_offset != filesize) {
			memcpy(t_repbuf + write_offset + len,
					c_repbuf + write_offset, bytes_left);
		}

		/*
		 * we are using the copy of FAB_REPOSITORY and will
		 * do msync first since it will be renamed to '.old' file.
		 */
		if (msync(c_repbuf, filesize, MS_SYNC) == -1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (fchmod(copy_fd, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (msync(t_repbuf, size, MS_SYNC) == -1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (fchmod(tmp_fd, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		close(copy_fd); copy_fd = -1;
		close(tmp_fd); tmp_fd = -1;

		/* here we do rename and rename before close fd */
		rename(copy_rep, OLD_FAB_REPOSITORY);
		rename(tmp_rep, FAB_REPOSITORY);

		if (lock_register(fd, F_SETLK, F_UNLCK, 0, SEEK_SET, 0) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		CLEANUP_N_RET(FPCFGA_OK);

	case REMOVE_ENTRY:
		if (size >= sizeof_rep_hdr + len - 1) {
			size -= len;
			/*
			 * No need to init the 'else' part (size < len) because
			 * in that case, there will be nothing to delete from
			 * the file and so 'size' will not be used in the code
			 * below since search_line() will not find upd_str.
			 */
		}

		if (search_line(c_repbuf, filesize, upd_str, len - 1,
					&write_offset, &bytes_left) != 0) {
			/* this line does not exists - nothing to remove */
			CLEANUP_N_RET(FPCFGA_OK); /* SUCCESS */
		}

		/* construct temp file name using pid. */
		if ((tmp_rep = (char *)calloc(1, strlen(FAB_REPOSITORY) +
				sizeof (TMP_EXT) + sizeof (pid_t))) == NULL) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		(void) sprintf(tmp_rep, "%s%s%ld", FAB_REPOSITORY,
							TMP_EXT, getpid());

		/* Open tmp repository file in absolute mode */
		if ((tmp_fd = open(tmp_rep, O_RDWR|O_CREAT|O_TRUNC,
						S_IRUSR | S_IWUSR)) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (size > 0) {
			if (lseek(tmp_fd, size - 1, SEEK_SET) == -1) {
				cfga_err(errstring, errno, ERR_UPD_REP, 0);
				CLEANUP_N_RET(FPCFGA_LIB_ERR);
			}

			if (write(tmp_fd, "", 1) != 1) {
				cfga_err(errstring, errno, ERR_UPD_REP, 0);
				CLEANUP_N_RET(FPCFGA_LIB_ERR);
			}

			if ((t_repbuf = (char *)mmap(0, size,
					PROT_READ|PROT_WRITE,
					MAP_SHARED, tmp_fd, 0)) == MAP_FAILED) {
				cfga_err(errstring, errno, ERR_UPD_REP, 0);
				CLEANUP_N_RET(FPCFGA_LIB_ERR);
			}

			memcpy(t_repbuf, c_repbuf, write_offset);
			if ((bytes_left - len) > 0) {
				memcpy(t_repbuf + write_offset,
					c_repbuf + write_offset + len,
							bytes_left - len);
			}

			if (msync(t_repbuf, size, MS_SYNC) == -1) {
				cfga_err(errstring, errno, ERR_UPD_REP, 0);
				CLEANUP_N_RET(FPCFGA_LIB_ERR);
			}
		}

		if (fchmod(tmp_fd, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		/*
		 * we are using the copy of FAB_REPOSITORY and will
		 * do msync first since it will be renamed to bak file.
		 */
		if (msync(c_repbuf, filesize, MS_SYNC) == -1) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		if (fchmod(copy_fd, S_IRUSR | S_IRGRP | S_IROTH) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		/* Close and invalidate the fd's */
		close(copy_fd); copy_fd = -1;
		close(tmp_fd); tmp_fd = -1;

		/* here we do rename and rename before close fd */
		rename(copy_rep, OLD_FAB_REPOSITORY);
		rename(tmp_rep, FAB_REPOSITORY);

		if (lock_register(fd, F_SETLK, F_UNLCK, 0, SEEK_SET, 0) < 0) {
			cfga_err(errstring, errno, ERR_UPD_REP, 0);
			CLEANUP_N_RET(FPCFGA_LIB_ERR);
		}

		CLEANUP_N_RET(FPCFGA_OK);

	default:
		/* Unexpected - just getout */
		break;
	}

	CLEANUP_N_RET(FPCFGA_OK);			/* SUCCESS */
}
