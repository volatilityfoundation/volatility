/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Antoine Brodin
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Dump memory, this was successfully tested on:
 * - amd64
 * - i386 with less than 4GB of ram
 * - i386 with more than 4GB of ram after https://svnweb.freebsd.org/changeset/base/343667 or https://svnweb.freebsd.org/changeset/base/350856
 */
#include <sys/param.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <devinfo.h>


static void usage(void);
static int find_io_memory_rman(struct devinfo_rman *, void *);
static int find_ram0_rman_resource(struct devinfo_res *, void *);
static int write_lime_header(int, uint64_t, uint64_t);
static int write_memory_segment(int, off_t, size_t);

struct lime_header {
	uint32_t magic;
	uint32_t version;
	uint64_t start;
	uint64_t end;
	uint64_t padding;
} __packed;

#define	BUFSIZE	1024 * 1024

int
main(int argc, char *argv[])
{
	int fd, rv;

	if (argc != 2)
		usage();
	if (strcmp(argv[1], "-") == 0)
		fd = STDOUT_FILENO;
	else if ((fd = open(argv[1], O_CREAT | O_WRONLY | O_TRUNC, 0600)) == -1)
		err(EX_CANTCREAT, "%s", argv[1]);
	if ((rv = devinfo_init()) != 0) {
		errno = rv;
		err(EX_SOFTWARE, "devinfo_init");
	}
	devinfo_foreach_rman(find_io_memory_rman, &fd);
	devinfo_free();
	if (fd != STDOUT_FILENO)
		close(fd);
	exit(EX_OK);
}

static void
usage(void)
{

	fprintf(stderr, "usage: %s file.lime|-\n", getprogname());
	exit(EX_USAGE);
}

static int
find_io_memory_rman(struct devinfo_rman *rman, void *arg)
{

	if (strcmp(rman->dm_desc, "I/O memory addresses") == 0)
		devinfo_foreach_rman_resource(rman, find_ram0_rman_resource, arg);
	return (0);
}

static int
find_ram0_rman_resource(struct devinfo_res *res, void *arg)
{
	struct devinfo_dev *dev;

	dev = devinfo_handle_to_device(res->dr_device);
	if (dev != NULL && strcmp(dev->dd_name, "ram0") == 0) {
		fprintf(stderr, "Dumping 0x%jx -> 0x%jx\n", res->dr_start, res->dr_start + res->dr_size - 1);
		write_lime_header(*(int *)arg, res->dr_start, res->dr_start + res->dr_size - 1);
		write_memory_segment(*(int *)arg, res->dr_start, res->dr_size);
	}
	return (0);
}

static int
write_lime_header(int fd, uint64_t start, uint64_t end)
{
	static struct lime_header h;

	h.magic = 0x4c694d45;
	h.version = 1;
	h.start = start;
	h.end = end;
	if (write(fd, &h, sizeof(h)) != sizeof(h))
		err(EX_IOERR, "write_lime_header write");
	return (0);
}

static int
write_memory_segment(int outfd, off_t offset, size_t size)
{
	static void *buf;
	static int memfd;

	if (buf == NULL)
		if ((buf = malloc(BUFSIZE)) == NULL)
			err(EX_SOFTWARE, "write_memory_segment malloc");
	if (memfd == 0)
		if ((memfd = open("/dev/mem", O_RDONLY, 0)) == -1)
			err(EX_NOINPUT, "write_memory_segment open");
	if (lseek(memfd, offset, SEEK_SET) != offset)
		err(EX_SOFTWARE, "write_memory_segment lseek");
	while (size > 0) {
		ssize_t nbytes;

		nbytes = MIN(BUFSIZE, size);
		if (read(memfd, buf, nbytes) != nbytes)
			err(EX_IOERR, "write_memory_segment read");
		if (write(outfd, buf, nbytes) != nbytes)
			err(EX_IOERR, "write_memory_segment write");
		size -= nbytes;
	}
	return (0);
}

