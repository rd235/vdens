/* 
 * vdens: Create a user namespace connected to a VDE network
 * Copyright (C) 2016  Renzo Davoli, Davide Berardi University of Bologna
 * Credit: inspired by the example code included in the
 *         user_namespaces(7) man page
 * 
 * Vdens is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>. 
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sched.h>
#include <limits.h>
#include <errno.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <libvdeplug.h>
#include <poll.h>
#include <sys/signalfd.h>
#include <execs.h>

/* just in case prctl.h is not providing these definitions */
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT      47
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE  2
#endif
#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER  3
#endif

#define DEFAULT_IF_NAME "vde0"
#define errExit(msg)    ({ perror(msg); exit(EXIT_FAILURE); })

#define CONNTYPE_NONE 0
#define CONNTYPE_VDE 1
#define CONNTYPE_VDESTREAM 2

struct child_args {
	char **argv;
	int	pipe_fd[2];  /* Pipe used to synchronize parent and child */
	char *if_name;
	int conntype;
	union {
		VDECONN *vdeconn;
		int streamfd[2];
	} conn;
};

static void usage_exit(char *pname)
{
	fprintf(stderr, 
			"Usage: %s [-i ifname] [vde_net [cmd [arg...]]]\n"
			"\tno virtual interface if vde_net omitted or \"no\"\n"
			"\t-i defines the interface name, the default value is \"vde0\"\n"
			"\tit runs $SHELL if cmd omitted\n\n" , pname);
	exit(EXIT_FAILURE);
}

static int open_tap(char *name) {
	struct ifreq ifr;
	int fd=-1;
	if((fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC)) < 0)
		return -1;
	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

static void uid_gid_map(pid_t pid) {
	char map_file[PATH_MAX];
	FILE *f;
	uid_t euid = geteuid();
	gid_t egid = getegid();
	snprintf(map_file, PATH_MAX, "/proc/%d/uid_map", pid);
	f = fopen(map_file, "w");
	if (f) {
		fprintf(f,"%d %d 1\n",euid,euid);
		fclose(f);
	}
	snprintf(map_file, PATH_MAX, "/proc/%d/setgroups", pid);
	f = fopen(map_file, "w");
	if (f) {
		fprintf(f,"deny\n");
		fclose(f);
	}
	snprintf(map_file, PATH_MAX, "/proc/%d/gid_map", pid);
	f = fopen(map_file, "w");
	if (f) {
		fprintf(f,"%d %d 1\n",egid,egid);
		fclose(f);
	}
}

static void plug2tap(VDECONN *conn, int tapfd) {
	int n;
	char buf[4096];
	struct pollfd pfd[] = {{tapfd, POLLIN, 0}, {vde_datafd(conn), POLLIN, 0}, {-1, POLLIN, 0}};
	sigset_t chldmask;
	sigemptyset(&chldmask);
	sigaddset(&chldmask, SIGCHLD);
	int sfd = signalfd(-1, &chldmask, SFD_CLOEXEC);
	pfd[2].fd = sfd;
	while (ppoll(pfd, 3, NULL, &chldmask) >= 0) {
		if (pfd[0].revents & POLLIN) {
			n = read(tapfd, buf, 4096);
			if (n == 0) break;
			vde_send(conn, buf, n, 0);
		}
		if (pfd[1].revents & POLLIN) {
			n = vde_recv(conn, buf, 4096, 0);
			if (n == 0) break;
			write(tapfd, buf, n);
		}
		if (pfd[2].revents & POLLIN) {
			//struct signalfd_siginfo fdsi;
			//read(sfd, &fdsi, sizeof(fdsi));
			break;
		}
	}
}

static ssize_t stream2tap_read(void *opaque, void *buf, size_t count) {
	int *tapfd = opaque;
	return write(*tapfd, buf, count);
}

static void stream2tap(int streamfd[2], int tapfd) {
	int n;
	unsigned char buf[4096];
	struct pollfd pfd[] = {{tapfd, POLLIN, 0}, {streamfd[0], POLLIN, 0}, {-1, POLLIN, 0}};
	sigset_t chldmask;
	sigemptyset(&chldmask);
	sigaddset(&chldmask, SIGCHLD);
	int sfd = signalfd(-1, &chldmask, SFD_CLOEXEC);
	VDESTREAM *vdestream = vdestream_open(&tapfd, streamfd[1], stream2tap_read, NULL);
	pfd[2].fd = sfd;
	while (ppoll(pfd, 3, NULL, &chldmask) >= 0) {
		if (pfd[0].revents & POLLIN) {
			n = read(tapfd, buf, 4096);
			if (n == 0) break;
			vdestream_send(vdestream, buf, n);
		}
		if (pfd[1].revents & POLLIN) {
			n = read(streamfd[0], buf, 4096);
			if (n == 0) break;
			vdestream_recv(vdestream, buf, n);
		}
		if (pfd[2].revents & POLLIN) {
			//struct signalfd_siginfo fdsi;
			//read(sfd, &fdsi, sizeof(fdsi));
			break;
		}
	}
}

/* Start function for cloned child */
static int              childFunc(void *arg)
{
	struct child_args *args = (struct child_args *) arg;
	char ch;
	int tapfd;
	pid_t cmdpid;

	/* Wait until the parent has updated the UID and GID mappings. */
	if (read(args->pipe_fd[0], &ch, 1) != 0) {
		fprintf(stderr,
				"Failure in child: read from pipe returned != 0\n");
		exit(EXIT_FAILURE);
	}

	close(args->pipe_fd[0]);

	/* set the capability to allow net configuration */
	cap_value_t cap = CAP_NET_ADMIN;
	cap_t caps=cap_get_proc();
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap = CAP_NET_RAW;
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap = CAP_NET_BIND_SERVICE;
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap = CAP_NET_BROADCAST;
	cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_SET);
	cap_set_proc(caps);
	cap_free(caps);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_ADMIN, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_RAW, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BIND_SERVICE, 0, 0);
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_NET_BROADCAST, 0, 0);

	/* create a net interface in the new namespace*/

	switch (args->conntype) {
		case CONNTYPE_NONE:
			execvp(args->argv[0], args->argv);
			errExit("execvp");
			break;
		case CONNTYPE_VDE:
			if ((tapfd = open_tap(args->if_name)) < 0)
				errExit("tap");
			switch (cmdpid=fork()) {
				case 0:
					execvp(args->argv[0], args->argv);
					errExit("execvp");
					break;
				default:
					plug2tap(args->conn.vdeconn, tapfd);
					exit(EXIT_SUCCESS);
				case -1:
					errExit("cmd fork");
					break;
			}
			break;
		case CONNTYPE_VDESTREAM:
			if ((tapfd = open_tap(args->if_name)) < 0)
				errExit("tap");
			switch (cmdpid=fork()) {
				case 0:
					execvp(args->argv[0], args->argv);
					errExit("execvp");
					break;
				default:
					stream2tap(args->conn.streamfd, tapfd);
					exit(EXIT_SUCCESS);
				case -1:
					errExit("cmd fork");
					break;
			}
			break;
		default:
			errExit("unknown conn type");
	}
}

int argv1_help(char *s) {
	if (strcmp(s,"-h") == 0)
		return 1;
	if (strcmp(s,"--help") == 0)
		return 1;
	return 0;
}

int argv1_nonet(char *s) {
	if (s == NULL)
		return 1;
	if (strcmp(s,"") == 0)
		return 1;
	if (strcmp(s,"-") == 0)
		return 1;
	if (strcmp(s,"no") == 0)
		return 1;
	return 0;
}

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];    /* Space for child's stack */

int main(int argc, char *argv[])
{
	pid_t child_pid;
	struct child_args args;
	char *vdenet = NULL;
	char *argvsh[]={getenv("SHELL"),NULL};

	switch (argc) {
		case 1:
			args.argv = argvsh;
			break;
		case 2:
			if (argv1_help(argv[1]))
				usage_exit(basename(argv[0]));
		default:
			if (strcmp(argv[1], "-i") == 0 && argc > 3) {
				args.if_name = argv[2];
				vdenet = argv[3];
				args.argv = argc > 4 ? argv + 4 : argvsh;
			} else {
				args.if_name = DEFAULT_IF_NAME;
				vdenet = argv[1];
				args.argv = argc > 2 ? argv + 2 : argvsh;
			}
			break;
	}

	if (args.argv[0] == NULL) {
		fprintf(stderr, "Error: $SHELL env variable not set\n");
		exit(EXIT_FAILURE); 
	}

	if (vdenet == NULL || argv1_nonet(vdenet))
		args.conntype = CONNTYPE_NONE;
	else if (*vdenet == '=') {
		args.conntype = CONNTYPE_VDESTREAM;
		if (coprocsp(vdenet+1, args.conn.streamfd) < 0)
			errExit("stream cmd");
	} else {
		args.conntype = CONNTYPE_VDE;
		if ((args.conn.vdeconn = vde_open(vdenet, "vdens", NULL)) == NULL)
			errExit("vdeplug");
	}

	/* We use a pipe to synchronize the parent and child, in order to
		 ensure that the parent sets the UID and GID maps before the child
		 calls execve(). This ensures that the child maintains its
		 capabilities during the execve() in the common case where we
		 want to map the child's effective user ID to 0 in the new user
		 namespace. Without this synchronization, the child would lose
		 its capabilities if it performed an execve() with nonzero
		 user IDs (see the capabilities(7) man page for details of the
		 transformation of a process's capabilities during execve()). */

	if (pipe2(args.pipe_fd, O_CLOEXEC) == -1)
		errExit("pipe");
	
	/* Create the child in new namespace(s) */

	child_pid = clone(childFunc, child_stack + STACK_SIZE,
			CLONE_VM | CLONE_FILES | CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD, &args);
	if (child_pid == -1)
		errExit("clone");

	/* Parent falls through to here */

	uid_gid_map(child_pid);

	/* Close the write end of the pipe, to signal to the child that we
		 have updated the UID and GID maps */

	close(args.pipe_fd[1]);

	if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
		errExit("waitpid");

	exit(EXIT_SUCCESS);
}
