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
#include <sys/mount.h>
#include <sys/stat.h>
#include <execs.h>
#include <getopt.h>

#define DEFAULT_IF_NAME "vde0"
#define errExit(msg)    ({ perror(msg); exit(EXIT_FAILURE); })

#define CONNTYPE_NONE 0
#define CONNTYPE_VDE 1
#define CONNTYPE_VDESTREAM 2

int conntype;
union {
	VDECONN *vdeconn;
	int streamfd[2];
} conn;
char *resolvaddr;
char *resolvconf;
char *if_name = DEFAULT_IF_NAME;
char **cmdargv;
int sysadm_flag;

void vdens_core(void);

static void usage_exit(char *pname)
{
	fprintf(stderr, 
			"Usage: %s OPTIONS  [vde_net [cmd [arg...]]]\n"
			"OPTIONS:\n"
			"  -h | --help   print this short usage message\n"
			"  -i | --iface intname\n"
			"                 defines the interface name, the default value is \"vde0\"\n"
			"  -r | --resolvconf file\n"
			"                 defines the /etc/resolv.conf file, e.g. -r /tmp/resolv.conf\n"
			"  -R | --resolvaddr string\n"
			"                 defines the address of the DNS servers, e.g. -R 80.80.80.80\n"
			"  -s | --sysadm  enable the cap_sys_admin ambient capability\n"
			"  -c | --clone   use clone instead of unshare:\n"
			"                 %s uses one more process\n"
			"                 (default bevavior: try unshare and use clone if unshare fails)\n"
			"  -u | --unshare use unshare instead of clone:\n"
			"                 %s saves 1 process (for non-multithreaded vde plugins only)\n"
			"  no virtual interface if vde_net omitted or \"no\"\n"
			"  it runs $SHELL if cmd omitted\n\n" , pname, pname);
	exit(EXIT_FAILURE);
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

static void setambientcaps(cap_value_t *caplist) {
	cap_t caps=cap_get_proc();
	cap_value_t *cap;
	for (cap = caplist; *cap >= 0; cap++) 
		cap_set_flag(caps, CAP_INHERITABLE, 1, cap, CAP_SET);
	cap_set_proc(caps);
	cap_free(caps);
	for (cap = caplist; *cap >= 0; cap++) 
		prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, *cap, 0, 0);
}

static cap_value_t vdecaps[] = {CAP_SYS_ADMIN, CAP_NET_ADMIN, CAP_NET_RAW, CAP_NET_BIND_SERVICE, CAP_NET_BROADCAST, -1};

static void setvdenscap(int sysadm) {
	setambientcaps(vdecaps + (sysadm ? 0 : 1));
}

static int unsharenet(int sysadm, int clonens) {
	int pipe_fd[2];
	pid_t child_pid;
	int unshare_rv;
	if (pipe2(pipe_fd, O_CLOEXEC) == -1)
		errExit("pipe");
	switch (child_pid = fork()) {
		case 0:
			close(pipe_fd[1]);
			read(pipe_fd[0], &unshare_rv, sizeof(unshare_rv));
			if (unshare_rv == 0)
				uid_gid_map(getppid());
			exit(0);
		default:
			close(pipe_fd[0]);
			unshare_rv = unshare(CLONE_NEWUSER | CLONE_NEWNET | ((clonens) ? CLONE_NEWNS : 0));
			write(pipe_fd[1], &unshare_rv, sizeof(unshare_rv));
			close(pipe_fd[1]);
			if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
				errExit("waitpid");
			break;
		case -1:
			errExit("unshare fork");
	}
	return unshare_rv;
}

#define STACK_SIZE (64 * 1024)

static int childFunc(void *arg)
{
	int *pipe_fd = arg;
	char buf[1];

	/* Wait until the parent has updated the UID and GID mappings. */
  if (read(pipe_fd[0], buf, 1) != 0)
		errExit("Failure in child: read from pipe returned != 0");
	close(pipe_fd[0]);
	vdens_core();
}

static void clonenet(int sysadm, int clonens) {
	char child_stack[STACK_SIZE];
  int pipe_fd[2];
	pid_t child_pid;
  if (pipe2(pipe_fd, O_CLOEXEC) == -1)
    errExit("pipe");
	child_pid = clone(childFunc, child_stack + STACK_SIZE,
      CLONE_VM | CLONE_FILES | CLONE_NEWUSER | CLONE_NEWNET | SIGCHLD |
			((clonens) ? CLONE_NEWNS : 0), pipe_fd);
  if (child_pid == -1)
    errExit("clone");
  /* Parent falls through to here */
  uid_gid_map(child_pid);
	/* Close the write end of the pipe, to signal to the child that we
		 have updated the UID and GID maps */
  close(pipe_fd[1]);
  if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
    errExit("waitpid");
  exit(EXIT_SUCCESS);
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

static void plug2tap(VDECONN *conn, int tapfd) {
	int n;
	char buf[VDE_ETHBUFSIZE];
	struct pollfd pfd[] = {{tapfd, POLLIN, 0}, {vde_datafd(conn), POLLIN, 0}, {-1, POLLIN, 0}};
	sigset_t chldmask;
	sigemptyset(&chldmask);
	sigaddset(&chldmask, SIGCHLD);
	int sfd = signalfd(-1, &chldmask, SFD_CLOEXEC);
	pfd[2].fd = sfd;
	while (ppoll(pfd, 3, NULL, &chldmask) >= 0) {
		if (pfd[0].revents & POLLIN) {
			n = read(tapfd, buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vde_send(conn, buf, n, 0);
		}
		if (pfd[1].revents & POLLIN) {
			n = vde_recv(conn, buf, VDE_ETHBUFSIZE, 0);
			if (n == 0) break;
			write(tapfd, buf, n);
		}
		if (pfd[2].revents & POLLIN) {
			//struct signalfd_siginfo fdsi;
			//read(sfd, &fdsi, sizeof(fdsi));
			break;
		}
	}
	vde_close(conn);
}

static ssize_t stream2tap_read(void *opaque, void *buf, size_t count) {
	int *tapfd = opaque;
	return write(*tapfd, buf, count);
}

static void stream2tap(int streamfd[2], int tapfd) {
	int n;
	unsigned char buf[VDE_ETHBUFSIZE];
	struct pollfd pfd[] = {{tapfd, POLLIN, 0}, {streamfd[0], POLLIN, 0}, {-1, POLLIN, 0}};
	sigset_t chldmask;
	sigemptyset(&chldmask);
	sigaddset(&chldmask, SIGCHLD);
	int sfd = signalfd(-1, &chldmask, SFD_CLOEXEC);
	VDESTREAM *vdestream = vdestream_open(&tapfd, streamfd[1], stream2tap_read, NULL);
	pfd[2].fd = sfd;
	while (ppoll(pfd, 3, NULL, &chldmask) >= 0) {
		if (pfd[0].revents & POLLIN) {
			n = read(tapfd, buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vdestream_send(vdestream, buf, n);
		}
		if (pfd[1].revents & POLLIN) {
			n = read(streamfd[0], buf, VDE_ETHBUFSIZE);
			if (n == 0) break;
			vdestream_recv(vdestream, buf, n);
		}
		if (pfd[2].revents & POLLIN) {
			break;
		}
	}
}

int mountaddr(const char *addr) {
	char tmpname[] = "/tmp/vdensmountXXXXXX";
	int fd = mkstemp(tmpname);
	int retval;
	const char *tagbegin, *tagend;
	if (fd < 0)
		return -1;
	fchmod(fd, 0600);
	for (tagbegin = addr; *tagbegin != 0; tagbegin = tagend) {
		char *line;
		size_t len;
		for (tagend = tagbegin; *tagend != 0 && *tagend != ','; tagend++)
			;
		len = tagend-tagbegin;
		while (*tagend == ',')
			tagend++;
		asprintf(&line, "nameserver %*.*s\n", len, len, tagbegin);
		write(fd, line, strlen(line));
		free(line);
	}
	fchmod(fd, 0400);
	close(fd);
	retval = mount(tmpname, "/etc/resolv.conf",  "", MS_BIND, NULL);
	unlink(tmpname);
	return retval;
}

void vdens_core(void) {
	int tapfd;
	pid_t child_pid;

	setvdenscap(sysadm_flag);
	if (resolvaddr) {
		if (mountaddr(resolvaddr) < 0)
			errExit("resolvaddr mount");
	} else
		if (resolvconf && mount(resolvconf, "/etc/resolv.conf", "", MS_BIND, NULL) < 0)
			errExit("resolvconf mount");

	switch (conntype) {
		case CONNTYPE_NONE:
			execvp(cmdargv[0], cmdargv);
			errExit("execvp");
			break;
		case CONNTYPE_VDE:
			if ((tapfd = open_tap(if_name)) < 0)
				errExit("tap");
			switch (child_pid = fork()) {
				case 0:
					execvp(cmdargv[0], cmdargv);
					errExit("execvp");
					break;
				default:
					plug2tap(conn.vdeconn, tapfd);
					exit(EXIT_SUCCESS);
				case -1:
					errExit("cmd fork");
					break;
			}
			break;
		case CONNTYPE_VDESTREAM:
			if ((tapfd = open_tap(if_name)) < 0)
				errExit("tap");
			switch (child_pid = fork()) {
				case 0:
					execvp(cmdargv[0], cmdargv);
					errExit("execvp");
					break;
				default:
					stream2tap(conn.streamfd, tapfd);
					exit(EXIT_SUCCESS);
				case -1:
					errExit("cmd fork");
					break;
			}
			break;
		default:
			errExit("unknown conn type");
	}

	exit(EXIT_SUCCESS);
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

int main(int argc, char *argv[])
{
	char *argvsh[] = {getenv("SHELL"),NULL};
	char *vdenet = NULL;
	static char *short_options = "+i:hsucr:R:";
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"iface", required_argument, 0, 'i'},
		{"sysadm", no_argument, 0, 's'},
		{"unshare", no_argument, 0, 'u'},
		{"clone", no_argument, 0, 'c'},
		{"resolvconf", required_argument, 0, 'r'},
		{"resolvaddr", required_argument, 0, 'R'},
		{0, 0, 0, 0}};
	char *progname = basename(argv[0]);
	int unshare_flag = 0;
	int clone_flag = 0;
	int clonens_flag;

	resolvconf = getenv("VDE_RESOLVCONF");
	resolvaddr = getenv("VDE_RESOLVADDR");

	while (1) {
		int c;
		if ((c = getopt_long(argc, argv, short_options, long_options, NULL)) == -1)
			break;
		switch (c) {
			case 'i': 
				if_name = optarg;
				break;
			case 'r':
				resolvconf = optarg;
				break;
			case 'R':
				resolvaddr = optarg;
				break;
			case 's':
				sysadm_flag = 1;
				break;
			case 'u':
				unshare_flag = 1;
				break;
			case 'c':
				clone_flag = 1;
				break;
			case '?':
			case 'h':
			default: usage_exit(progname);
		}
	}
	argc -= optind;
	argv += optind;

	switch (argc) {
		case 0:
			cmdargv = argvsh;
			break;
		case 1:
			cmdargv = argvsh;
			vdenet = argv[0];
			break;
		default:
			cmdargv = argv + 1;
			vdenet = argv[0];
			break;
	}

	if (cmdargv[0] == NULL) {
		fprintf(stderr, "Error: $SHELL env variable not set\n");
		exit(EXIT_FAILURE); 
	}

	if (vdenet == NULL || argv1_nonet(vdenet))
		conntype = CONNTYPE_NONE;
	else if (*vdenet == '=') {
		conntype = CONNTYPE_VDESTREAM;
		if (coprocsp(vdenet+1, conn.streamfd) < 0)
			errExit("stream cmd");
	} else {
		conntype = CONNTYPE_VDE;
		if ((conn.vdeconn = vde_open(vdenet, "vdens", NULL)) == NULL)
			errExit("vdeplug");
	}

	clonens_flag = sysadm_flag | (resolvconf != NULL) | (resolvaddr != NULL);
	if (clone_flag) 
		clonenet(sysadm_flag, clonens_flag);
	else {
		if (unsharenet(sysadm_flag, clonens_flag) == 0)
			vdens_core();
		else {
			if (unshare_flag)
				errExit("unshare");
			else
				clonenet(sysadm_flag, clonens_flag);
		}
	}
}
