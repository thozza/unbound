/*
 * daemon/unbound.c - main program for unbound DNS resolver daemon.
 *
 * Copyright (c) 2007, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

/**
 * \file
 *
 * Main program to start the DNS resolver daemon.
 */

#include "config.h"
#include "util/log.h"
#include "daemon/daemon.h"
#include "util/config_file.h"
#include "util/storage/slabhash.h"
#include "services/listen_dnsport.h"
#include "services/cache/rrset.h"
#include "services/cache/infra.h"
#include "util/data/msgreply.h"
#include "util/module.h"
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef USE_MINI_EVENT
#include "util/mini_event.h"
#else
#include <event.h>
#endif

/** global debug value to keep track of heap memory allocation */
void* unbound_start_brk = 0;

/** print usage. */
static void usage()
{
	printf("usage:  unbound [options]\n");
	printf("	start unbound daemon DNS resolver.\n");
	printf("-h	this help\n");
	printf("-c file	config file to read instead of %s\n", CONFIGFILE);
	printf("	file format is described in unbound.conf(5).\n");
	printf("-d	do not fork into the background.\n");
	printf("-v	verbose (more times to increase verbosity)\n");
	printf("Version %s\n", PACKAGE_VERSION);
	printf("libevent %s, libldns %s\n", 
		event_get_version(), ldns_version());
	printf("BSD licensed, see LICENSE in source package for details.\n");
	printf("Report bugs to %s\n", PACKAGE_BUGREPORT);
}

/** check file descriptor count */
static void
checkrlimits(struct config_file* cfg)
{
#ifdef HAVE_GETRLIMIT
	int list = ((cfg->do_ip4?1:0) + (cfg->do_ip6?1:0)) * 
		((cfg->do_udp?1:0) + (cfg->do_tcp?1 + 
			(int)cfg->incoming_num_tcp:0));
	size_t ifs = (size_t)(cfg->num_ifs==0?1:cfg->num_ifs);
	size_t listen_num = list*ifs;
	size_t outudpnum = (size_t)cfg->outgoing_num_ports;
	size_t outtcpnum = cfg->outgoing_num_tcp;
	size_t misc = 4; /* logfile, pidfile, stdout... */
	size_t perthread_noudp = listen_num + outtcpnum + 
		2/*cmdpipe*/ + 2/*libevent*/ + misc; 
	size_t perthread = perthread_noudp + outudpnum;

#if !defined(HAVE_PTHREAD) && !defined(HAVE_SOLARIS_THREADS)
	int numthread = 1; /* it forks */
#else
	int numthread = cfg->num_threads;
#endif
	size_t total = numthread * perthread + misc;
	size_t avail;
	struct rlimit rlim;

	if(getrlimit(RLIMIT_NOFILE, &rlim) < 0) {
		log_warn("getrlimit: %s", strerror(errno));
		return;
	}
	if(rlim.rlim_cur == (rlim_t)RLIM_INFINITY)
		return;
	if((size_t)rlim.rlim_cur < total) {
		avail = (size_t)rlim.rlim_cur;
		rlim.rlim_cur = (rlim_t)(total + 10);
		rlim.rlim_max = (rlim_t)(total + 10);
		if(setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
			log_warn("setrlimit: %s", strerror(errno));
			log_warn("cannot increase max open fds from %u to %u",
				(unsigned)avail, (unsigned)total+10);
			cfg->outgoing_num_ports = (int)((avail 
				- numthread*perthread_noudp 
				- 10 /* safety margin */) /numthread);
			log_warn("continuing with less udp ports: %u",
				cfg->outgoing_num_ports);
			log_warn("increase ulimit or decrease threads, ports in config to remove this warning");
			return;
		}
		log_warn("increased limit(open files) from %u to %u",
			(unsigned)avail, (unsigned)total+10);
	}
#else	
	(void)cfg;
#endif /* HAVE_GETRLIMIT */
}

/** set verbosity, check rlimits, cache settings */
static void
apply_settings(struct daemon* daemon, struct config_file* cfg, 
	int cmdline_verbose)
{
	/* apply if they have changed */
	daemon->cfg = cfg;
	verbosity = cmdline_verbose + cfg->verbosity;
	config_apply(cfg);
	if(!daemon->env->msg_cache ||
	   cfg->msg_cache_size != slabhash_get_size(daemon->env->msg_cache) ||
	   cfg->msg_cache_slabs != daemon->env->msg_cache->size) {
		slabhash_delete(daemon->env->msg_cache);
		daemon->env->msg_cache = slabhash_create(cfg->msg_cache_slabs, 
			HASH_DEFAULT_STARTARRAY, cfg->msg_cache_size, 
			msgreply_sizefunc, query_info_compare,
			query_entry_delete, reply_info_delete, NULL);
		if(!daemon->env->msg_cache) {
			fatal_exit("malloc failure updating config settings");
		}
	}
	if((daemon->env->rrset_cache = rrset_cache_adjust(
		daemon->env->rrset_cache, cfg, &daemon->superalloc)) == 0)
		fatal_exit("malloc failure updating config settings");
	if((daemon->env->infra_cache = infra_adjust(daemon->env->infra_cache, 
		cfg))==0)
		fatal_exit("malloc failure updating config settings");
	checkrlimits(cfg);
}

#ifdef HAVE_KILL
/** Read existing pid from pidfile. 
 * @param file: file name of pid file.
 * @return: the pid from the file or -1 if none.
 */
static pid_t
readpid (const char* file)
{
	int fd;
	pid_t pid;
	char pidbuf[32];
	char* t;
	ssize_t l;

	if ((fd = open(file, O_RDONLY)) == -1) {
		if(errno != ENOENT)
			log_err("Could not read pidfile %s: %s",
				file, strerror(errno));
		return -1;
	}

	if (((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
		if(errno != ENOENT)
			log_err("Could not read pidfile %s: %s",
				file, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	/* Empty pidfile means no pidfile... */
	if (l == 0) {
		return -1;
	}

	pidbuf[sizeof(pidbuf)-1] = 0;
	pid = (pid_t)strtol(pidbuf, &t, 10);
	
	if (*t && *t != '\n') {
		return -1;
	}
	return pid;
}

/** write pid to file. 
 * @param pidfile: file name of pid file.
 * @param pid: pid to write to file.
 */
static void
writepid (const char* pidfile, pid_t pid)
{
	FILE* f;

	if ((f = fopen(pidfile, "w")) ==  NULL ) {
		log_err("cannot open pidfile %s: %s", 
			pidfile, strerror(errno));
		return;
	}
	if(fprintf(f, "%lu\n", (unsigned long)pid) < 0) {
		log_err("cannot write to pidfile %s: %s", 
			pidfile, strerror(errno));
	}
	fclose(f);
}

/**
 * check old pid file.
 * @param cfg: the config settings
 */
static void
checkoldpid(struct config_file* cfg)
{
	pid_t old;
	char* file = cfg->pidfile;
	if(cfg->chrootdir && cfg->chrootdir[0] &&
		strncmp(file, cfg->chrootdir, strlen(cfg->chrootdir))==0) {
		file += strlen(cfg->chrootdir);
	}
	if((old = readpid(file)) != -1) {
		/* see if it is still alive */
		if(kill(old, 0) == 0 || errno == EPERM)
			log_warn("unbound is already running as pid %u.", 
				(unsigned)old);
		else	log_warn("did not exit gracefully last time (%u)", 
				(unsigned)old);
	}
}
#endif /* HAVE_KILL */

/** detach from command line */
static void
detach(struct config_file* cfg)
{
#ifdef HAVE_WORKING_FORK
	int fd;
	/* Take off... */
	switch (fork()) {
		case 0:
			break;
		case -1:
			unlink(cfg->pidfile);
			fatal_exit("fork failed: %s", strerror(errno));
		default:
			/* exit interactive session */
			exit(0);
	}
	/* detach */
#ifdef HAVE_SETSID
	if(setsid() == -1)
		fatal_exit("setsid() failed: %s", strerror(errno));
#endif
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close(fd);
	}
#else
	(void)cfg;
#endif /* HAVE_WORKING_FORK */
}

/** daemonize, drop user priviliges and chroot if needed */
static void
do_chroot(struct daemon* daemon, struct config_file* cfg, int debug_mode,
	char** cfgfile)
{
	uid_t uid;
	gid_t gid;
	/* initialize, but not to 0 (root) */
	memset(&uid, 112, sizeof(uid));
	memset(&gid, 112, sizeof(gid));
	log_assert(cfg);

	/* daemonize last to be able to print error to user */
#ifdef HAVE_GETPWNAM
	if(cfg->username && cfg->username[0]) {
		struct passwd *pwd;
		if((pwd = getpwnam(cfg->username)) == NULL)
			fatal_exit("user '%s' does not exist.", cfg->username);
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
		endpwent();
	}
#endif
#ifdef HAVE_CHROOT
	if(cfg->chrootdir && cfg->chrootdir[0]) {
		if(chdir(cfg->chrootdir)) {
			fatal_exit("unable to chdir to chroot %s: %s",
				cfg->chrootdir, strerror(errno));
		}
		verbose(VERB_QUERY, "chdir to %s", cfg->chrootdir);
		if(chroot(cfg->chrootdir))
			fatal_exit("unable to chroot to %s: %s", 
				cfg->chrootdir, strerror(errno));
		verbose(VERB_QUERY, "chroot to %s", cfg->chrootdir);
		if(strncmp(*cfgfile, cfg->chrootdir, 
			strlen(cfg->chrootdir)) == 0) 
			(*cfgfile) += strlen(cfg->chrootdir);
	}
#else
	(void)cfgfile;
#endif
	if(cfg->directory && cfg->directory[0]) {
		char* dir = cfg->directory;
		if(cfg->chrootdir && cfg->chrootdir[0] &&
			strncmp(dir, cfg->chrootdir, 
			strlen(cfg->chrootdir)) == 0)
			dir += strlen(cfg->chrootdir);
		if(dir[0]) {
			if(chdir(dir)) {
				fatal_exit("Could not chdir to %s: %s",
					dir, strerror(errno));
			}
			verbose(VERB_QUERY, "chdir to %s", dir);
		}
	}
#ifdef HAVE_GETPWNAM
	if(cfg->username && cfg->username[0]) {
		if(setgid(gid) != 0)
			fatal_exit("unable to set group id of %s: %s", 
				cfg->username, strerror(errno));
		if(setuid(uid) != 0)
			fatal_exit("unable to set user id of %s: %s", 
				cfg->username, strerror(errno));
		verbose(VERB_QUERY, "drop user privileges, run as %s", 
			cfg->username);
	}
#endif
#ifdef HAVE_KILL
	/* check old pid file before forking */
	if(cfg->pidfile && cfg->pidfile[0]) {
		checkoldpid(cfg);
	}
#endif

	/* init logfile just before fork */
	log_init(cfg->logfile, cfg->use_syslog, cfg->chrootdir);
	if(!debug_mode && cfg->do_daemonize) {
		detach(cfg);
	}
#ifdef HAVE_KILL
	if(cfg->pidfile && cfg->pidfile[0]) {
		char* pf = cfg->pidfile;
		if(cfg->chrootdir && cfg->chrootdir[0] &&
			strncmp(pf, cfg->chrootdir, strlen(cfg->chrootdir))==0)
			pf += strlen(cfg->chrootdir);
		writepid(pf, getpid());
		if(!(daemon->pidfile = strdup(pf)))
			log_err("pidf: malloc failed");
	}
#else
	(void)daemon;
#endif
}

/**
 * Run the daemon. 
 * @param cfgfile: the config file name.
 * @param cmdline_verbose: verbosity resulting from commandline -v.
 *    These increase verbosity as specified in the config file.
 * @param debug_mode: if set, do not daemonize.
 */
static void 
run_daemon(char* cfgfile, int cmdline_verbose, int debug_mode)
{
	struct config_file* cfg = NULL;
	struct daemon* daemon = NULL;
	int done_chroot = 0;

	if(!(daemon = daemon_init()))
		fatal_exit("alloc failure");
	while(!daemon->need_to_exit) {
		if(done_chroot)
			verbose(VERB_OPS, "Restart of %s.", PACKAGE_STRING);
		else	verbose(VERB_OPS, "Start of %s.", PACKAGE_STRING);

		/* config stuff */
		if(!(cfg = config_create()))
			fatal_exit("Could not alloc config defaults");
		if(!config_read(cfg, cfgfile)) {
			if(errno != ENOENT)
				fatal_exit("Could not read config file: %s",
					cfgfile);
			log_warn("Continuing with default config settings");
		}
		apply_settings(daemon, cfg, cmdline_verbose);
	
		/* prepare */
		if(!daemon_open_shared_ports(daemon))
			fatal_exit("could not open ports");
		if(!done_chroot) { 
			do_chroot(daemon, cfg, debug_mode, &cfgfile); 
			done_chroot = 1; 
		} else log_init(cfg->logfile, cfg->use_syslog, cfg->chrootdir);
		/* work */
		daemon_fork(daemon);

		/* clean up for restart */
		verbose(VERB_ALGO, "cleanup.");
		daemon_cleanup(daemon);
		config_delete(cfg);
	}
	verbose(VERB_ALGO, "Exit cleanup.");
	if(daemon->pidfile)
		unlink(daemon->pidfile);
	daemon_delete(daemon);
}

/** getopt global, in case header files fail to declare it. */
extern int optind;
/** getopt global, in case header files fail to declare it. */
extern char* optarg;

/**
 * main program. Set options given commandline arguments.
 * @param argc: number of commandline arguments.
 * @param argv: array of commandline arguments.
 * @return: exit status of the program.
 */
int 
main(int argc, char* argv[])
{
	int c;
	char* cfgfile = CONFIGFILE;
	int cmdline_verbose = 0;
	int debug_mode = 0;

#ifdef HAVE_SBRK
	/* take debug snapshot of heap */
	unbound_start_brk = sbrk(0);
#endif

	log_init(NULL, 0, NULL);
	/* parse the options */
	while( (c=getopt(argc, argv, "c:dhv")) != -1) {
		switch(c) {
		case 'c':
			cfgfile = optarg;
			break;
		case 'v':
			cmdline_verbose ++;
			verbosity++;
			break;
		case 'd':
			debug_mode = 1;
			break;
		case '?':
		case 'h':
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if(argc != 0) {
		usage();
		return 1;
	}

	run_daemon(cfgfile, cmdline_verbose, debug_mode);
	log_init(NULL, 0, NULL); /* close logfile */
	return 0;
}
