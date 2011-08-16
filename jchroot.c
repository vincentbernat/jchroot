/*
 * Copyright (c) 2011 Vincent Bernat <bernat@luffy.cx>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE
#define _BSD_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <alloca.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <mntent.h>
#include <sys/mount.h>

struct config {
  uid_t user;
  gid_t group;
  char *fstab;
  char *target;
  char *const *command;
};

static void usage() {
  fprintf(stderr,
	  "Usage: jchroot [OPTIONS] TARGET [--] COMMAND\n"
	  "\n"
	  "Available options:\n"
	  "  -u USER | --user=USER     Specify user to use after chroot\n"
	  "  -g USER | --group=USER    Specify group to use after chroot\n"
	  "  -f FSTAB | --fstab=FSTAB  Specify a fstab(5) file\n"
	  );
  exit(EXIT_FAILURE);
}

/* Step 5: Execute command */
static int step5(struct config *config) {
  if (execvp(config->command[0], config->command) == -1) {
    int i = 1;
    fprintf(stderr, "unable to execute '%s", config->command[0]);
    while (config->command[i]) fprintf(stderr, " %s", config->command[i++]);
    fprintf(stderr, "': %m\n");
    return errno;
  }
  return 0; /* No real return... */
}

/* Step 4: Drop privileges */
static int step4(struct config *config) {
  if (config->group != (gid_t) -1 && setgid(config->group)) {
    fprintf(stderr, "unable to change to GID %d: %m\n", config->group);
    return EXIT_FAILURE;
  }
  if (setgroups(0, NULL)) {
    fprintf(stderr, "unable to drop additional groups: %m\n");
    return EXIT_FAILURE;
  }
  if (config->user != (uid_t) -1 && setuid(config->user)) {
    fprintf(stderr, "unable to change to UID %d: %m\n", config->user);
    return EXIT_FAILURE;
  }
  return step5(config);
}

/* Step 3: Chroot */
static int step3(struct config *config) {
  if (chroot(config->target)) {
    fprintf(stderr, "unable to chroot to %s: %m\n", config->target);
    return EXIT_FAILURE;
  }
  if (chdir("/")) {
    fprintf(stderr, "unable to go into chroot: %m\n");
    return EXIT_FAILURE;
  }
  return step4(config);
}

/* Step 2: Mount anything needed */
static int step2(void *arg) {
  struct config *config = arg;
  /* TODO: parse provided fstab and mount content */
  return step3(config);
}

/* Step 1: create a new PID/IPC/NS namespace */
static int step1(struct config *config) {
  int ret;
  pid_t pid;

  long stack_size = sysconf(_SC_PAGESIZE);
  void *stack = alloca(stack_size) + stack_size;

  pid = clone(step2,
	      stack,
	      SIGCHLD |
	      CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS,
	      config);
  if (pid < 0) {
    fprintf(stderr, "failed to clone: %m\n");
    return EXIT_FAILURE;
  }

  while (waitpid(pid, &ret, 0) < 0 && errno == EINTR)
    continue;
  return WIFEXITED(ret)?WEXITSTATUS(ret):EXIT_FAILURE;
}

int main(int argc, char * argv[]) {
  struct config config;
  memset(&config, 0, sizeof(struct config));
  config.user = config.group = -1;

  int c;
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      { "user",  required_argument, 0, 'u' },
      { "group", required_argument, 0, 'g' },
      { "fstab", required_argument, 0, 'f' },
      { "help",  no_argument,       0, 'h' },
      { 0,       0,                 0, 0   }
    };

    c = getopt_long(argc, argv, "u:g:f:",
		    long_options, &option_index);
    if (c == -1) break;

    switch (c) {
    case 'h':
      usage();
      break;
    case 'u':
      if (!optarg) usage();

      struct passwd *passwd;
      passwd = getpwnam(optarg);
      if (!passwd) {
	config.user = strtoul(optarg, NULL, 10);
	if (errno) {
	  fprintf(stderr, "'%s' is not a valid user", optarg);
	  usage();
	}
      } else {
	config.user = passwd->pw_uid;
	if (config.group == (gid_t) -1)
	  config.group = passwd->pw_gid;
      }
      break;
    case 'g':
      if (!optarg) usage();

      struct group *group;
      group = getgrnam(optarg);
      if (!group) {
	config.group = strtoul(optarg, NULL, 10);
	if (errno) {
	  fprintf(stderr, "'%s' is not a valid group", optarg);
	  usage();
	}
      } else {
	config.group = group->gr_gid;
      }
      break;
    case 'f':
      if (!optarg) usage();
      config.fstab = optarg;
      break;
    }
  }

  if (optind == argc) usage();
  config.target = argv[optind++];
  if (optind == argc) usage();
  config.command = argv + optind;
  
  exit(step1(&config));
}
