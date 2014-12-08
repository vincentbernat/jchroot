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
#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <mntent.h>
#include <sys/mount.h>

struct config {
  int   userns;
  int   netns;
  uid_t user;
  gid_t group;
  char *fstab;
  char *hostname;
  char *target;
  char *const *command;
};

const char *progname;
static void usage() {
  fprintf(stderr,
	  "Usage: %s [OPTIONS] TARGET [--] COMMAND\n"
	  "\n"
	  "Available options:\n"
          "  -U                         Use a new user namespace\n"
          "  -N                         Use a new network namespace\n"
	  "  -u USER  | --user=USER     Specify user to use after chroot\n"
	  "  -g USER  | --group=USER    Specify group to use after chroot\n"
	  "  -f FSTAB | --fstab=FSTAB   Specify a fstab(5) file\n"
	  "  -n NAME  | --hostname=NAME Specify a hostname\n",
	  progname);
  exit(EXIT_FAILURE);
}

/* Step 6: Execute command */
static int step6(struct config *config) {
  if (execvp(config->command[0], config->command) == -1) {
    int i = 1;
    fprintf(stderr, "unable to execute '%s", config->command[0]);
    while (config->command[i]) fprintf(stderr, " %s", config->command[i++]);
    fprintf(stderr, "': %m\n");
    return errno;
  }
  return 0; /* No real return... */
}

/* Step 5: Drop privileges */
static int step5(struct config *config) {
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
  return step6(config);
}

/* Step 4: Chroot */
static int step4(struct config *config) {
  if (chroot(config->target)) {
    fprintf(stderr, "unable to chroot to %s: %m\n", config->target);
    return EXIT_FAILURE;
  }
  if (chdir("/")) {
    fprintf(stderr, "unable to go into chroot: %m\n");
    return EXIT_FAILURE;
  }
  return step5(config);
}

/* Step 3: Set hostname */
static int step3(struct config *config) {
  if (config->hostname &&
      sethostname(config->hostname, strlen(config->hostname))) {
    fprintf(stderr, "unable to change hostname to '%s': %m\n",
	    config->hostname);
  }
  return step4(config);
}

struct mount_opt {
  char *name;
  int clear;
  int flag;
};

static struct mount_opt mount_opt[] = {
  { "defaults",   0, 0              },
  { "ro",         0, MS_RDONLY      },
  { "rw",         1, MS_RDONLY      },
  { "suid",       1, MS_NOSUID      },
  { "nosuid",     0, MS_NOSUID      },
  { "dev",        1, MS_NODEV       },
  { "nodev",      0, MS_NODEV       },
  { "exec",       1, MS_NOEXEC      },
  { "noexec",     0, MS_NOEXEC      },
  { "sync",       0, MS_SYNCHRONOUS },
  { "async",      1, MS_SYNCHRONOUS },
  { "atime",      1, MS_NOATIME     },
  { "noatime",    0, MS_NOATIME     },
  { "diratime",   1, MS_NODIRATIME  },
  { "nodiratime", 0, MS_NODIRATIME  },
  { "bind",       0, MS_BIND        },
  { NULL,         0, 0              },
};

/* Step 2: Mount anything needed */
static int step2(void *arg) {
  struct config *config = arg;
  if (config->fstab) {
    struct mntent *mntent;
    char path[256];
    FILE *file;

    file = setmntent(config->fstab, "r");
    if (!file) {
      fprintf(stderr, "unable to open '%s': %m\n", config->fstab);
      return EXIT_FAILURE;
    }

    while ((mntent = getmntent(file))) {
      /* We need to parse mnt_opts */
      unsigned long mntflags = 0;
      char *mntopts = strdup(mntent->mnt_opts);
      char *mntdata = malloc(strlen(mntent->mnt_opts) + 1);
      if (!mntdata || !mntopts) {
	fprintf(stderr, "unable to allocate memory\n");
	free(mntopts);
	free(mntdata);
	return EXIT_FAILURE;
      }
      *mntdata = 0;

      char *opt = NULL;
      struct mount_opt *mo;

      for (opt = strtok(mntopts, ","); opt != NULL;
	   opt = strtok(NULL, ",")) {
	/* Is `opt` a known option? */
	for (mo = &mount_opt[0];
	     mo->name != NULL; mo++) {
	  if (!strncmp(opt, mo->name, strlen(mo->name))) {
	    if (mo->clear)
	      mntflags &= ~mo->flag;
	    else
	      mntflags |= mo->flag;
	    break;
	  }
	}
	if (!mo->name) {
	  /* `opt` is not know, append it to `mntdata` */
	  if (strlen(mntdata)) strcat(mntdata, ",");
	  strcat(mntdata, opt);
	}
      }
      free(mntopts);

      /* Mount! */
      if (snprintf(path, sizeof(path), "%s%s",
		   config->target, mntent->mnt_dir) >= sizeof(path)) {
	fprintf(stderr, "path too long: %s\n", mntent->mnt_dir);
	free(mntdata);
	return EXIT_FAILURE;
      }
      if ((mount(mntent->mnt_fsname, path, mntent->mnt_type,
		 mntflags & ~MS_REMOUNT, mntdata)) ||
	  /* With MS_BIND, we need to remount to enable some options like "ro" */
	  (((mntflags & MS_REMOUNT) || (mntflags & MS_BIND)) &&
	   (mount(mntent->mnt_fsname, path, mntent->mnt_type,
		  mntflags | MS_REMOUNT, mntdata)))) {
	fprintf(stderr, "unable to mount '%s' on '%s': %m\n",
		mntent->mnt_fsname, mntent->mnt_dir);
	free(mntdata);
	return EXIT_FAILURE;
      }
      free(mntdata);
    }
  }
  return step3(config);
}

/* Step 1: create a new PID/IPC/NS/UTS namespace */
static int step1(struct config *config) {
  int ret;
  pid_t pid;

  long stack_size = sysconf(_SC_PAGESIZE);
  void *stack = alloca(stack_size) + stack_size;
  int flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS;

  if (config->hostname) flags |= CLONE_NEWUTS;
  if (config->userns) flags |= CLONE_NEWUSER;
  if (config->netns) flags |= CLONE_NEWNET;
  pid = clone(step2,
	      stack,
	      SIGCHLD | flags | CLONE_FILES,
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
  progname = argv[0];

  int c;
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {
      { "user",     required_argument, 0, 'u' },
      { "group",    required_argument, 0, 'g' },
      { "fstab",    required_argument, 0, 'f' },
      { "hostname", required_argument, 0, 'n' },
      { "help",     no_argument,       0, 'h' },
      { 0,          0,                 0, 0   }
    };

    c = getopt_long(argc, argv, "hNUu:g:f:n:",
		    long_options, &option_index);
    if (c == -1) break;

    switch (c) {
    case 'U':
      config.userns = 1;
      break;
    case 'N':
      config.netns = 1;
      break;
    case 'u':
      if (!optarg) usage();

      struct passwd *passwd;
      passwd = getpwnam(optarg);
      if (!passwd) {
	config.user = strtoul(optarg, NULL, 10);
	if (errno) {
	  fprintf(stderr, "'%s' is not a valid user\n", optarg);
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
	  fprintf(stderr, "'%s' is not a valid group\n", optarg);
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
    case 'n':
      if (!optarg) usage();
      config.hostname = optarg;
      break;
    default:
      usage();
    }
  }

  if (optind == argc) usage();
  config.target = argv[optind++];
  if (optind == argc) usage();
  config.command = argv + optind;

  struct stat st;
  if (stat(config.target, &st) || !S_ISDIR(st.st_mode)) {
    fprintf(stderr, "'%s' is not a directory\n", config.target);
    return EXIT_FAILURE;
  }
  
  return step1(&config);
}
