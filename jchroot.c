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
#define _DEFAULT_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <alloca.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <mntent.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

struct config {
  int   pipe_fd[2];
  int   userns;
  int   netns;
  uid_t user;
  gid_t group;
  char *fstab;
  char *hostname;
  char *target;
  char *const *command;
  const char *uid_map;
  const char *gid_map;
  const char *pid_file;
  const char *chdir_to;
};

const char *progname;
static void usage() {
  fprintf(stderr,
	  "Usage: %s [OPTIONS] TARGET [--] COMMAND\n"
	  "\n"
	  "Available options:\n"
	  "  -U       | --new-user-ns     Use a new user namespace\n"
	  "  -N       | --new-network-ns  Use a new network namespace\n"
	  "  -u USER  | --user=USER       Specify user to use after chroot\n"
	  "  -g USER  | --group=USER      Specify group to use after chroot\n"
	  "  -f FSTAB | --fstab=FSTAB     Specify a fstab(5) file\n"
	  "  -n NAME  | --hostname=NAME   Specify a hostname\n"
	  "  -M MAP   | --uid-map=MAP     Comma-separated list of UID mappings\n"
	  "  -G MAP   | --gid-map=MAP     Comma-separated list of GID mappings\n"
	  "  -p FILE  | --pidfile=FILE    Write PID of child process to file\n"
	  "  -e N=V   | --env=NAME=VALUE  Set an environment variable\n"
	  "  -c DIR   | --chdir=DIR       Change directory inside the chroot\n",
	  progname);
  exit(EXIT_FAILURE);
}

/* Step 7: Execute command */
static int step7(struct config *config) {
  if (config->chdir_to != NULL && chdir(config->chdir_to)) {
    fprintf(stderr, "unable to change directory: %m\n");
    return EXIT_FAILURE;
  }
  if (execvp(config->command[0], config->command) == -1) {
    int i = 1;
    fprintf(stderr, "unable to execute '%s", config->command[0]);
    while (config->command[i]) fprintf(stderr, " %s", config->command[i++]);
    fprintf(stderr, "': %m\n");
    return errno;
  }
  return 0; /* No real return... */
}

/* Step 6: Drop (or increase) privileges */
static int step6(struct config *config) {
  if (config->group != (gid_t) -1 && setgid(config->group)) {
    fprintf(stderr, "unable to change to GID %d: %m\n", config->group);
    return EXIT_FAILURE;
  }
  if (setgroups(0, NULL)) {
    /* This may fail on some recent kernels. See
     * https://lwn.net/Articles/626665/ for the rationale. */
    if (!config->userns) {
      fprintf(stderr, "unable to drop additional groups: %m\n");
      return EXIT_FAILURE;
    }
  }
  if (config->user != (uid_t) -1 && setuid(config->user)) {
    fprintf(stderr, "unable to change to UID %d: %m\n", config->user);
    return EXIT_FAILURE;
  }
  #ifdef PR_SET_NO_NEW_PRIVS
  if (config->group != (gid_t) -1 || config->user != (uid_t) -1) {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
  }
  #endif
  return step7(config);
}

/* Step 5: Chroot with pivot_root */
static int step5(struct config *config) {
  char *template = NULL;
  char *p = NULL;
  if (mount("", "/", "", MS_PRIVATE | MS_REC, "") == -1) {
    fprintf(stderr, "unable to make current root private: %m\n");
    return EXIT_FAILURE;
  }
  if (mount(config->target, config->target, "bind", MS_BIND|MS_REC, "") == -1) {
    fprintf(stderr, "unable to turn new root into mountpoint: %m\n");
    return EXIT_FAILURE;
  }
  if (asprintf(&template, "%s/tmp/.pivotrootXXXXXX", config->target) == -1) {
    fprintf(stderr, "unable to allocate template directory: %m\n");
    return EXIT_FAILURE;
  }
  if (mkdtemp(template) == NULL) {
    fprintf(stderr, "unable to create temporary directory for pivot root: %m\n");
    free(template);
    return EXIT_FAILURE;
  }
  if (syscall(__NR_pivot_root, config->target, template) == -1) {
    fprintf(stderr, "unable to pivot root to %s: %m\n", config->target);
    rmdir(template);
    free(template);
    return EXIT_FAILURE;
  }
  if (chdir("/")) {
    fprintf(stderr, "unable to go into chroot: %m\n");
    /* We should cleanup the mount and the temporary directory, but we
     * have pivoted and we won't are likely to still use the old
     * mount... */
    free(template);
    return EXIT_FAILURE;
  }
  p = template;
  p += strlen(config->target);
  if (umount2(p, MNT_DETACH) == -1) {
    fprintf(stderr, "unable to umount old root: %m\n");
    /* Again, cannot really clean... */
    free(template);
    return EXIT_FAILURE;
  }
  if (rmdir(p) == -1) {
    fprintf(stderr, "unable to remove directory for old root: %m\n");
    /* ... */
    free(template);
    return EXIT_FAILURE;
  }
  return step6(config);
}

/* Step 4: Set hostname */
static int step4(struct config *config) {
  if (config->hostname &&
      sethostname(config->hostname, strlen(config->hostname))) {
    fprintf(stderr, "unable to change hostname to '%s': %m\n",
	    config->hostname);
  }
  return step5(config);
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

/* Step 3: Mount anything needed */
static int step3(void *arg) {
  struct config *config = arg;

  /* First, wait for the parent to be ready */
  char ch;
  if (read(config->pipe_fd[0], &ch, 1) != 0) {
    fprintf(stderr, "unable to synchronize with parent: %m\n");
    return EXIT_FAILURE;
  }

  close(config->pipe_fd[0]);
  /* Make sure we have no handles shared with parent anymore,
   * these might be used to break out of the chroot */
  unshare(CLONE_FILES);

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
  return step4(config);
}

static void step2_update_map(const char *map, char *map_file) {
  int fd, j;
  ssize_t map_len;
  char *mapping = strdup(map);

  map_len = strlen(mapping);
  for (j = 0; j < map_len; j++)
    if (mapping[j] == ',')
      mapping[j] = '\n';

  fd = open(map_file, O_RDWR);
  if (fd == -1) {
    fprintf(stderr, "unable to open %s: %m\n", map_file);
    exit(EXIT_FAILURE);
  }

  if (write(fd, mapping, map_len) != map_len) {
    fprintf(stderr, "unable to write to %s: %m\n", map_file);
    exit(EXIT_FAILURE);
  }

  close(fd);
  free(mapping);
}

/* Step 2: setup user mappings */
static void step2(struct config *config, pid_t pid) {
  char map_path[PATH_MAX];
  if (config->uid_map != NULL) {
    snprintf(map_path, PATH_MAX, "/proc/%ld/uid_map", (long) pid);
    step2_update_map(config->uid_map, map_path);
  }
  if (config->gid_map != NULL) {
    snprintf(map_path, PATH_MAX, "/proc/%ld/gid_map", (long) pid);
    step2_update_map(config->gid_map, map_path);
  }
  close(config->pipe_fd[1]);     /* Sync with child */
}

/* Step 1: create a new PID/IPC/NS/UTS namespace */
static int step1(struct config *config) {
  int ret;
  pid_t pid;

  long stack_size = sysconf(_SC_PAGESIZE);
  void *stack = alloca(stack_size) + stack_size;
  int flags = CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNS;

  if (pipe(config->pipe_fd) == -1) {
    fprintf(stderr, "failed to create a pipe: %m\n");
    return EXIT_FAILURE;
  }

  FILE *pid_file;

  if (config->pid_file) {
    pid_file = fopen(config->pid_file, "w");
    if (pid_file == NULL) {
      fprintf(stderr, "failed to open pid file %s for writing: %m\n",
	      config->pid_file);
      return EXIT_FAILURE;
    }
  }

  if (config->hostname) flags |= CLONE_NEWUTS;
  if (config->userns) flags |= CLONE_NEWUSER;
  if (config->netns) flags |= CLONE_NEWNET;
  pid = clone(step3,
	      stack,
	      SIGCHLD | flags | CLONE_FILES,
	      config);
  if (pid < 0) {
    fprintf(stderr, "failed to clone: %m\n");
    if (config->pid_file) fclose(pid_file);
    return EXIT_FAILURE;
  }

  if (config->pid_file) {
    if (fprintf(pid_file, "%u", pid) < 0) {
      fprintf(stderr, "failed to write PID (%u) to file %s: %m\n",
	      pid, config->pid_file);
      fclose(pid_file);
      return EXIT_FAILURE;
    }
    fclose(pid_file);
  }

  step2(config, pid);

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
      { "new-user-ns",    no_argument,       0, 'U' },
      { "new-network-ns", no_argument,       0, 'N' },
      { "user",           required_argument, 0, 'u' },
      { "group",          required_argument, 0, 'g' },
      { "fstab",          required_argument, 0, 'f' },
      { "hostname",       required_argument, 0, 'n' },
      { "uid-map",        required_argument, 0, 'M' },
      { "gid-map",        required_argument, 0, 'G' },
      { "pidfile",        required_argument, 0, 'p' },
      { "env",            required_argument, 0, 'e' },
      { "chdir",          required_argument, 0, 'c' },
      { "help",           no_argument,       0, 'h' },
      { 0,                0,                 0, 0   }
    };

    c = getopt_long(argc, argv, "hNUu:g:f:n:M:G:p:e:c:",
		    long_options, &option_index);
    if (c == -1) break;

    switch (c) {
    case 'U':
      config.userns = 1;
      break;
    case 'M':
      config.uid_map = optarg;
      break;
    case 'G':
      config.gid_map = optarg;
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
    case 'e':
      if (!optarg) usage();
      if (putenv(optarg) != 0) {
	fprintf(stderr, "failed to set environment variable: %s\n", optarg);
	usage();
      }
      break;
    case 'c':
      if (!optarg) usage();
      config.chdir_to = optarg;
      break;
    case 'p':
      if (!optarg) usage();
      config.pid_file = optarg;
      break;
    default:
      usage();
    }
  }

  if (!config.userns &&
      (config.uid_map != NULL || config.gid_map != NULL)) {
    fprintf(stderr, "cannot use UID/GID mapping without a user namespace\n");
    usage();
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
