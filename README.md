jchroot: a chroot with more isolation
=====================================

Recent Linux kernels are now able to provide a new PID namespace to a
newly created process. The process becomes PID 1 in its own namespace
and all processes created in this namespace will be killed when the
first process terminates. This allows to reliably kill any process
started by the first process, even when they double fork. It also
ensures a better isolation.

The same applies for mount points and IPC. If you combine those three
namespaces with a standard chroot, you get a chroot on steroids. You
can launch any (non malicious) process in this chroot, it won't
interfere with your main system and everybody will be killed when you
exit the shell. Any filesystem that was mounted will also be unmounted
automatically.

This is what jchroot does:

 0. Setup user/group mappings.
 1. provide a new PID/IPC/mount/UTS namespace
 2. mount anything you want
 3. set hostname if needed
 4. chroot to your target
 5. drop privileges if needed
 6. execute your command
 
After your command has been executed, any process started by the
execution of this command will be killed, any IPC will be freed, any
mount point will be unmounted. All clean!
 
See also [schroot][1] and [lxc][2]. `schroot` is not yet able to do
this, but this is planned. See [bug #637870][3]. `lxc` should be able
to do this but seems targeted at more complex situations... If you use
systemd, look at `nspawn` or `systemd-nspawn` which does almost the
same thing than jchroot. You could also use `unshare` (with `chroot`)
from `util-linux` package.
 
[1]: http://packages.qa.debian.org/s/schroot.html
[2]: http://lxc.sourceforge.net/
[3]: http://bugs.debian.org/637870

Security note
-------------

It should be noted that a privileged process inside jchroot may be
able to escape unless its privileges are reduced. For example, it
could fiddle with `/dev/kmem` or mount any filesystem after creating
the appropriate node.

If you seek a complex isolation, you are better off with [lxc][2]
which bundles many security mechanisms.

You may want to use user namespaces to increase the security of the
chroot:

    ./jchroot -U -u 0 -g 0 -M "0 $(id -u) 1" -G "0 $(id -g) 1" /path/to/chroot cmd

Installation & use
------------------
 
Just use `make` to get `jchroot`. Then `jchroot --help` to get help.

Related projects
----------------

[ChrootX](https://github.com/Spiritdude/ChrootX) is a wrapper around
`chroot`/`jchroot`.
