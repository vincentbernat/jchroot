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
 1. provide a new PID namespace
 2. provide a new IPC namespace
 3. provide a new mount namespace
 4. mount anything you want
 5. chroot to your target
 6. drop privileges if needed
 7. execute your command
 
 After your command has been executed, any process started by the
 execution of this command will be killed, any IPC will be freed, any
 mount point will be unmounted. All clean!
 
 See also [schroot][1] and [lxc][2]. `schroot` is not yet able to do
 this, but this is planned. See [bug #637870][3]. `lxc` should be able
 to do this but seems targeted at more complex situations...
 
 Installation & use
 ------------------
 
 Just use `make` to get `jchroot`. Then `jchroot --help` to get help.
 
