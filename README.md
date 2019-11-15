# vdens
Create User Namespaces connected to VDE networks.

vdens requires [vdeplug4](https://github.com/rd235/vdeplug4) (or [vde2](https://github.com/virtualsquare/vde-2) deprecated)

## Install vdens

Vdens uses cmake so a standard installation procedure is the following:
```
$ mkdir build
$ cd build
$ cmake ..
$ make
$ sudo make install
```

vdens requires user namespace to be included and enabled in the kernel of the hosting system.
Kernel config file must include the following option.
```
CONFIG_USER_NS=y
```

Debian users should enable user namespaces using the following command:
```
$ sudo echo 1 > /proc/sys/kernel/unprivileged_userns_clone
```

## Tutorial

Vdens can be used without any parameter:

```
$ vdens
$ # ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
```

In this way vdens creates a new network namespace providing only the loopback interface.
The new network namespace is created inside a user namespace so the user can be safely granted
all the capability nedded to autonomously manage their own network.

The caprint command (provided by the [cado](https://github.com/rd235/cado) command suite) can
reveal the capabilities granted to the user inside a vdens namespace.

```
$ caprint
cap_net_bind_service
cap_net_broadcast
cap_net_admin
cap_net_raw
```

Thus, for example, it is possible to create a tap interface connected to a vde\_switch (using *vdeplug4*)

```
$ vde_plug -d vde:// tap://vde0
$ ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 96:b4:71:c9:f6:f7 brd ff:ff:ff:ff:ff:ff
```

using *vde2* the first command is:
```
$ vde_plug2tap tap0 &
```

If required,
the command cadrop (also provided by  the [cado](https://github.com/rd235/cado) command suite).
permits to drop some or all the capabilities after the network configuration phase,
to provide higher security,

Vde\_plug services based on TCP-IP networking (like slirp, vxvde, vxvdex, vxlan, udp, etc.)
would not work if activated from inside the vdens namespace (the namespace providing access to
the real networking interfaces is not accessible from within the vdens).

Vdens can define a virtual interface during the activation of the namespace. The virtual
network interface is usually named vde0 unless elseway defined by the -i option (see the man page).
It is a virtual interface in the user private namespace, but the libvdeplug library (and its plugins)
use the networking services available outside the private namespace.

Note: the following example is for *vdeplug4*

```
$ vdens vxvde://
$ ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether ce:e6:4c:88:44:49 brd ff:ff:ff:ff:ff:ff
```

It is possible to run several instances of the command here above on several hosts of a LAN (multicast domain)
to create a network of namespaces.
All vdens namespaces connected to the same vxvde multicast address and vni (see libvdeplug\_vxvde(1)
man page) will create a vlan of namespaces.

In order to run a specific command in a vdens (instead of starting a shell session) just add the
command and its arguments at the end of the vdens command line.

```
$ vdens vxvde:// xterm
```

It is also possible to create vde namespaces connected to several networks using the flag `-m` or `--multi`:

vdeplug4:
```
$ vdens -m vde:// vxvde://
$ # ip addr
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: vde0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 6e:03:cd:c1:84:83 brd ff:ff:ff:ff:ff:ff
3: vde1: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 3e:39:0e:4e:52:c5 brd ff:ff:ff:ff:ff:ff
```

vde2:
```
$ vdens -m /var/run/sw1 /var/run/sw2
```
