PANCTL(1) - General Commands Manual

# NAME

**panctl** - Control the Matrix reverse proxy daemon pantalaimon.

# DESCRIPTION

**panctl**
is a small utility to control and introspect the state of pantalaimon.
It communicates with the running daemon over D-Bus
(bus name
**org.pantalaimon1**).

## Commands

The commands accepted by
**panctl**
are as follows:

**list-servers**

> List the configured homeserver proxies.

**list-users**

> List all users that currently have an active pan session.

**list-devices** *pan-user* *user-id*

> List the devices of *user-id* that are known to the given *pan-user*.

**start-verification** *pan-user* *user-id* *device-id*

> Start an interactive SAS (short authentication string) key verification
> between the given *pan-user* and the remote *device-id*.
> The daemon will emit a
> **SasShow**
> signal when the emoji codes are ready to compare.

**accept-verification** *pan-user* *user-id* *device-id*

> Accept an interactive key verification that the remote device has started.

**confirm-verification** *pan-user* *user-id* *device-id*

> Confirm that the short authentication string shown on both devices matches.

**cancel-verification** *pan-user* *user-id* *device-id*

> Cancel an in-progress interactive key verification.

**verify-device** *pan-user* *user-id* *device-id*

> Manually mark the given device as verified for the given *pan-user*.

**unverify-device** *pan-user* *user-id* *device-id*

> Remove the verified mark from a previously verified device.

**blacklist-device** *pan-user* *user-id* *device-id*

> Mark the given device as blacklisted.
> Blacklisted devices never receive encryption keys.

**unblacklist-device** *pan-user* *user-id* *device-id*

> Remove the blacklisted mark from a previously blacklisted device.

**send-anyways** *pan-user* *room-id*

> When pantalaimon blocks a message because an encrypted room contains
> unverified devices, this command instructs the daemon to mark all
> unverified devices as ignored and send the message.

**cancel-sending** *pan-user* *room-id*

> Cancel a message that pantalaimon has blocked due to unverified devices.
> The user can then verify or blacklist devices before retrying.

**import-keys** *pan-user* *file* *passphrase*

> Import end-to-end encryption keys from the given file for the given
> *pan-user*.

**export-keys** *pan-user* *file* *passphrase*

> Export end-to-end encryption keys to the given file.
> The provided passphrase is used to encrypt the exported file.

**continue-keyshare** *pan-user* *user-id* *device-id*

> Forward a pending Megolm key-share request from the given device.

**cancel-keyshare** *pan-user* *user-id* *device-id*

> Reject a pending Megolm key-share request from the given device.

# EXIT STATUS

The **panctl** utility exits&#160;0 on success, and&#160;&gt;0 if an error occurs.

# SEE ALSO

pantalaimon(8)
pantalaimon(5)

# AUTHORS

**panctl**
was originally written by
Damir Jeli&#263; &lt;[poljar@termina.org.uk](mailto:poljar@termina.org.uk)&gt;.
Rewritten in Rust by the pantalaimon contributors.
