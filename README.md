# NetAuth LDAP Server

The NetAuth LDAP server acts as a bridge that allows legacy systems
that understand LDAP to gain a read-only view of data in the NetAuth
server.

It is recommended to install the NetAuth LDAP server on each host that
requires this interface and to bind it to the loopback interface.

The format that the LDAP bridge exposes data in is slightly different
to that which is presented to an actual NetAuth client.  The groups
are presented in a flattened format with all expansions processed, and
all groups are precented under a special `ou=groups` path.  Similarly,
entities are presented under a `ou=entities` path under the base DN.

Speaking of the base DN, NetAuth doesn't have such a concept, so the
LDAP bridge takes this as a seperate configuration item on startup.
The provided format must be a valid domain name that will be split on
`.`.  Prepended to this will be `dc=netauth` to clearly signify that
the data retrieved is coming from NetAuth.
