# DNS-Resolver

# Usage:

First run the resolver.py and the resolver will keep listening on the port.

```
$ python3 ./resolver.py port
```

Then you can start the client to send the query

```
$ python3 ./client.py 127.0.0.1 resolver_port name [type=A] [rd] [timeout=5]
```

Sample:

```
$ python3 ./resolver.py 5555
$ python3 ./client.py 127.0.0.1 5555 www.google.com
```

# Overview

This is a basic version of DNS-Resolver. It implements a subset of the functionalities of dnspython.
The resolver will listen for queries on a UDP port which is specified as a command-line argument. Clients will send queries from a UDP port which is automatically allocated
by the operating system. Upon receiving a query, the resolver will repeatedly make non-recursive
queries, starting at the root and following referrals, to iteratively resolve the query on behalf of the
client.
