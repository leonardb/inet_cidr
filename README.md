# InetCidr

Classless Inter-Domain Routing (CIDR) library for Erlang that supports both IPv4 and IPv6.

This is a pure erlang port of https://github.com/Cobenian/inet_cidr

## Install

Add `inet_cidr` to your list of dependencies in `rebar.config`:

## Usage

### Parsing a CIDR string

```erlang
1> inet_cidr:parse("192.168.0.0/16").
{{192,168,0,0}, {192,168,255,255}, 16}

2> inet_cidr:parse("2001:abcd::/32").
{{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 65535, 65535, 65535, 65535, 65535, 65535}, 32}
```

### Printing a CIDR block to string

```erlang
1> V4 =  inet_cidr:parse("192.168.0.0/16").
2> inet_cidr:to_string(V4).
"192.168.0.0/16"
3> V6 = inet_cidr:parse("2001:abcd::/32").
4> inet_cidr:to_string(V6).
"2001:ABCD::/32"
```

### Check whether a CIDR block contains an IP address

```erlang
1> Cidr = inet_cidr:parse("192.168.0.0/16").
{{192,168,0,0}, {192,168,255,255}, 16}

2> Address1 = inet_cidr:parse_address("192.168.15.20").
{192,168,15,20}

3> inet_cidr:contains(Cidr, Address1).
true

4> Address2 = inet_cidr:parse_address("10.168.15.20").
{10,168,15,20}

5> inet_cidr:contains(Cidr, Address2).
false
```

```erlang
1> Cidr = inet_cidr:parse("2001:abcd::/32").
{{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 65535, 65535, 65535, 65535, 65535, 65535}, 32}

2> Address1 = inet_cidr:parse_address("2001:abcd::").
{8193, 43981, 0, 0, 0, 0, 0, 0}

3> inet_cidr:contains(Cidr, Address1).
true

4> Address2 = inet_cidr:parse_address("abcd:2001::").
{43981, 8193, 0, 0, 0, 0, 0, 0}

5> inet_cidr:contains(Cidr, Address2).
false
```

## License

Copyright (c) 2015 Bryan Weber

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
