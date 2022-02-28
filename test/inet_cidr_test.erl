-module(inet_cidr_test).

-include_lib("eunit/include/eunit.hrl").


can_parse_ipv4_cidr_block_test() ->
    ?assertEqual(inet_cidr:parse("192.168.0.0/0", true), {{0,0,0,0}, {255,255,255,255}, 0}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/8", true), {{192,0,0,0}, {192,255,255,255}, 8}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/15", true), {{192,168,0,0}, {192,169,255,255}, 15}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/16"), {{192,168,0,0}, {192,168,255,255}, 16}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/17"), {{192,168,0,0}, {192,168,127,255}, 17}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/18"), {{192,168,0,0}, {192,168,63,255}, 18}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/19"), {{192,168,0,0}, {192,168,31,255}, 19}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/20"), {{192,168,0,0}, {192,168,15,255}, 20}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/21"), {{192,168,0,0}, {192,168,7,255}, 21}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/22"), {{192,168,0,0}, {192,168,3,255}, 22}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/23"), {{192,168,0,0}, {192,168,1,255}, 23}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/24"), {{192,168,0,0}, {192,168,0,255}, 24}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/31"), {{192,168,0,0}, {192,168,0,1}, 31}),
    ?assertEqual(inet_cidr:parse("192.168.0.0/32"), {{192,168,0,0}, {192,168,0,0}, 32}).

can_parse_ipv6_cidr_block_test() ->
    ?assertEqual(inet_cidr:parse("2001:abcd::/0", true), {{0, 0, 0, 0, 0, 0, 0, 0}, {65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535}, 0}),
    ?assertEqual(inet_cidr:parse("2001:abcd::/32"), {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 65535, 65535, 65535, 65535, 65535, 65535}, 32}),
    ?assertEqual(inet_cidr:parse("2001:abcd::/33"), {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 32767, 65535, 65535, 65535, 65535, 65535}, 33}),
    ?assertEqual(inet_cidr:parse("2001:abcd::/34"), {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 16383, 65535, 65535, 65535, 65535, 65535}, 34}),
    ?assertEqual(inet_cidr:parse("2001:abcd::/35"), {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 8191, 65535, 65535, 65535, 65535, 65535}, 35}),
    ?assertEqual(inet_cidr:parse("2001:abcd::/36"), {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 4095, 65535, 65535, 65535, 65535, 65535}, 36}),
    ?assertEqual(inet_cidr:parse("2001:abcd::/128"), {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 0, 0, 0, 0, 0, 0}, 128}),
    ?assertEqual(inet_cidr:parse("2001:db8::/48"), {{8193, 3512, 0, 0, 0, 0, 0, 0}, {8193, 3512, 0, 65535, 65535, 65535, 65535, 65535}, 48}).

printing_cidr_block_to_string_test() ->
    ?assertEqual(inet_cidr:to_string({{192,168,0,0}, {192,168,255,255}, 16}), "192.168.0.0/16"),
    ?assertEqual(inet_cidr:to_string({{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 65535, 65535, 65535, 65535, 65535, 65535}, 32}), "2001:abcd::/32").

can_parse_ipv4_address_test() ->
    ?assertEqual(inet_cidr:parse_address("76.58.129.251"), {76,58,129,251}).

can_parse_ipv6_address_test() ->
    ?assertEqual(inet_cidr:parse_address("2001:abcd::"), {8193, 43981, 0, 0, 0, 0, 0, 0}),
    ?assertEqual(inet_cidr:parse_address("1:abcd::4"), {1, 43981, 0, 0, 0, 0, 0, 4}).

correct_address_count_for_ipv4_cidr_block_test() ->
    V4address = {192,168,0,0},
    ?assertEqual(inet_cidr:address_count(V4address, 0), 4294967296),
    ?assertEqual(inet_cidr:address_count(V4address, 16), 65536),
    ?assertEqual(inet_cidr:address_count(V4address, 17), 32768),
    ?assertEqual(inet_cidr:address_count(V4address, 24), 256),
    ?assertEqual(inet_cidr:address_count(V4address, 32), 1).

correct_address_count_for_ipv6_cidr_block_test() ->
    V6address = inet_cidr:parse_address("2001::abcd"),
    ?assertEqual(inet_cidr:address_count(V6address, 0), round(math:pow(2,128))),
    ?assertEqual(inet_cidr:address_count(V6address, 64), round(math:pow(2,64))),
    ?assertEqual(inet_cidr:address_count(V6address, 128), 1).

is_ipv4_address_test() ->
    ?assertEqual(inet_cidr:v4({192,168,0,0}), true),
    ?assertEqual(inet_cidr:v4({192,168,0,256}), false),
    ?assertEqual(inet_cidr:v4({192,168,0}), false),
    ?assertEqual(inet_cidr:v4({192,168,0,0,0}), false),
    ?assertEqual(inet_cidr:v4(inet_cidr:parse_address("2001::abcd")), false).

is_ipv6_address_test() ->
    ?assertEqual(inet_cidr:v6({8193, 43981, 0, 0, 0, 0, 0, 0}), true),
    ?assertEqual(inet_cidr:v6({192,168,0,0}), false),
    ?assertEqual(inet_cidr:v6({8193, 43981, 0, 0, 0, 0, 0, 70000}), false),
    ?assertEqual(inet_cidr:v6({8193, 43981, 0, 0, 0, 0, 0}), false),
    ?assertEqual(inet_cidr:v6({8193, 43981, 0, 0, 0, 0, 0, 0, 0}), false).

ipv4_block_contains_address_test() ->
    Block = {{192,168,0,0}, {192,168,255,255}, 16},
    ?assertEqual(inet_cidr:contains(Block, {192,168,0,0}), true),
    ?assertEqual(inet_cidr:contains(Block, {192,168,0,1}), true),
    ?assertEqual(inet_cidr:contains(Block, {192,168,1,0}), true),
    ?assertEqual(inet_cidr:contains(Block, {192,168,0,255}), true),
    ?assertEqual(inet_cidr:contains(Block, {192,168,255,0}), true),
    ?assertEqual(inet_cidr:contains(Block, {192,168,255,255}), true),
    ?assertEqual(inet_cidr:contains(Block, {192,168,255,256}), false),
    ?assertEqual(inet_cidr:contains(Block, {192,169,0,0}), false),
    ?assertEqual(inet_cidr:contains(Block, {192,167,255,255}), false).

ipv6_block_contains_address_test() ->
    Block = {{8193, 43981, 0, 0, 0, 0, 0, 0}, {8193, 43981, 8191, 65535, 65535, 65535, 65535, 65535}, 35},
    ?assertEqual(inet_cidr:contains(Block, {8193, 43981, 0, 0, 0, 0, 0, 0}), true),
    ?assertEqual(inet_cidr:contains(Block, {8193, 43981, 0, 0, 0, 0, 0, 1}), true),
    ?assertEqual(inet_cidr:contains(Block, {8193, 43981, 8191, 65535, 65535, 65535, 65535, 65534}), true),
    ?assertEqual(inet_cidr:contains(Block, {8193, 43981, 8191, 65535, 65535, 65535, 65535, 65535}), true),
    ?assertEqual(inet_cidr:contains(Block, {8193, 43981, 8192, 65535, 65535, 65535, 65535, 65535}), false),
    ?assertEqual(inet_cidr:contains(Block, {65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535}), false).
