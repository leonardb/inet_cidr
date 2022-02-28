%%% Pure erlang port of https://github.com/Cobenian/inet_cidr
%%% Erlang Port by Leonard Boyce, 2022
%%%
%%% Original code Copyright (c) 2015 Bryan Weber
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.

-module(inet_cidr).

-export([address_count/2,
         contains/2,
         parse/1,
         parse/2,
         parse_address/1,
         to_string/1,
         v4/1,
         v6/1]).

-include_lib("kernel/src/inet_int.hrl").
-type cidr() :: {inet:ip_address(), inet:ip_address(), non_neg_integer()}.

%% @doc
%%  Parses a string containing either an IPv4 or IPv6 CIDR block using the
%%  notation like `192.168.0.0/16` or `2001:abcd::/32`. It returns a tuple with the
%%  start address, end address and cidr length.
%%
%%  You can optionally pass true as the second argument to adjust the start `IP`
%%  address if it is not consistent with the cidr length.
%%  For example, `192.168.0.0/0` would be adjusted to have a start IP of `0.0.0.0`
%%  instead of `192.168.0.0`. The default behavior is to be more strict and raise
%%  an exception when this occurs.
%% @end
-spec parse(list() | binary()) -> cidr().
parse(CidrString) ->
    parse(CidrString, false).

-spec parse(list() | binary(), boolean()) -> cidr().
parse(CidrString, Adjust) when is_binary(CidrString) ->
    parse(binary_to_list(CidrString), Adjust);
parse(CidrString, Adjust) when is_list(CidrString) ->
    {StartAddress, PrefixLength} = parse_cidr(CidrString, Adjust),
    EndAddress = calc_end_address(StartAddress, PrefixLength),
    {StartAddress, EndAddress, PrefixLength}.

%% @doc
%% Prints the CIDR block to a string such that it can be parsed back to a CIDR
%% block by this module.
%% @end
-spec to_string(cidr()) -> list().
to_string({StartAddress, _EndAddress, CidrLength}) ->
    lists:flatten(io_lib:format("~s/~w", [inet:ntoa(StartAddress), CidrLength])).

%% @doc
%%  Convenience function that takes an IPv4 or IPv6 address as a string and
%%  returns the address.  It raises an exception if the string does not contain
%%  a valid IP address.
%% @end
-spec parse_address(list()) -> inet:ip_address().
parse_address(Prefix) ->
    {ok, StartAddress} = inet:parse_address(Prefix),
    StartAddress.

%% @doc The number of IP addresses included in the CIDR block.
-spec address_count(inet:ip_address(), non_neg_integer()) -> non_neg_integer().
address_count(Ip, Len) ->
    1 bsl (bit_count(Ip) - Len).

%% @doc The number of bits in the address family (32 for IPv4 and 128 for IPv6)
-spec bit_count(inet:ip_address()) -> 32 | 128.
bit_count({_,_,_,_}) -> 32;
bit_count({_,_,_,_,_,_,_,_}) -> 128.

%% @doc Returns true if the CIDR block contains the IP address, false otherwise.
-spec contains(cidr(), inet:ip_address()) -> boolean().
contains({{A0, B0, C0, D0},
          {A1, B1, C1, D1}, _PrefixLength},
         {A2, B2, C2, D2}) ->
    (A2 >= A0 andalso A2 =< A1)
        andalso (B2 >= B0 andalso B2 =< B1)
        andalso (C2 >= C0 andalso C2 =< C1)
        andalso (D2 >= D0 andalso D2 =< D1);
contains({{A0, B0, C0, D0, E0, F0, G0, H0},
          {A1, B1, C1, D1, E1, F1, G1, H1}, _PrefixLength},
         {A2, B2, C2, D2, E2, F2, G2, H2}) ->
    (A2 >= A0 andalso A2 =< A1)
        andalso (B2 >= B0 andalso B2 =< B1)
        andalso (C2 >= C0 andalso C2 =< C1)
        andalso (D2 >= D0 andalso D2 =< D1)
        andalso (E2 >= E0 andalso E2 =< E1)
        andalso (F2 >= F0 andalso F2 =< F1)
        andalso (G2 >= G0 andalso G2 =< G1)
        andalso (H2 >= H0 andalso H2 =< H1);
contains(_, _) ->
    false.

%% @doc Returns true if the value passed in is an IPv4 address, false otherwise.
-spec v4(inet:ip_address()) -> boolean().
v4({A, B, C, D}) ->
    ?ip(A, B, C, D);
v4(_) ->
    false.

%%  @doc Returns true if the value passed in is an IPv6 address, false otherwise.
-spec v6(inet:ip_address()) -> boolean().
v6({A, B, C, D, E, F, G, H}) ->
    ?ip6(A, B, C, D, E, F, G, H);
v6(_) ->
    false.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% internal functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
parse_cidr(CidrString, Adjust) when is_list(CidrString) ->
    [Prefix, PrefixLengthStr] = string:split(CidrString, "/"),
    StartAddress = parse_address(Prefix),
    PrefixLength = list_to_integer(PrefixLengthStr),
    %% if something 'nonsensical' is passed in like 192.168.0.0/0
    %% we have three choices:
    %% a) leave it alone (we do NOT allow this)
    %% b) adjust the start ip (to 0.0.0.0 in this case) - when adjust == true
    %% c) raise an exception - when adjust != true
    Masked = band_with_mask(StartAddress, start_mask(StartAddress, PrefixLength)),
    if not Adjust andalso Masked =/= StartAddress ->
            throw(invalid_cidr);
       true ->
            ok
    end,
    {Masked, PrefixLength}.

calc_end_address(StartAddress, PrefixLength) ->
    bor_with_mask( StartAddress, end_mask(StartAddress, PrefixLength) ).

start_mask({_,_,_,_} = S, Len) when Len >= 0 andalso Len =< 32 ->
    {A, B, C, D} = end_mask(S, Len),
    {bnot(A),
     bnot(B),
     bnot(C),
     bnot(D)};
start_mask({_,_,_,_,_,_,_,_} = S, Len) when Len >= 0 andalso Len =< 128 ->
    {A, B, C, D, E, F, G, H} = end_mask(S, Len),
    {bnot(A),
     bnot(B),
     bnot(C),
     bnot(D),
     bnot(E),
     bnot(F),
     bnot(G),
     bnot(H)}.

end_mask({_,_,_,_}, Len) when Len >= 0 andalso Len =< 32 ->
    case true of
        _ when Len =:= 32 ->
            {0, 0, 0, 0};
        _ when Len >= 24 ->
            {0, 0, 0, bmask(Len,8)};
        _ when Len >= 16 ->
            {0, 0, bmask(Len,8), 16#FF};
        _ when Len >= 8 ->
            {0, bmask(Len,8), 16#FF, 16#FF};
        _ when Len >= 0 ->
            {bmask(Len,8), 16#FF, 16#FF, 16#FF}
    end;
end_mask({_,_,_,_,_,_,_,_}, Len) when Len >= 0 andalso Len =< 128 ->
    case true of
        _ when Len =:= 128 ->
            {0, 0, 0, 0, 0, 0, 0, 0};
        _ when Len >= 112 ->
            {0, 0, 0, 0, 0, 0, 0, bmask(Len, 16)};
        _ when Len >= 96 ->
            {0, 0, 0, 0, 0, 0, bmask(Len, 16), 16#FFFF};
        _ when Len >= 80 ->
            {0, 0, 0, 0, 0, bmask(Len, 16), 16#FFFF, 16#FFFF};
        _ when Len >= 64 ->
            {0, 0, 0, 0, bmask(Len, 16), 16#FFFF, 16#FFFF, 16#FFFF};
        _ when Len >= 48 ->
            {0, 0, 0,bmask(Len, 16), 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF};
        _ when Len >= 32 ->
            {0, 0, bmask(Len, 16), 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF};
        _ when Len >= 16 ->
            {0, bmask(Len, 16), 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF};
        _ when Len >= 0 ->
            {bmask(Len, 16), 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF, 16#FFFF}
    end.

bmask(I,8)when I >= 0 andalso I =< 32 ->
    16#FF bsr (I rem 8);
bmask(I, 16) when I >= 0 andalso I =< 128 ->
    16#FFFF bsr (I rem 16).

bor_with_mask({A0,B0,C0,D0}, {A1,B1,C1,D1}) ->
    {A0 bor A1,
     B0 bor B1,
     C0 bor C1,
     D0 bor D1};
bor_with_mask( {A0,B0,C0,D0,E0,F0,G0,H0}, {A1,B1,C1,D1,E1,F1,G1,H1} ) ->
    {A0 bor A1,
     B0 bor B1,
     C0 bor C1,
     D0 bor D1,
     E0 bor E1,
     F0 bor F1,
     G0 bor G1,
     H0 bor H1}.

band_with_mask( {A0,B0,C0,D0}, {A1,B1,C1,D1} ) ->
    {A0 band A1,
     B0 band B1,
     C0 band C1,
     D0 band D1};
band_with_mask( {A0,B0,C0,D0,E0,F0,G0,H0}, {A1,B1,C1,D1,E1,F1,G1,H1} ) ->
    {A0 band A1,
     B0 band B1,
     C0 band C1,
     D0 band D1,
     E0 band E1,
     F0 band F1,
     G0 band G1,
     H0 band H1}.
