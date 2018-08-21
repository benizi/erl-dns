-module(tinydns_data_parser).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([tinydns_data_to_erlang/1]).
%-compile(export_all).

tinydns_data_to_erlang(Binary) ->
  Lines = binary_to_lines(Binary),
  Records = lists:flatmap(fun line_to_records/1, Lines),
  Zone = pick_zone(Records),
  {Sha, Keys} = {[], []},
  {Zone, Sha, Records, Keys}.

binary_to_lines(Binary) ->
  Parts = binary:split(Binary, [<<"\r">>, <<"\n">>], [trim, global]),
  lists:filter(fun(X) -> byte_size(X) > 0 end, Parts).

line_to_records(<<Type:8, Rest/binary>>) ->
  RawFields = binary:split(Rest, [<<":">>], [global]),
  Fields = lists:map(fun decode_octal/1, RawFields),
  records_for(Type, Fields).

decode_octal(<<>>) ->
  <<>>;
decode_octal(<<"\\", Oct:3/bytes, Rest/binary>>) ->
  Parsed =
    case octal_to_char(Oct) of
      {ok, C} -> C;
      {error, _Err} -> <<"\\", Oct/binary>>
    end,
  iolist_to_binary([Parsed, decode_octal(Rest)]);
decode_octal(<<C:8, Rest/binary>>) ->
  iolist_to_binary([C, decode_octal(Rest)]).

octal_to_char(<<Oct:3/bytes>>) ->
  try binary_to_integer(Oct, 8) of
    C when is_integer(C) andalso C >= 0 andalso C =< 255 -> {ok, <<C:8>>}
  catch
    error:E -> {error, E}
  end;
octal_to_char(O) ->
  O.

records_for($., [Fqdn,_Ip,X,Ttl,_Timestamp,_Loc] = Data) ->
  %% TODO: handle conditionals
  SoaData = {X ++ ".ns." ++ Fqdn,
             "hostmaster." ++ Fqdn,
             "1", %% TODO: Current time
             "16384",
             "2048",
             "1048576",
             "2560"},
  records_for($&, Data) ++ [record(soa, Fqdn, SoaData, Ttl)];

records_for($&, [Fqdn,Ip,X,Ttl,Timestamp,Loc]) ->
  %% TODO: handle conditionals
  Host = X ++ ".ns." ++ Fqdn,
  [record(ns, Host, Fqdn, Ttl)|records_for($+, [Host,Ip,Ttl,Timestamp,Loc])];

records_for($=, [Fqdn,Ip,Ttl,_Timestamp,_Loc]=Data) ->
  records_for($+, Data) ++ [record(ptr, inaddr_arpa(Ip), Fqdn, Ttl)];

records_for($+, [Fqdn,Ip,Ttl,_Timestamp,_Loc]) ->
  [record(a, Fqdn, Ip, Ttl)];

records_for($Z, [Fqdn,Mname,Rname,Serial,Refresh,Retry,Expire,Min,Ttl,_Timestamp,_Loc]) ->
  [record(soa, Fqdn, {Mname, Rname, Serial, Refresh, Retry, Expire, Min}, Ttl)];

records_for($@, [Fqdn,Ip,Dist,Ttl,_Timestamp,_Loc]) ->
  [record(mx, Fqdn, {Ip,Dist}, Ttl)];

records_for($C, [Fqdn,Dname,Ttl,_Timestamp,_Loc]) ->
  [record(cname, Fqdn, Dname, Ttl)];

records_for(Other, Data) ->
  [{fail, [Other|""], Data}].

inaddr_arpa(Ip) ->
  Parts = string:split(Ip, ".", all),
  string:join(lists:reverse(Parts) ++ ["in-addr.arpa"], ".").

record(Type, Name, Data, Ttl) ->
  {RecordType, RecordData} = type_and_data(Type, Data),
  #dns_rr{name = Name, type = RecordType, data = RecordData, ttl = Ttl}.

type_and_data(ns, Fqdn) ->
  {?DNS_TYPE_NS, #dns_rrdata_ns{dname = Fqdn}};

type_and_data(a, Ip) ->
  {?DNS_TYPE_A, #dns_rrdata_a{ip = Ip}};

type_and_data(soa, {Mname, Rname, Serial, Refresh, Retry, Expire, Min}) ->
  {?DNS_TYPE_SOA,
   #dns_rrdata_soa{
      mname = Mname,
      rname = Rname,
      serial = Serial,
      refresh = Refresh,
      retry = Retry,
      expire = Expire,
      minimum = Min}};

type_and_data(ptr, Host) ->
  {?DNS_TYPE_PTR, #dns_rrdata_ptr{dname = Host}};

type_and_data(mx, {Ip, Dist}) ->
  {?DNS_TYPE_MX, #dns_rrdata_mx{preference = Dist, exchange = Ip}};

type_and_data(cname, Dname) ->
  {?DNS_TYPE_CNAME, #dns_rrdata_cname{dname = Dname}}.

%% TODO: better heuristic(s)?
pick_zone(Records) ->
  IsSoa = fun(#dns_rr{type = Type}) -> Type =:= ?DNS_TYPE_SOA end,
  case lists:search(IsSoa, Records) of
    {value, #dns_rr{name = Zone}} -> Zone;
    _ -> <<"example.com">>
  end.
