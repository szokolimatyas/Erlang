-file("io_lib_format.erl", 1).

-module(io_lib_format).

-export([fwrite/2, fwrite/3, fwrite_g/1, indentation/2, scan/2, unscan/1, build/1, build/2]).

-spec(fwrite(Format,Data) -> io_lib:chars() when Format::io:format(),Data::[term()]).

fwrite(Format,Args) ->
    build(scan(Format,Args)).

-spec(fwrite(Format,Data,Options) -> io_lib:chars() when Format::io:format(),Data::[term()],Options::[Option],Option::{chars_limit,CharsLimit},CharsLimit::io_lib:chars_limit()).

fwrite(Format,Args,Options) ->
    build(scan(Format,Args),Options).

-spec(build(FormatList) -> io_lib:chars() when FormatList::[char()|io_lib:format_spec()]).

build(Cs) ->
    build(Cs,[]).

-spec(build(FormatList,Options) -> io_lib:chars() when FormatList::[char()|io_lib:format_spec()],Options::[Option],Option::{chars_limit,CharsLimit},CharsLimit::io_lib:chars_limit()).

build(Cs,Options) ->
    CharsLimit = get_option(chars_limit,Options,-1),
    Res1 = build_small(Cs),
    {P,S,W,Other} = count_small(Res1),
    case P + S + W of
        0->
            Res1;
        NumOfLimited->
            RemainingChars = sub(CharsLimit,Other),
            build_limited(Res1,P,NumOfLimited,RemainingChars,0)
    end.

-spec(scan(Format,Data) -> FormatList when Format::io:format(),Data::[term()],FormatList::[char()|io_lib:format_spec()]).

scan(Format,Args)
    when is_atom(Format)->
    scan(atom_to_list(Format),Args);
scan(Format,Args)
    when is_binary(Format)->
    scan(binary_to_list(Format),Args);
scan(Format,Args) ->
    collect(Format,Args).

-spec(unscan(FormatList) -> {Format,Data} when FormatList::[char()|io_lib:format_spec()],Format::io:format(),Data::[term()]).

unscan(Cs) ->
    {print(Cs),args(Cs)}.

args([#{args:=As}| Cs]) ->
    As ++ args(Cs);
args([_C| Cs]) ->
    args(Cs);
args([]) ->
    [].

print([#{control_char:=C,width:=F,adjust:=Ad,precision:=P,pad_char:=Pad,encoding:=Encoding,strings:=Strings}| Cs]) ->
    print(C,F,Ad,P,Pad,Encoding,Strings) ++ print(Cs);
print([C| Cs]) ->
    [C| print(Cs)];
print([]) ->
    [].

print(C,F,Ad,P,Pad,Encoding,Strings) ->
    [$~] ++ print_field_width(F,Ad) ++ print_precision(P,Pad) ++ print_pad_char(Pad) ++ print_encoding(Encoding) ++ print_strings(Strings) ++ [C].

print_field_width(none,_Ad) ->
    "";
print_field_width(F,left) ->
    integer_to_list(-F);
print_field_width(F,right) ->
    integer_to_list(F).

print_precision(none,$ ) ->
    "";
print_precision(none,_Pad) ->
    ".";
print_precision(P,_Pad) ->
    [$.| integer_to_list(P)].

print_pad_char($ ) ->
    "";
print_pad_char(Pad) ->
    [$., Pad].

print_encoding(unicode) ->
    "t";
print_encoding(latin1) ->
    "".

print_strings(false) ->
    "l";
print_strings(true) ->
    "".

collect([$~| Fmt0],Args0) ->
    {C,Fmt1,Args1} = collect_cseq(Fmt0,Args0),
    [C| collect(Fmt1,Args1)];
collect([C| Fmt],Args) ->
    [C| collect(Fmt,Args)];
collect([],[]) ->
    [].

collect_cseq(Fmt0,Args0) ->
    {F,Ad,Fmt1,Args1} = field_width(Fmt0,Args0),
    {P,Fmt2,Args2} = precision(Fmt1,Args1),
    {Pad,Fmt3,Args3} = pad_char(Fmt2,Args2),
    Spec0 = #{width=>F,adjust=>Ad,precision=>P,pad_char=>Pad,encoding=>latin1,strings=>true},
    {Spec1,Fmt4} = modifiers(Fmt3,Spec0),
    {C,As,Fmt5,Args4} = collect_cc(Fmt4,Args3),
    Spec2 = Spec1#{control_char=>C,args=>As},
    {Spec2,Fmt5,Args4}.

modifiers([$t| Fmt],Spec) ->
    modifiers(Fmt,Spec#{encoding=>unicode});
modifiers([$l| Fmt],Spec) ->
    modifiers(Fmt,Spec#{strings=>false});
modifiers(Fmt,Spec) ->
    {Spec,Fmt}.

field_width([$-| Fmt0],Args0) ->
    {F,Fmt,Args} = field_value(Fmt0,Args0),
    field_width(-F,Fmt,Args);
field_width(Fmt0,Args0) ->
    {F,Fmt,Args} = field_value(Fmt0,Args0),
    field_width(F,Fmt,Args).

field_width(F,Fmt,Args)
    when F < 0->
    {-F,left,Fmt,Args};
field_width(F,Fmt,Args)
    when F >= 0->
    {F,right,Fmt,Args}.

precision([$.| Fmt],Args) ->
    field_value(Fmt,Args);
precision(Fmt,Args) ->
    {none,Fmt,Args}.

field_value([$*| Fmt],[A| Args])
    when is_integer(A)->
    {A,Fmt,Args};
field_value([C| Fmt],Args)
    when is_integer(C),
    C >= $0,
    C =< $9->
    field_value([C| Fmt],Args,0);
field_value(Fmt,Args) ->
    {none,Fmt,Args}.

field_value([C| Fmt],Args,F)
    when is_integer(C),
    C >= $0,
    C =< $9->
    field_value(Fmt,Args,10 * F + (C - $0));
field_value(Fmt,Args,F) ->
    {F,Fmt,Args}.

pad_char([$., $*| Fmt],[Pad| Args]) ->
    {Pad,Fmt,Args};
pad_char([$., Pad| Fmt],Args) ->
    {Pad,Fmt,Args};
pad_char(Fmt,Args) ->
    {$ ,Fmt,Args}.

collect_cc([$w| Fmt],[A| Args]) ->
    {$w,[A],Fmt,Args};
collect_cc([$p| Fmt],[A| Args]) ->
    {$p,[A],Fmt,Args};
collect_cc([$W| Fmt],[A, Depth| Args]) ->
    {$W,[A, Depth],Fmt,Args};
collect_cc([$P| Fmt],[A, Depth| Args]) ->
    {$P,[A, Depth],Fmt,Args};
collect_cc([$s| Fmt],[A| Args]) ->
    {$s,[A],Fmt,Args};
collect_cc([$e| Fmt],[A| Args]) ->
    {$e,[A],Fmt,Args};
collect_cc([$f| Fmt],[A| Args]) ->
    {$f,[A],Fmt,Args};
collect_cc([$g| Fmt],[A| Args]) ->
    {$g,[A],Fmt,Args};
collect_cc([$b| Fmt],[A| Args]) ->
    {$b,[A],Fmt,Args};
collect_cc([$B| Fmt],[A| Args]) ->
    {$B,[A],Fmt,Args};
collect_cc([$x| Fmt],[A, Prefix| Args]) ->
    {$x,[A, Prefix],Fmt,Args};
collect_cc([$X| Fmt],[A, Prefix| Args]) ->
    {$X,[A, Prefix],Fmt,Args};
collect_cc([$+| Fmt],[A| Args]) ->
    {$+,[A],Fmt,Args};
collect_cc([$#| Fmt],[A| Args]) ->
    {$#,[A],Fmt,Args};
collect_cc([$c| Fmt],[A| Args]) ->
    {$c,[A],Fmt,Args};
collect_cc([$~| Fmt],Args)
    when is_list(Args)->
    {$~,[],Fmt,Args};
collect_cc([$n| Fmt],Args)
    when is_list(Args)->
    {$n,[],Fmt,Args};
collect_cc([$i| Fmt],[A| Args]) ->
    {$i,[A],Fmt,Args}.

count_small(Cs) ->
    count_small(Cs,#{p=>0,s=>0,w=>0,other=>0}).

count_small([#{control_char:=$p}| Cs],#{p:=P} = Cnts) ->
    count_small(Cs,Cnts#{p:=P + 1});
count_small([#{control_char:=$P}| Cs],#{p:=P} = Cnts) ->
    count_small(Cs,Cnts#{p:=P + 1});
count_small([#{control_char:=$w}| Cs],#{w:=W} = Cnts) ->
    count_small(Cs,Cnts#{w:=W + 1});
count_small([#{control_char:=$W}| Cs],#{w:=W} = Cnts) ->
    count_small(Cs,Cnts#{w:=W + 1});
count_small([#{control_char:=$s}| Cs],#{w:=W} = Cnts) ->
    count_small(Cs,Cnts#{w:=W + 1});
count_small([S| Cs],#{other:=Other} = Cnts)
    when is_list(S);
    is_binary(S)->
    count_small(Cs,Cnts#{other:=Other + io_lib:chars_length(S)});
count_small([C| Cs],#{other:=Other} = Cnts)
    when is_integer(C)->
    count_small(Cs,Cnts#{other:=Other + 1});
count_small([],#{p:=P,s:=S,w:=W,other:=Other}) ->
    {P,S,W,Other}.

build_small([#{control_char:=C,args:=As,width:=F,adjust:=Ad,precision:=P,pad_char:=Pad,encoding:=Enc} = CC| Cs]) ->
    case control_small(C,As,F,Ad,P,Pad,Enc) of
        not_small->
            [CC| build_small(Cs)];
        S->
            lists:flatten(S) ++ build_small(Cs)
    end;
build_small([C| Cs]) ->
    [C| build_small(Cs)];
build_small([]) ->
    [].

build_limited([#{control_char:=C,args:=As,width:=F,adjust:=Ad,precision:=P,pad_char:=Pad,encoding:=Enc,strings:=Str}| Cs],NumOfPs0,Count0,MaxLen0,I) ->
    MaxChars = if MaxLen0 < 0 ->
        MaxLen0;true ->
        MaxLen0 div Count0 end,
    S = control_limited(C,As,F,Ad,P,Pad,Enc,Str,MaxChars,I),
    NumOfPs = decr_pc(C,NumOfPs0),
    Count = Count0 - 1,
    MaxLen = if MaxLen0 < 0 ->
        MaxLen0;true ->
        Len = io_lib:chars_length(S),
        sub(MaxLen0,Len) end,
    if NumOfPs > 0 ->
        [S| build_limited(Cs,NumOfPs,Count,MaxLen,indentation(S,I))];true ->
        [S| build_limited(Cs,NumOfPs,Count,MaxLen,I)] end;
build_limited([$\n| Cs],NumOfPs,Count,MaxLen,_I) ->
    [$\n| build_limited(Cs,NumOfPs,Count,MaxLen,0)];
build_limited([$\t| Cs],NumOfPs,Count,MaxLen,I) ->
    [$\t| build_limited(Cs,NumOfPs,Count,MaxLen,(I + 8) div 8 * 8)];
build_limited([C| Cs],NumOfPs,Count,MaxLen,I) ->
    [C| build_limited(Cs,NumOfPs,Count,MaxLen,I + 1)];
build_limited([],_,_,_,_) ->
    [].

decr_pc($p,Pc) ->
    Pc - 1;
decr_pc($P,Pc) ->
    Pc - 1;
decr_pc(_,Pc) ->
    Pc.

-spec(indentation(String,StartIndent) -> integer() when String::io_lib:chars(),StartIndent::integer()).

indentation([$\n| Cs],_I) ->
    indentation(Cs,0);
indentation([$\t| Cs],I) ->
    indentation(Cs,(I + 8) div 8 * 8);
indentation([C| Cs],I)
    when is_integer(C)->
    indentation(Cs,I + 1);
indentation([C| Cs],I) ->
    indentation(Cs,indentation(C,I));
indentation([],I) ->
    I.

control_small($s,[A],F,Adj,P,Pad,latin1 = Enc)
    when is_atom(A)->
    L = iolist_to_chars(atom_to_list(A)),
    string(L,F,Adj,P,Pad,Enc);
control_small($s,[A],F,Adj,P,Pad,unicode = Enc)
    when is_atom(A)->
    string(atom_to_list(A),F,Adj,P,Pad,Enc);
control_small($e,[A],F,Adj,P,Pad,_Enc)
    when is_float(A)->
    fwrite_e(A,F,Adj,P,Pad);
control_small($f,[A],F,Adj,P,Pad,_Enc)
    when is_float(A)->
    fwrite_f(A,F,Adj,P,Pad);
control_small($g,[A],F,Adj,P,Pad,_Enc)
    when is_float(A)->
    fwrite_g(A,F,Adj,P,Pad);
control_small($b,[A],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    unprefixed_integer(A,F,Adj,base(P),Pad,true);
control_small($B,[A],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    unprefixed_integer(A,F,Adj,base(P),Pad,false);
control_small($x,[A, Prefix],F,Adj,P,Pad,_Enc)
    when is_integer(A),
    is_atom(Prefix)->
    prefixed_integer(A,F,Adj,base(P),Pad,atom_to_list(Prefix),true);
control_small($x,[A, Prefix],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    true = io_lib:deep_char_list(Prefix),
    prefixed_integer(A,F,Adj,base(P),Pad,Prefix,true);
control_small($X,[A, Prefix],F,Adj,P,Pad,_Enc)
    when is_integer(A),
    is_atom(Prefix)->
    prefixed_integer(A,F,Adj,base(P),Pad,atom_to_list(Prefix),false);
control_small($X,[A, Prefix],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    true = io_lib:deep_char_list(Prefix),
    prefixed_integer(A,F,Adj,base(P),Pad,Prefix,false);
control_small($+,[A],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    Base = base(P),
    Prefix = [integer_to_list(Base), $#],
    prefixed_integer(A,F,Adj,Base,Pad,Prefix,true);
control_small($#,[A],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    Base = base(P),
    Prefix = [integer_to_list(Base), $#],
    prefixed_integer(A,F,Adj,Base,Pad,Prefix,false);
control_small($c,[A],F,Adj,P,Pad,unicode)
    when is_integer(A)->
    char(A,F,Adj,P,Pad);
control_small($c,[A],F,Adj,P,Pad,_Enc)
    when is_integer(A)->
    char(A band 255,F,Adj,P,Pad);
control_small($~,[],F,Adj,P,Pad,_Enc) ->
    char($~,F,Adj,P,Pad);
control_small($n,[],F,Adj,P,Pad,_Enc) ->
    newline(F,Adj,P,Pad);
control_small($i,[_A],_F,_Adj,_P,_Pad,_Enc) ->
    [];
control_small(_C,_As,_F,_Adj,_P,_Pad,_Enc) ->
    not_small.

control_limited($s,[L0],F,Adj,P,Pad,latin1 = Enc,_Str,CL,_I) ->
    L = iolist_to_chars(L0,F,CL),
    string(L,limit_field(F,CL),Adj,P,Pad,Enc);
control_limited($s,[L0],F,Adj,P,Pad,unicode = Enc,_Str,CL,_I) ->
    L = cdata_to_chars(L0,F,CL),
    uniconv(string(L,limit_field(F,CL),Adj,P,Pad,Enc));
control_limited($w,[A],F,Adj,P,Pad,Enc,_Str,CL,_I) ->
    Chars = io_lib:write(A,[{depth,-1}, {encoding,Enc}, {chars_limit,CL}]),
    term(Chars,F,Adj,P,Pad);
control_limited($p,[A],F,Adj,P,Pad,Enc,Str,CL,I) ->
    print(A,-1,F,Adj,P,Pad,Enc,Str,CL,I);
control_limited($W,[A, Depth],F,Adj,P,Pad,Enc,_Str,CL,_I)
    when is_integer(Depth)->
    Chars = io_lib:write(A,[{depth,Depth}, {encoding,Enc}, {chars_limit,CL}]),
    term(Chars,F,Adj,P,Pad);
control_limited($P,[A, Depth],F,Adj,P,Pad,Enc,Str,CL,I)
    when is_integer(Depth)->
    print(A,Depth,F,Adj,P,Pad,Enc,Str,CL,I).

uniconv(C) ->
    C.

base(none) ->
    10;
base(B)
    when is_integer(B)->
    B.

term(T,none,_Adj,none,_Pad) ->
    T;
term(T,none,Adj,P,Pad) ->
    term(T,P,Adj,P,Pad);
term(T,F,Adj,P0,Pad) ->
    L = io_lib:chars_length(T),
    P = min(L,case P0 of
        none->
            F;
        _->
            min(P0,F)
    end),
    if L > P ->
        adjust(chars($*,P),chars(Pad,F - P),Adj);F >= P ->
        adjust(T,chars(Pad,F - L),Adj) end.

print(T,D,none,Adj,P,Pad,E,Str,ChLim,I) ->
    print(T,D,80,Adj,P,Pad,E,Str,ChLim,I);
print(T,D,F,Adj,none,Pad,E,Str,ChLim,I) ->
    print(T,D,F,Adj,I + 1,Pad,E,Str,ChLim,I);
print(T,D,F,right,P,_Pad,Enc,Str,ChLim,_I) ->
    Options = [{chars_limit,ChLim}, {column,P}, {line_length,F}, {depth,D}, {encoding,Enc}, {strings,Str}],
    io_lib_pretty:print(T,Options).

fwrite_e(Fl,none,Adj,none,Pad) ->
    fwrite_e(Fl,none,Adj,6,Pad);
fwrite_e(Fl,none,_Adj,P,_Pad)
    when P >= 2->
    float_e(Fl,float_data(Fl),P);
fwrite_e(Fl,F,Adj,none,Pad) ->
    fwrite_e(Fl,F,Adj,6,Pad);
fwrite_e(Fl,F,Adj,P,Pad)
    when P >= 2->
    term(float_e(Fl,float_data(Fl),P),F,Adj,F,Pad).

float_e(Fl,Fd,P)
    when Fl < 0.0->
    [$-| float_e(-Fl,Fd,P)];
float_e(_Fl,{Ds,E},P) ->
    case float_man(Ds,1,P - 1) of
        {[$0| Fs],true}->
            [[$1| Fs]| float_exp(E)];
        {Fs,false}->
            [Fs| float_exp(E - 1)]
    end.

float_man(Ds,0,Dc) ->
    {Cs,C} = float_man(Ds,Dc),
    {[$.| Cs],C};
float_man([D| Ds],I,Dc) ->
    case float_man(Ds,I - 1,Dc) of
        {Cs,true}
            when D =:= $9->
            {[$0| Cs],true};
        {Cs,true}->
            {[D + 1| Cs],false};
        {Cs,false}->
            {[D| Cs],false}
    end;
float_man([],I,Dc) ->
    {lists:duplicate(I,$0) ++ [$.| lists:duplicate(Dc,$0)],false}.

float_man([D| _],0)
    when D >= $5->
    {[],true};
float_man([_| _],0) ->
    {[],false};
float_man([D| Ds],Dc) ->
    case float_man(Ds,Dc - 1) of
        {Cs,true}
            when D =:= $9->
            {[$0| Cs],true};
        {Cs,true}->
            {[D + 1| Cs],false};
        {Cs,false}->
            {[D| Cs],false}
    end;
float_man([],Dc) ->
    {lists:duplicate(Dc,$0),false}.

float_exp(E)
    when E >= 0->
    [$e, $+| integer_to_list(E)];
float_exp(E) ->
    [$e| integer_to_list(E)].

fwrite_f(Fl,none,Adj,none,Pad) ->
    fwrite_f(Fl,none,Adj,6,Pad);
fwrite_f(Fl,none,_Adj,P,_Pad)
    when P >= 1->
    float_f(Fl,float_data(Fl),P);
fwrite_f(Fl,F,Adj,none,Pad) ->
    fwrite_f(Fl,F,Adj,6,Pad);
fwrite_f(Fl,F,Adj,P,Pad)
    when P >= 1->
    term(float_f(Fl,float_data(Fl),P),F,Adj,F,Pad).

float_f(Fl,Fd,P)
    when Fl < 0.0->
    [$-| float_f(-Fl,Fd,P)];
float_f(Fl,{Ds,E},P)
    when E =< 0->
    float_f(Fl,{lists:duplicate(-E + 1,$0) ++ Ds,1},P);
float_f(_Fl,{Ds,E},P) ->
    case float_man(Ds,E,P) of
        {Fs,true}->
            "1" ++ Fs;
        {Fs,false}->
            Fs
    end.

float_data(Fl) ->
    float_data(float_to_list(Fl),[]).

float_data([$e| E],Ds) ->
    {lists:reverse(Ds),list_to_integer(E) + 1};
float_data([D| Cs],Ds)
    when D >= $0,
    D =< $9->
    float_data(Cs,[D| Ds]);
float_data([_| Cs],Ds) ->
    float_data(Cs,Ds).

-spec(fwrite_g(float()) -> string()).

fwrite_g(0.0) ->
    "0.0";
fwrite_g(Float)
    when is_float(Float)->
    {Frac,Exp} = mantissa_exponent(Float),
    {Place,Digits} = fwrite_g_1(Float,Exp,Frac),
    R = insert_decimal(Place,[($0 + D) || D <- Digits]),
    [$- || true <- [Float < 0.0]] ++ R.

mantissa_exponent(F) ->
    case <<F:64/float>> of
        <<_S:1,0:11,M:52>>->
            E = log2floor(M),
            {M bsl (53 - E),E - 52 - 1075};
        <<_S:1,BE:11,M:52>>
            when BE < 2047->
            {M + (1 bsl 52),BE - 1075}
    end.

fwrite_g_1(Float,Exp,Frac) ->
    Round = Frac band 1 =:= 0,
    if Exp >= 0 ->
        BExp = 1 bsl Exp,
        if Frac =:= 1 bsl 52 ->
            scale(Frac * BExp * 4,4,BExp * 2,BExp,Round,Round,Float);true ->
            scale(Frac * BExp * 2,2,BExp,BExp,Round,Round,Float) end;Exp < -1074 ->
        BExp = 1 bsl (-1074 - Exp),
        scale(Frac * 2,1 bsl (1 - Exp),BExp,BExp,Round,Round,Float);Exp > -1074,
    Frac =:= 1 bsl 52 ->
        scale(Frac * 4,1 bsl (2 - Exp),2,1,Round,Round,Float);true ->
        scale(Frac * 2,1 bsl (1 - Exp),1,1,Round,Round,Float) end.

scale(R,S,MPlus,MMinus,LowOk,HighOk,Float) ->
    Est = int_ceil(math:log10(abs(Float)) - 1.0e-10),
    if Est >= 0 ->
        fixup(R,S * int_pow(10,Est),MPlus,MMinus,Est,LowOk,HighOk);true ->
        Scale = int_pow(10,-Est),
        fixup(R * Scale,S,MPlus * Scale,MMinus * Scale,Est,LowOk,HighOk) end.

fixup(R,S,MPlus,MMinus,K,LowOk,HighOk) ->
    TooLow = if HighOk ->
        R + MPlus >= S;true ->
        R + MPlus > S end,
    case TooLow of
        true->
            {K + 1,generate(R,S,MPlus,MMinus,LowOk,HighOk)};
        false->
            {K,generate(R * 10,S,MPlus * 10,MMinus * 10,LowOk,HighOk)}
    end.

generate(R0,S,MPlus,MMinus,LowOk,HighOk) ->
    D = R0 div S,
    R = R0 rem S,
    TC1 = if LowOk ->
        R =< MMinus;true ->
        R < MMinus end,
    TC2 = if HighOk ->
        R + MPlus >= S;true ->
        R + MPlus > S end,
    case {TC1,TC2} of
        {false,false}->
            [D| generate(R * 10,S,MPlus * 10,MMinus * 10,LowOk,HighOk)];
        {false,true}->
            [D + 1];
        {true,false}->
            [D];
        {true,true}
            when R * 2 < S->
            [D];
        {true,true}->
            [D + 1]
    end.

insert_decimal(0,S) ->
    "0." ++ S;
insert_decimal(Place,S) ->
    L = length(S),
    if Place < 0;
    Place >= L ->
        ExpL = integer_to_list(Place - 1),
        ExpDot = if L =:= 1 ->
            2;true ->
            1 end,
        ExpCost = length(ExpL) + 1 + ExpDot,
        if Place < 0 ->
            if 2 - Place =< ExpCost ->
                "0." ++ lists:duplicate(-Place,$0) ++ S;true ->
                insert_exp(ExpL,S) end;true ->
            if Place - L + 2 =< ExpCost ->
                S ++ lists:duplicate(Place - L,$0) ++ ".0";true ->
                insert_exp(ExpL,S) end end;true ->
        {S0,S1} = lists:split(Place,S),
        S0 ++ "." ++ S1 end.

insert_exp(ExpL,[C]) ->
    [C] ++ ".0e" ++ ExpL;
insert_exp(ExpL,[C| S]) ->
    [C] ++ "." ++ S ++ "e" ++ ExpL.

int_ceil(X)
    when is_float(X)->
    T = trunc(X),
    case X - T of
        Neg
            when Neg < 0->
            T;
        Pos
            when Pos > 0->
            T + 1;
        _->
            T
    end.

int_pow(X,0)
    when is_integer(X)->
    1;
int_pow(X,N)
    when is_integer(X),
    is_integer(N),
    N > 0->
    int_pow(X,N,1).

int_pow(X,N,R)
    when N < 2->
    R * X;
int_pow(X,N,R) ->
    int_pow(X * X,N bsr 1,case N band 1 of
        1->
            R * X;
        0->
            R
    end).

log2floor(Int)
    when is_integer(Int),
    Int > 0->
    log2floor(Int,0).

log2floor(0,N) ->
    N;
log2floor(Int,N) ->
    log2floor(Int bsr 1,1 + N).

fwrite_g(Fl,F,Adj,none,Pad) ->
    fwrite_g(Fl,F,Adj,6,Pad);
fwrite_g(Fl,F,Adj,P,Pad)
    when P >= 1->
    A = abs(Fl),
    E = if A < 0.1 ->
        -2;A < 1.0 ->
        -1;A < 10.0 ->
        0;A < 100.0 ->
        1;A < 1000.0 ->
        2;A < 10000.0 ->
        3;true ->
        fwrite_f end,
    if P =< 1,
    E =:= -1;
    P - 1 > E,
    E >= -1 ->
        fwrite_f(Fl,F,Adj,P - 1 - E,Pad);P =< 1 ->
        fwrite_e(Fl,F,Adj,2,Pad);true ->
        fwrite_e(Fl,F,Adj,P,Pad) end.

iolist_to_chars(Cs,F,CharsLimit)
    when CharsLimit < 0;
    CharsLimit >= F->
    iolist_to_chars(Cs);
iolist_to_chars(Cs,_,CharsLimit) ->
    limit_iolist_to_chars(Cs,sub(CharsLimit,3),[],normal).

iolist_to_chars([C| Cs])
    when is_integer(C),
    C >= $\\,
    C =< $ÿ->
    [C| iolist_to_chars(Cs)];
iolist_to_chars([I| Cs]) ->
    [iolist_to_chars(I)| iolist_to_chars(Cs)];
iolist_to_chars([]) ->
    [];
iolist_to_chars(B)
    when is_binary(B)->
    binary_to_list(B).

limit_iolist_to_chars(Cs,0,S,normal) ->
    L = limit_iolist_to_chars(Cs,4,S,final),
    case iolist_size(L) of
        N
            when N < 4->
            L;
        4->
            "..."
    end;
limit_iolist_to_chars(_Cs,0,_S,final) ->
    [];
limit_iolist_to_chars([C| Cs],Limit,S,Mode)
    when C >= $\\,
    C =< $ÿ->
    [C| limit_iolist_to_chars(Cs,Limit - 1,S,Mode)];
limit_iolist_to_chars([I| Cs],Limit,S,Mode) ->
    limit_iolist_to_chars(I,Limit,[Cs| S],Mode);
limit_iolist_to_chars([],_Limit,[],_Mode) ->
    [];
limit_iolist_to_chars([],Limit,[Cs| S],Mode) ->
    limit_iolist_to_chars(Cs,Limit,S,Mode);
limit_iolist_to_chars(B,Limit,S,Mode)
    when is_binary(B)->
    case byte_size(B) of
        Sz
            when Sz > Limit->
            {B1,B2} = split_binary(B,Limit),
            [binary_to_list(B1)| limit_iolist_to_chars(B2,0,S,Mode)];
        Sz->
            [binary_to_list(B)| limit_iolist_to_chars([],Limit - Sz,S,Mode)]
    end.

cdata_to_chars(Cs,F,CharsLimit)
    when CharsLimit < 0;
    CharsLimit >= F->
    cdata_to_chars(Cs);
cdata_to_chars(Cs,_,CharsLimit) ->
    limit_cdata_to_chars(Cs,sub(CharsLimit,3),normal).

cdata_to_chars([C| Cs])
    when is_integer(C),
    C >= $\\->
    [C| cdata_to_chars(Cs)];
cdata_to_chars([I| Cs]) ->
    [cdata_to_chars(I)| cdata_to_chars(Cs)];
cdata_to_chars([]) ->
    [];
cdata_to_chars(B)
    when is_binary(B)->
    case  catch unicode:characters_to_list(B) of
        L
            when is_list(L)->
            L;
        _->
            binary_to_list(B)
    end.

limit_cdata_to_chars(Cs,0,normal) ->
    L = limit_cdata_to_chars(Cs,4,final),
    case string:length(L) of
        N
            when N < 4->
            L;
        4->
            "..."
    end;
limit_cdata_to_chars(_Cs,0,final) ->
    [];
limit_cdata_to_chars(Cs,Limit,Mode) ->
    case string:next_grapheme(Cs) of
        {error,<<C,Cs1/binary>>}->
            [C| limit_cdata_to_chars(Cs1,Limit - 1,Mode)];
        {error,[C| Cs1]}->
            [C| limit_cdata_to_chars(Cs1,Limit - 1,Mode)];
        []->
            [];
        [GC| Cs1]->
            [GC| limit_cdata_to_chars(Cs1,Limit - 1,Mode)]
    end.

limit_field(F,CharsLimit)
    when CharsLimit < 0;
    F =:= none->
    F;
limit_field(F,CharsLimit) ->
    max(3,min(F,CharsLimit)).

string(S,none,_Adj,none,_Pad,_Enc) ->
    S;
string(S,F,Adj,none,Pad,Enc) ->
    string_field(S,F,Adj,io_lib:chars_length(S),Pad,Enc);
string(S,none,_Adj,P,Pad,Enc) ->
    string_field(S,P,left,io_lib:chars_length(S),Pad,Enc);
string(S,F,Adj,P,Pad,Enc)
    when F >= P->
    N = io_lib:chars_length(S),
    if F > P ->
        if N > P ->
            adjust(flat_trunc(S,P,Enc),chars(Pad,F - P),Adj);N < P ->
            adjust([S| chars(Pad,P - N)],chars(Pad,F - P),Adj);true ->
            adjust(S,chars(Pad,F - P),Adj) end;true ->
        string_field(S,F,Adj,N,Pad,Enc) end.

string_field(S,F,_Adj,N,_Pad,Enc)
    when N > F->
    flat_trunc(S,F,Enc);
string_field(S,F,Adj,N,Pad,_Enc)
    when N < F->
    adjust(S,chars(Pad,F - N),Adj);
string_field(S,_,_,_,_,_) ->
    S.

unprefixed_integer(Int,F,Adj,Base,Pad,Lowercase)
    when Base >= 2,
    Base =< 1 + $Z - $A + 10->
    if Int < 0 ->
        S = cond_lowercase(integer_to_list(-Int,Base),Lowercase),
        term([$-| S],F,Adj,none,Pad);true ->
        S = cond_lowercase(integer_to_list(Int,Base),Lowercase),
        term(S,F,Adj,none,Pad) end.

prefixed_integer(Int,F,Adj,Base,Pad,Prefix,Lowercase)
    when Base >= 2,
    Base =< 1 + $Z - $A + 10->
    if Int < 0 ->
        S = cond_lowercase(integer_to_list(-Int,Base),Lowercase),
        term([$-, Prefix| S],F,Adj,none,Pad);true ->
        S = cond_lowercase(integer_to_list(Int,Base),Lowercase),
        term([Prefix| S],F,Adj,none,Pad) end.

char(C,none,_Adj,none,_Pad) ->
    [C];
char(C,F,_Adj,none,_Pad) ->
    chars(C,F);
char(C,none,_Adj,P,_Pad) ->
    chars(C,P);
char(C,F,Adj,P,Pad)
    when F >= P->
    adjust(chars(C,P),chars(Pad,F - P),Adj).

newline(none,_Adj,_P,_Pad) ->
    "\n";
newline(F,right,_P,_Pad) ->
    chars($\n,F).

adjust(Data,[],_) ->
    Data;
adjust(Data,Pad,left) ->
    [Data| Pad];
adjust(Data,Pad,right) ->
    [Pad| Data].

flat_trunc(List,N,latin1)
    when is_integer(N),
    N >= 0->
    {S,_} = lists:split(N,lists:flatten(List)),
    S;
flat_trunc(List,N,unicode)
    when is_integer(N),
    N >= 0->
    string:slice(List,0,N).

chars(_C,0) ->
    [];
chars(C,1) ->
    [C];
chars(C,2) ->
    [C, C];
chars(C,3) ->
    [C, C, C];
chars(C,N)
    when is_integer(N),
    N band 1 =:= 0->
    S = chars(C,N bsr 1),
    [S| S];
chars(C,N)
    when is_integer(N)->
    S = chars(C,N bsr 1),
    [C, S| S].

cond_lowercase(String,true) ->
    lowercase(String);
cond_lowercase(String,false) ->
    String.

lowercase([H| T])
    when is_integer(H),
    H >= $A,
    H =< $Z->
    [H - $A + $a| lowercase(T)];
lowercase([H| T]) ->
    [H| lowercase(T)];
lowercase([]) ->
    [].

sub(T,_)
    when T < 0->
    T;
sub(T,E)
    when T >= E->
    T - E;
sub(_,_) ->
    0.

get_option(Key,TupleList,Default) ->
    case lists:keyfind(Key,1,TupleList) of
        false->
            Default;
        {Key,Value}->
            Value;
        _->
            Default
    end.