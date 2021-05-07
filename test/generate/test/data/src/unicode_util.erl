-file("unicode_util.erl", 1).

-module(unicode_util).

-export([cp/1, gc/1]).

-export([nfd/1, nfc/1, nfkd/1, nfkc/1]).

-export([whitespace/0, is_whitespace/1]).

-export([uppercase/1, lowercase/1, titlecase/1, casefold/1]).

-export([spec_version/0, lookup/1, get_case/1]).

-inline([{class,1}]).

-compile(nowarn_unused_vars).

-dialyzer({no_improper_lists,[{cp,1}, {gc,1}, {gc_prepend,2}]}).

-type(gc()::char()|[char()]).

-spec(lookup(char()) -> #{canon := [{byte(),char()}],ccc := byte(),compat := []|{atom(),[{byte(),char()}]}}).

lookup(Codepoint) ->
    {CCC,Can,Comp} = unicode_table(Codepoint),
    #{ccc=>CCC,canon=>Can,compat=>Comp}.

-spec(get_case(char()) -> #{fold := gc(),lower := gc(),title := gc(),upper := gc()}).

get_case(Codepoint) ->
    case case_table(Codepoint) of
        {U,L}->
            #{upper=>U,lower=>L,title=>U,fold=>L};
        {U,L,T,F}->
            #{upper=>U,lower=>L,title=>T,fold=>F}
    end.

spec_version() ->
    {12,1}.

class(Codepoint) ->
    {CCC,_,_} = unicode_table(Codepoint),
    CCC.

-spec(uppercase(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())).

uppercase(Str0) ->
    case cp(Str0) of
        [CP| Str] = Str1->
            case case_table(CP) of
                {Upper,_}->
                    [Upper| Str];
                {Upper,_,_,_}->
                    [Upper| Str]
            end;
        []->
            [];
        {error,Err}->
            error({badarg,Err})
    end.

-spec(lowercase(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())).

lowercase(Str0) ->
    case cp(Str0) of
        [CP| Str] = Str1->
            case case_table(CP) of
                {_,Lower}->
                    [Lower| Str];
                {_,Lower,_,_}->
                    [Lower| Str]
            end;
        []->
            [];
        {error,Err}->
            error({badarg,Err})
    end.

-spec(titlecase(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())).

titlecase(Str0) ->
    case cp(Str0) of
        [CP| Str] = Str1->
            case case_table(CP) of
                {_,_,Title,_}->
                    [Title| Str];
                {Upper,_}->
                    [Upper| Str]
            end;
        []->
            [];
        {error,Err}->
            error({badarg,Err})
    end.

-spec(casefold(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())).

casefold(Str0) ->
    case cp(Str0) of
        [CP| Str] = Str1->
            case case_table(CP) of
                {_,_,_,Fold}->
                    [Fold| Str];
                {_,Lower}->
                    [Lower| Str]
            end;
        []->
            [];
        {error,Err}->
            error({badarg,Err})
    end.

-spec(nfd(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())|{error,unicode:chardata()}).

nfd(Str0) ->
    case gc(Str0) of
        [GC| R]
            when GC < 128->
            [GC| R];
        [GC| Str]->
            [decompose(GC)| Str];
        []->
            [];
        {error,_} = Error->
            Error
    end.

-spec(nfkd(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())|{error,unicode:chardata()}).

nfkd(Str0) ->
    case gc(Str0) of
        [GC| R]
            when GC < 128->
            [GC| R];
        [GC| Str]->
            [decompose_compat(GC)| Str];
        []->
            [];
        {error,_} = Error->
            Error
    end.

-spec(nfc(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())|{error,unicode:chardata()}).

nfc(Str0) ->
    case gc(Str0) of
        [GC| R]
            when GC < 256->
            [GC| R];
        [GC| Str]->
            [compose(decompose(GC))| Str];
        []->
            [];
        {error,_} = Error->
            Error
    end.

-spec(nfkc(unicode:chardata()) -> maybe_improper_list(gc(),unicode:chardata())|{error,unicode:chardata()}).

nfkc(Str0) ->
    case gc(Str0) of
        [GC| R]
            when GC < 128->
            [GC| R];
        [GC| Str]->
            [compose_compat_0(decompose_compat(GC))| Str];
        []->
            [];
        {error,_} = Error->
            Error
    end.

decompose(CP)
    when is_integer(CP),
    CP < 44032,
    55203 > CP->
    case unicode_table(CP) of
        {_,[],_}->
            CP;
        {_,CPs,_}->
            canonical_order(CPs)
    end;
decompose(CP) ->
    canonical_order(decompose_1(CP)).

decompose_1(CP)
    when 44032 =< CP,
    CP =< 55203->
    Syll = CP - 44032,
    T = 28,
    N = 588,
    Lead = 4352 + Syll div N,
    Vowel = 4449 + Syll rem N div T,
    case Syll rem T of
        0->
            [{0,Lead}, {0,Vowel}];
        Trail->
            [{0,Lead}, {0,Vowel}, {0,Trail + 4519}]
    end;
decompose_1(CP)
    when is_integer(CP)->
    case unicode_table(CP) of
        {CCC,[],_}->
            [{CCC,CP}];
        {_,CPs,_}->
            CPs
    end;
decompose_1([CP| CPs]) ->
    decompose_1(CP) ++ decompose_1(CPs);
decompose_1([]) ->
    [].

canonical_order([{_,CP}]) ->
    CP;
canonical_order(CPs) ->
    canonical_order_1(CPs).

canonical_order_1([{0,CP}| TaggedCPs]) ->
    [CP| canonical_order_1(TaggedCPs)];
canonical_order_1([_| _] = TaggedCPs) ->
    canonical_order_2(TaggedCPs,[]);
canonical_order_1([]) ->
    [].

canonical_order_2([{CCC,_} = First| Cont],Seq)
    when CCC > 0->
    canonical_order_2(Cont,[First| Seq]);
canonical_order_2(Cont,Seq) ->
    [CP || {_,CP} <- lists:keysort(1,lists:reverse(Seq))] ++ canonical_order_1(Cont).

decompose_compat(CP)
    when is_integer(CP),
    CP < 44032,
    55203 > CP->
    case unicode_table(CP) of
        {_,[],[]}->
            CP;
        {_,_,{_,CPs}}->
            canonical_order(CPs);
        {_,CPs,_}->
            canonical_order(CPs)
    end;
decompose_compat(CP) ->
    canonical_order(decompose_compat_1(CP)).

decompose_compat_1(CP)
    when 44032 =< CP,
    CP =< 55203->
    Syll = CP - 44032,
    T = 28,
    N = 588,
    Lead = 4352 + Syll div N,
    Vowel = 4449 + Syll rem N div T,
    case Syll rem T of
        0->
            [{0,Lead}, {0,Vowel}];
        Trail->
            [{0,Lead}, {0,Vowel}, {0,Trail + 4519}]
    end;
decompose_compat_1(CP)
    when is_integer(CP)->
    case unicode_table(CP) of
        {CCC,[],[]}->
            [{CCC,CP}];
        {_,_,{_,CPs}}->
            CPs;
        {_,CPs,_}->
            CPs
    end;
decompose_compat_1([CP| CPs]) ->
    decompose_compat_1(CP) ++ decompose_compat_1(CPs);
decompose_compat_1([]) ->
    [].

compose(CP)
    when is_integer(CP)->
    CP;
compose([Lead, Vowel| Trail])
    when 4352 =< Lead,
    Lead =< 4370->
    if 4449 =< Vowel,
    Vowel =< 4469 ->
        CP = 44032 + (Lead - 4352) * 588 + (Vowel - 4449) * 28,
        case Trail of
            [T| Acc]
                when 4519 =< T,
                T =< 4546->
                nolist(CP + T - 4519,Acc);
            Acc->
                nolist(CP,Acc)
        end;true ->
        case compose([Vowel| Trail]) of
            [_| _] = CPs->
                [Lead| CPs];
            CP->
                [Lead, CP]
        end end;
compose([Base, Accent] = GC0) ->
    case compose_pair(Base,Accent) of
        false->
            GC0;
        GC->
            GC
    end;
compose([CP| Many]) ->
    compose_many(Many,CP,[],class(CP)).

compose_many([CP| Rest],Base,Accents,Prev) ->
    Class = class(CP),
    case (Prev =:= 0 orelse Prev < Class) andalso compose_pair(Base,CP) of
        false->
            compose_many(Rest,Base,[CP| Accents],Class);
        Combined->
            compose_many(Rest,Combined,Accents,Prev)
    end;
compose_many([],Base,[],Prev) ->
    Base;
compose_many([],Base,Accents,Prev) ->
    [Base| lists:reverse(Accents)].

compose_compat_0(CP)
    when is_integer(CP)->
    CP;
compose_compat_0(L) ->
    case gc(L) of
        [First| Rest]->
            case compose_compat(First) of
                [_| _] = GC->
                    GC ++ compose_compat_0(Rest);
                CP->
                    [CP| compose_compat_0(Rest)]
            end;
        []->
            []
    end.

compose_compat(CP)
    when is_integer(CP)->
    CP;
compose_compat([Lead, Vowel| Trail])
    when 4352 =< Lead,
    Lead =< 4370->
    if 4449 =< Vowel,
    Vowel =< 4469 ->
        CP = 44032 + (Lead - 4352) * 588 + (Vowel - 4449) * 28,
        case Trail of
            [T| Acc]
                when 4519 =< T,
                T =< 4546->
                nolist(CP + T - 4519,Acc);
            Acc->
                nolist(CP,Acc)
        end;true ->
        case compose_compat([Vowel| Trail]) of
            [_| _] = CPs->
                [Lead| CPs];
            CP->
                [Lead, CP]
        end end;
compose_compat([Base, Accent] = GC0) ->
    case compose_pair(Base,Accent) of
        false->
            GC0;
        GC->
            GC
    end;
compose_compat([CP| Many]) ->
    compose_compat_many(Many,CP,[],class(CP)).

compose_compat_many([CP| Rest],Base,Accents,Prev) ->
    Class = class(CP),
    case (Prev =:= 0 orelse Prev < Class) andalso compose_pair(Base,CP) of
        false->
            compose_compat_many(Rest,Base,[CP| Accents],Class);
        Combined->
            compose_compat_many(Rest,Combined,Accents,Prev)
    end;
compose_compat_many([],Base,[],Prev) ->
    Base;
compose_compat_many([],Base,Accents,Prev) ->
    [Base| lists:reverse(Accents)].

-spec(whitespace() -> [gc()]).

whitespace() ->
    [[13, 10], 9, 10, 11, 12, 13, 32, 133, 8206, 8207, 8232, 8233].

-spec(is_whitespace(gc()) -> boolean()).

is_whitespace([13, 10]) ->
    true;
is_whitespace(9) ->
    true;
is_whitespace(10) ->
    true;
is_whitespace(11) ->
    true;
is_whitespace(12) ->
    true;
is_whitespace(13) ->
    true;
is_whitespace(32) ->
    true;
is_whitespace(133) ->
    true;
is_whitespace(8206) ->
    true;
is_whitespace(8207) ->
    true;
is_whitespace(8232) ->
    true;
is_whitespace(8233) ->
    true;
is_whitespace(_) ->
    false.

-spec(cp(String::unicode:chardata()) -> maybe_improper_list()|{error,unicode:chardata()}).

cp([C| _] = L)
    when is_integer(C)->
    L;
cp([List]) ->
    cp(List);
cp([List| R]) ->
    cpl(List,R);
cp([]) ->
    [];
cp(<<C/utf8,R/binary>>) ->
    [C| R];
cp(<<>>) ->
    [];
cp(<<R/binary>>) ->
    {error,R}.

cpl([C],R)
    when is_integer(C)->
    [C| cpl_1_cont(R)];
cpl([C| T],R)
    when is_integer(C)->
    [C| cpl_cont(T,R)];
cpl([List],R) ->
    cpl(List,R);
cpl([List| T],R) ->
    cpl(List,[T| R]);
cpl([],R) ->
    cp(R);
cpl(<<C/utf8,T/binary>>,R) ->
    [C, T| R];
cpl(<<>>,R) ->
    cp(R);
cpl(<<B/binary>>,R) ->
    {error,[B| R]}.

cpl_cont([C| T],R)
    when is_integer(C)->
    [C| cpl_cont2(T,R)];
cpl_cont([L],R) ->
    cpl_cont(L,R);
cpl_cont([L| T],R) ->
    cpl_cont(L,[T| R]);
cpl_cont([],R) ->
    cpl_1_cont(R);
cpl_cont(T,R) ->
    [T| R].

cpl_cont2([C| T],R)
    when is_integer(C)->
    [C| cpl_cont3(T,R)];
cpl_cont2([L],R) ->
    cpl_cont2(L,R);
cpl_cont2([L| T],R) ->
    cpl_cont2(L,[T| R]);
cpl_cont2([],R) ->
    cpl_1_cont2(R);
cpl_cont2(T,R) ->
    [T| R].

cpl_cont3([C],R)
    when is_integer(C)->
    [C| R];
cpl_cont3([C| T],R)
    when is_integer(C)->
    [C, T| R];
cpl_cont3([L],R) ->
    cpl_cont3(L,R);
cpl_cont3([L| T],R) ->
    cpl_cont3(L,[T| R]);
cpl_cont3([],R) ->
    cpl_1_cont3(R);
cpl_cont3(T,R) ->
    [T| R].

cpl_1_cont([C| T])
    when is_integer(C)->
    [C| cpl_1_cont2(T)];
cpl_1_cont([L]) ->
    cpl_1_cont(L);
cpl_1_cont([L| T]) ->
    cpl_cont(L,T);
cpl_1_cont(T) ->
    T.

cpl_1_cont2([C| T])
    when is_integer(C)->
    [C| cpl_1_cont3(T)];
cpl_1_cont2([L]) ->
    cpl_1_cont2(L);
cpl_1_cont2([L| T]) ->
    cpl_cont2(L,T);
cpl_1_cont2(T) ->
    T.

cpl_1_cont3([C| _] = T)
    when is_integer(C)->
    T;
cpl_1_cont3([L]) ->
    cpl_1_cont3(L);
cpl_1_cont3([L| T]) ->
    cpl_cont3(L,T);
cpl_1_cont3(T) ->
    T.

cp_no_bin([C| _] = L)
    when is_integer(C)->
    L;
cp_no_bin([List]) ->
    cp_no_bin(List);
cp_no_bin([List| R]) ->
    cp_no_binl(List,R);
cp_no_bin([]) ->
    [];
cp_no_bin(_) ->
    binary_found.

cp_no_binl([C],R)
    when is_integer(C)->
    [C| cpl_1_cont(R)];
cp_no_binl([C| T],R)
    when is_integer(C)->
    [C| cpl_cont(T,R)];
cp_no_binl([List],R) ->
    cp_no_binl(List,R);
cp_no_binl([List| T],R) ->
    cp_no_binl(List,[T| R]);
cp_no_binl([],R) ->
    cp_no_bin(R);
cp_no_binl(_,_) ->
    binary_found.

-spec(gc(String::unicode:chardata()) -> maybe_improper_list()|{error,unicode:chardata()}).

gc([] = R) ->
    R;
gc([CP] = R)
    when is_integer(CP)->
    R;
gc([$\r = CP| R0]) ->
    case cp(R0) of
        [$\n| R1]->
            [[$\r, $\n]| R1];
        T->
            [CP| T]
    end;
gc([CP1| T1] = T)
    when CP1 < 256->
    case T1 of
        [CP2| _]
            when CP2 < 256->
            T;
        _->
            case cp_no_bin(T1) of
                [CP2| _] = T3
                    when CP2 < 256->
                    [CP1| T3];
                binary_found->
                    gc_1(T);
                T4->
                    gc_1([CP1| T4])
            end
    end;
gc(<<>>) ->
    [];
gc(<<CP1/utf8,Rest/binary>>) ->
    if CP1 < 256,
    CP1 =/= $\r ->
        case Rest of
            <<CP2/utf8,_/binary>>
                when CP2 < 256->
                [CP1| Rest];
            _->
                gc_1([CP1| Rest])
        end;true ->
        gc_1([CP1| Rest]) end;
gc([CP| _] = T)
    when is_integer(CP)->
    gc_1(T);
gc(Str) ->
    case cp(Str) of
        {error,_} = Error->
            Error;
        CPs->
            gc(CPs)
    end.

gc_1([$\r| R0] = R) ->
    case cp(R0) of
        [$\n| R1]->
            [[$\r, $\n]| R1];
        _->
            R
    end;
gc_1([0 = CP| R1] = R0) ->
    R0;
gc_1([1 = CP| R1] = R0) ->
    R0;
gc_1([2 = CP| R1] = R0) ->
    R0;
gc_1([3 = CP| R1] = R0) ->
    R0;
gc_1([4 = CP| R1] = R0) ->
    R0;
gc_1([5 = CP| R1] = R0) ->
    R0;
gc_1([6 = CP| R1] = R0) ->
    R0;
gc_1([7 = CP| R1] = R0) ->
    R0;
gc_1([8 = CP| R1] = R0) ->
    R0;
gc_1([9 = CP| R1] = R0) ->
    R0;
gc_1([10 = CP| R1] = R0) ->
    R0;
gc_1([11 = CP| R1] = R0) ->
    R0;
gc_1([12 = CP| R1] = R0) ->
    R0;
gc_1([14 = CP| R1] = R0) ->
    R0;
gc_1([15 = CP| R1] = R0) ->
    R0;
gc_1([16 = CP| R1] = R0) ->
    R0;
gc_1([17 = CP| R1] = R0) ->
    R0;
gc_1([18 = CP| R1] = R0) ->
    R0;
gc_1([19 = CP| R1] = R0) ->
    R0;
gc_1([20 = CP| R1] = R0) ->
    R0;
gc_1([21 = CP| R1] = R0) ->
    R0;
gc_1([22 = CP| R1] = R0) ->
    R0;
gc_1([23 = CP| R1] = R0) ->
    R0;
gc_1([24 = CP| R1] = R0) ->
    R0;
gc_1([25 = CP| R1] = R0) ->
    R0;
gc_1([26 = CP| R1] = R0) ->
    R0;
gc_1([27 = CP| R1] = R0) ->
    R0;
gc_1([28 = CP| R1] = R0) ->
    R0;
gc_1([29 = CP| R1] = R0) ->
    R0;
gc_1([30 = CP| R1] = R0) ->
    R0;
gc_1([31 = CP| R1] = R0) ->
    R0;
gc_1([127 = CP| R1] = R0) ->
    R0;
gc_1([128 = CP| R1] = R0) ->
    R0;
gc_1([129 = CP| R1] = R0) ->
    R0;
gc_1([130 = CP| R1] = R0) ->
    R0;
gc_1([131 = CP| R1] = R0) ->
    R0;
gc_1([132 = CP| R1] = R0) ->
    R0;
gc_1([133 = CP| R1] = R0) ->
    R0;
gc_1([134 = CP| R1] = R0) ->
    R0;
gc_1([135 = CP| R1] = R0) ->
    R0;
gc_1([136 = CP| R1] = R0) ->
    R0;
gc_1([137 = CP| R1] = R0) ->
    R0;
gc_1([138 = CP| R1] = R0) ->
    R0;
gc_1([139 = CP| R1] = R0) ->
    R0;
gc_1([140 = CP| R1] = R0) ->
    R0;
gc_1([141 = CP| R1] = R0) ->
    R0;
gc_1([142 = CP| R1] = R0) ->
    R0;
gc_1([143 = CP| R1] = R0) ->
    R0;
gc_1([144 = CP| R1] = R0) ->
    R0;
gc_1([145 = CP| R1] = R0) ->
    R0;
gc_1([146 = CP| R1] = R0) ->
    R0;
gc_1([147 = CP| R1] = R0) ->
    R0;
gc_1([148 = CP| R1] = R0) ->
    R0;
gc_1([149 = CP| R1] = R0) ->
    R0;
gc_1([150 = CP| R1] = R0) ->
    R0;
gc_1([151 = CP| R1] = R0) ->
    R0;
gc_1([152 = CP| R1] = R0) ->
    R0;
gc_1([153 = CP| R1] = R0) ->
    R0;
gc_1([154 = CP| R1] = R0) ->
    R0;
gc_1([155 = CP| R1] = R0) ->
    R0;
gc_1([156 = CP| R1] = R0) ->
    R0;
gc_1([157 = CP| R1] = R0) ->
    R0;
gc_1([158 = CP| R1] = R0) ->
    R0;
gc_1([159 = CP| R1] = R0) ->
    R0;
gc_1([173 = CP| R1] = R0) ->
    R0;
gc_1([169 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([174 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R] = R0)
    when CP < 256->
    case R of
        [CP2| _]
            when CP2 < 256->
            R0;
        _->
            gc_extend(cp(R),R,CP)
    end;
gc_1([1564 = CP| R1] = R0) ->
    R0;
gc_1([6158 = CP| R1] = R0) ->
    R0;
gc_1([8203 = CP| R1] = R0) ->
    R0;
gc_1([CP| R1] = R0)
    when 8206 =< CP,
    CP =< 8207->
    R0;
gc_1([CP| R1] = R0)
    when 8232 =< CP,
    CP =< 8238->
    R0;
gc_1([CP| R1] = R0)
    when 8288 =< CP,
    CP =< 8303->
    R0;
gc_1([65279 = CP| R1] = R0) ->
    R0;
gc_1([CP| R1] = R0)
    when 65520 =< CP,
    CP =< 65531->
    R0;
gc_1([CP| R1] = R0)
    when 78896 =< CP,
    CP =< 78904->
    R0;
gc_1([CP| R1] = R0)
    when 113824 =< CP,
    CP =< 113827->
    R0;
gc_1([CP| R1] = R0)
    when 119155 =< CP,
    CP =< 119162->
    R0;
gc_1([CP| R1] = R0)
    when 917504 =< CP,
    CP =< 917535->
    R0;
gc_1([CP| R1] = R0)
    when 917632 =< CP,
    CP =< 917759->
    R0;
gc_1([CP| R1] = R0)
    when 918000 =< CP,
    CP =< 921599->
    R0;
gc_1([1757 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([1807 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([2274 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([3406 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([69821 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([69837 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([72250 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([73030 = CP| R1] = R0) ->
    gc_prepend(R1,CP);
gc_1([CP| R1] = R0)
    when 1536 =< CP,
    CP =< 1541->
    gc_prepend(R1,CP);
gc_1([CP| R1] = R0)
    when 70082 =< CP,
    CP =< 70083->
    gc_prepend(R1,CP);
gc_1([CP| R1] = R0)
    when 72324 =< CP,
    CP =< 72329->
    gc_prepend(R1,CP);
gc_1([CP| R1] = R0)
    when 4352 =< CP,
    CP =< 4447->
    gc_h_L(R1,[CP]);
gc_1([CP| R1] = R0)
    when 43360 =< CP,
    CP =< 43388->
    gc_h_L(R1,[CP]);
gc_1([CP| R1] = R0)
    when 4448 =< CP,
    CP =< 4519->
    gc_h_V(R1,[CP]);
gc_1([CP| R1] = R0)
    when 55216 =< CP,
    CP =< 55238->
    gc_h_V(R1,[CP]);
gc_1([CP| R1] = R0)
    when 4520 =< CP,
    CP =< 4607->
    gc_h_T(R1,[CP]);
gc_1([CP| R1] = R0)
    when 55243 =< CP,
    CP =< 55291->
    gc_h_T(R1,[CP]);
gc_1([CP| _] = R0)
    when 44000 < CP,
    CP < 56000->
    gc_h_lv_lvt(R0,R0,[]);
gc_1([CP| R1] = R0)
    when 127462 =< CP,
    CP =< 127487->
    gc_regional(R1,CP);
gc_1([8252 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([8265 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([8482 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([8505 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([9000 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([9096 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([9167 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([9410 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([9654 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([9664 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10004 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10006 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10013 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10017 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10024 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10052 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10055 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10060 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10062 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10071 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10145 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10160 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([10175 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([11088 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([11093 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([12336 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([12349 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([12951 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([12953 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([127279 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([127374 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([127514 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([127535 = CP| R1] = R0) ->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127340 =< CP,
    CP =< 127345->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9872 =< CP,
    CP =< 9989->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9642 =< CP,
    CP =< 9643->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 8986 =< CP,
    CP =< 8987->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 8596 =< CP,
    CP =< 8601->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 8617 =< CP,
    CP =< 8618->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9193 =< CP,
    CP =< 9203->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9208 =< CP,
    CP =< 9210->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9735 =< CP,
    CP =< 9746->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9723 =< CP,
    CP =< 9726->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9728 =< CP,
    CP =< 9733->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9748 =< CP,
    CP =< 9861->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 10548 =< CP,
    CP =< 10549->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 10067 =< CP,
    CP =< 10069->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 9992 =< CP,
    CP =< 10002->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 10035 =< CP,
    CP =< 10036->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 10083 =< CP,
    CP =< 10087->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 10133 =< CP,
    CP =< 10135->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 126976 =< CP,
    CP =< 127231->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 11013 =< CP,
    CP =< 11015->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 11035 =< CP,
    CP =< 11036->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127245 =< CP,
    CP =< 127247->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 128884 =< CP,
    CP =< 128895->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127548 =< CP,
    CP =< 127551->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127405 =< CP,
    CP =< 127461->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127358 =< CP,
    CP =< 127359->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127377 =< CP,
    CP =< 127386->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127489 =< CP,
    CP =< 127503->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127538 =< CP,
    CP =< 127546->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 128326 =< CP,
    CP =< 128591->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 127561 =< CP,
    CP =< 127994->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 128000 =< CP,
    CP =< 128317->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 128640 =< CP,
    CP =< 128767->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129160 =< CP,
    CP =< 129167->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129096 =< CP,
    CP =< 129103->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 128981 =< CP,
    CP =< 129023->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129036 =< CP,
    CP =< 129039->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129114 =< CP,
    CP =< 129119->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129340 =< CP,
    CP =< 129349->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129198 =< CP,
    CP =< 129279->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129292 =< CP,
    CP =< 129338->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R1] = R0)
    when 129351 =< CP,
    CP =< 131069->
    gc_ext_pict(R1,[CP]);
gc_1([CP| R]) ->
    gc_extend(cp(R),R,CP).

gc_prepend(R00,CP0) ->
    case cp(R00) of
        [CP1| _] = R0->
            case is_control(CP1) of
                true->
                    [CP0| R00];
                false->
                    case gc_1(R0) of
                        [GC| R1]
                            when is_integer(GC)->
                            [[CP0, GC]| R1];
                        [GC| R1]->
                            [[CP0| GC]| R1]
                    end
            end;
        []->
            [CP0];
        {error,R}->
            [CP0| R]
    end.

is_control(173) ->
    true;
is_control(1564) ->
    true;
is_control(6158) ->
    true;
is_control(8203) ->
    true;
is_control(65279) ->
    true;
is_control(CP)
    when 78896 =< CP,
    CP =< 78904->
    true;
is_control(CP)
    when 8232 =< CP,
    CP =< 8238->
    true;
is_control(CP)
    when 0 =< CP,
    CP =< 31->
    true;
is_control(CP)
    when 127 =< CP,
    CP =< 159->
    true;
is_control(CP)
    when 8206 =< CP,
    CP =< 8207->
    true;
is_control(CP)
    when 8288 =< CP,
    CP =< 8303->
    true;
is_control(CP)
    when 65520 =< CP,
    CP =< 65531->
    true;
is_control(CP)
    when 917504 =< CP,
    CP =< 917535->
    true;
is_control(CP)
    when 113824 =< CP,
    CP =< 113827->
    true;
is_control(CP)
    when 119155 =< CP,
    CP =< 119162->
    true;
is_control(CP)
    when 917632 =< CP,
    CP =< 917759->
    true;
is_control(CP)
    when 918000 =< CP,
    CP =< 921599->
    true;
is_control(_) ->
    false.

gc_extend([CP| T],T0,CP0) ->
    case is_extend(CP) of
        false->
            [CP0| T0];
        _TrueOrZWJ->
            gc_extend2(cp(T),T,[CP, CP0])
    end;
gc_extend([],_,CP) ->
    [CP];
gc_extend({error,R},_,CP) ->
    [CP| R].

gc_extend2([CP| T],T0,Acc) ->
    case is_extend(CP) of
        false->
            [lists:reverse(Acc)| T0];
        _TrueOrZWJ->
            gc_extend2(cp(T),T,[CP| Acc])
    end;
gc_extend2([],_,Acc) ->
    [lists:reverse(Acc)];
gc_extend2({error,R},_,Acc) ->
    [lists:reverse(Acc)] ++ [R].

is_extend(768) ->
    true;
is_extend(769) ->
    true;
is_extend(770) ->
    true;
is_extend(771) ->
    true;
is_extend(772) ->
    true;
is_extend(773) ->
    true;
is_extend(774) ->
    true;
is_extend(775) ->
    true;
is_extend(776) ->
    true;
is_extend(777) ->
    true;
is_extend(778) ->
    true;
is_extend(779) ->
    true;
is_extend(780) ->
    true;
is_extend(781) ->
    true;
is_extend(782) ->
    true;
is_extend(783) ->
    true;
is_extend(784) ->
    true;
is_extend(785) ->
    true;
is_extend(786) ->
    true;
is_extend(787) ->
    true;
is_extend(788) ->
    true;
is_extend(789) ->
    true;
is_extend(790) ->
    true;
is_extend(791) ->
    true;
is_extend(792) ->
    true;
is_extend(793) ->
    true;
is_extend(794) ->
    true;
is_extend(795) ->
    true;
is_extend(796) ->
    true;
is_extend(797) ->
    true;
is_extend(798) ->
    true;
is_extend(799) ->
    true;
is_extend(800) ->
    true;
is_extend(801) ->
    true;
is_extend(802) ->
    true;
is_extend(803) ->
    true;
is_extend(804) ->
    true;
is_extend(805) ->
    true;
is_extend(806) ->
    true;
is_extend(807) ->
    true;
is_extend(808) ->
    true;
is_extend(809) ->
    true;
is_extend(810) ->
    true;
is_extend(811) ->
    true;
is_extend(812) ->
    true;
is_extend(813) ->
    true;
is_extend(814) ->
    true;
is_extend(815) ->
    true;
is_extend(816) ->
    true;
is_extend(817) ->
    true;
is_extend(818) ->
    true;
is_extend(819) ->
    true;
is_extend(820) ->
    true;
is_extend(821) ->
    true;
is_extend(822) ->
    true;
is_extend(823) ->
    true;
is_extend(824) ->
    true;
is_extend(825) ->
    true;
is_extend(826) ->
    true;
is_extend(827) ->
    true;
is_extend(828) ->
    true;
is_extend(829) ->
    true;
is_extend(830) ->
    true;
is_extend(831) ->
    true;
is_extend(832) ->
    true;
is_extend(833) ->
    true;
is_extend(834) ->
    true;
is_extend(835) ->
    true;
is_extend(836) ->
    true;
is_extend(837) ->
    true;
is_extend(838) ->
    true;
is_extend(839) ->
    true;
is_extend(840) ->
    true;
is_extend(841) ->
    true;
is_extend(842) ->
    true;
is_extend(843) ->
    true;
is_extend(844) ->
    true;
is_extend(845) ->
    true;
is_extend(846) ->
    true;
is_extend(847) ->
    true;
is_extend(848) ->
    true;
is_extend(849) ->
    true;
is_extend(850) ->
    true;
is_extend(851) ->
    true;
is_extend(852) ->
    true;
is_extend(853) ->
    true;
is_extend(854) ->
    true;
is_extend(855) ->
    true;
is_extend(856) ->
    true;
is_extend(857) ->
    true;
is_extend(858) ->
    true;
is_extend(859) ->
    true;
is_extend(860) ->
    true;
is_extend(861) ->
    true;
is_extend(862) ->
    true;
is_extend(863) ->
    true;
is_extend(864) ->
    true;
is_extend(865) ->
    true;
is_extend(866) ->
    true;
is_extend(867) ->
    true;
is_extend(868) ->
    true;
is_extend(869) ->
    true;
is_extend(870) ->
    true;
is_extend(871) ->
    true;
is_extend(872) ->
    true;
is_extend(873) ->
    true;
is_extend(874) ->
    true;
is_extend(875) ->
    true;
is_extend(876) ->
    true;
is_extend(877) ->
    true;
is_extend(878) ->
    true;
is_extend(879) ->
    true;
is_extend(1155) ->
    true;
is_extend(1156) ->
    true;
is_extend(1157) ->
    true;
is_extend(1158) ->
    true;
is_extend(1159) ->
    true;
is_extend(1160) ->
    true;
is_extend(1161) ->
    true;
is_extend(1425) ->
    true;
is_extend(1426) ->
    true;
is_extend(1427) ->
    true;
is_extend(1428) ->
    true;
is_extend(1429) ->
    true;
is_extend(1430) ->
    true;
is_extend(1431) ->
    true;
is_extend(1432) ->
    true;
is_extend(1433) ->
    true;
is_extend(1434) ->
    true;
is_extend(1435) ->
    true;
is_extend(1436) ->
    true;
is_extend(1437) ->
    true;
is_extend(1438) ->
    true;
is_extend(1439) ->
    true;
is_extend(1440) ->
    true;
is_extend(1441) ->
    true;
is_extend(1442) ->
    true;
is_extend(1443) ->
    true;
is_extend(1444) ->
    true;
is_extend(1445) ->
    true;
is_extend(1446) ->
    true;
is_extend(1447) ->
    true;
is_extend(1448) ->
    true;
is_extend(1449) ->
    true;
is_extend(1450) ->
    true;
is_extend(1451) ->
    true;
is_extend(1452) ->
    true;
is_extend(1453) ->
    true;
is_extend(1454) ->
    true;
is_extend(1455) ->
    true;
is_extend(1456) ->
    true;
is_extend(1457) ->
    true;
is_extend(1458) ->
    true;
is_extend(1459) ->
    true;
is_extend(1460) ->
    true;
is_extend(1461) ->
    true;
is_extend(1462) ->
    true;
is_extend(1463) ->
    true;
is_extend(1464) ->
    true;
is_extend(1465) ->
    true;
is_extend(1466) ->
    true;
is_extend(1467) ->
    true;
is_extend(1468) ->
    true;
is_extend(1469) ->
    true;
is_extend(1471) ->
    true;
is_extend(1473) ->
    true;
is_extend(1474) ->
    true;
is_extend(1476) ->
    true;
is_extend(1477) ->
    true;
is_extend(1479) ->
    true;
is_extend(1552) ->
    true;
is_extend(1553) ->
    true;
is_extend(1554) ->
    true;
is_extend(1555) ->
    true;
is_extend(1556) ->
    true;
is_extend(1557) ->
    true;
is_extend(1558) ->
    true;
is_extend(1559) ->
    true;
is_extend(1560) ->
    true;
is_extend(1561) ->
    true;
is_extend(1562) ->
    true;
is_extend(1611) ->
    true;
is_extend(1612) ->
    true;
is_extend(1613) ->
    true;
is_extend(1614) ->
    true;
is_extend(1615) ->
    true;
is_extend(1616) ->
    true;
is_extend(1617) ->
    true;
is_extend(1618) ->
    true;
is_extend(1619) ->
    true;
is_extend(1620) ->
    true;
is_extend(1621) ->
    true;
is_extend(1622) ->
    true;
is_extend(1623) ->
    true;
is_extend(1624) ->
    true;
is_extend(1625) ->
    true;
is_extend(1626) ->
    true;
is_extend(1627) ->
    true;
is_extend(1628) ->
    true;
is_extend(1629) ->
    true;
is_extend(1630) ->
    true;
is_extend(1631) ->
    true;
is_extend(1648) ->
    true;
is_extend(1750) ->
    true;
is_extend(1751) ->
    true;
is_extend(1752) ->
    true;
is_extend(1753) ->
    true;
is_extend(1754) ->
    true;
is_extend(1755) ->
    true;
is_extend(1756) ->
    true;
is_extend(1759) ->
    true;
is_extend(1760) ->
    true;
is_extend(1761) ->
    true;
is_extend(1762) ->
    true;
is_extend(1763) ->
    true;
is_extend(1764) ->
    true;
is_extend(1767) ->
    true;
is_extend(1768) ->
    true;
is_extend(1770) ->
    true;
is_extend(1771) ->
    true;
is_extend(1772) ->
    true;
is_extend(1773) ->
    true;
is_extend(1809) ->
    true;
is_extend(1840) ->
    true;
is_extend(1841) ->
    true;
is_extend(1842) ->
    true;
is_extend(1843) ->
    true;
is_extend(1844) ->
    true;
is_extend(1845) ->
    true;
is_extend(1846) ->
    true;
is_extend(1847) ->
    true;
is_extend(1848) ->
    true;
is_extend(1849) ->
    true;
is_extend(1850) ->
    true;
is_extend(1851) ->
    true;
is_extend(1852) ->
    true;
is_extend(1853) ->
    true;
is_extend(1854) ->
    true;
is_extend(1855) ->
    true;
is_extend(1856) ->
    true;
is_extend(1857) ->
    true;
is_extend(1858) ->
    true;
is_extend(1859) ->
    true;
is_extend(1860) ->
    true;
is_extend(1861) ->
    true;
is_extend(1862) ->
    true;
is_extend(1863) ->
    true;
is_extend(1864) ->
    true;
is_extend(1865) ->
    true;
is_extend(1866) ->
    true;
is_extend(1958) ->
    true;
is_extend(1959) ->
    true;
is_extend(1960) ->
    true;
is_extend(1961) ->
    true;
is_extend(1962) ->
    true;
is_extend(1963) ->
    true;
is_extend(1964) ->
    true;
is_extend(1965) ->
    true;
is_extend(1966) ->
    true;
is_extend(1967) ->
    true;
is_extend(1968) ->
    true;
is_extend(2027) ->
    true;
is_extend(2028) ->
    true;
is_extend(2029) ->
    true;
is_extend(2030) ->
    true;
is_extend(2031) ->
    true;
is_extend(2032) ->
    true;
is_extend(2033) ->
    true;
is_extend(2034) ->
    true;
is_extend(2035) ->
    true;
is_extend(2045) ->
    true;
is_extend(2070) ->
    true;
is_extend(2071) ->
    true;
is_extend(2072) ->
    true;
is_extend(2073) ->
    true;
is_extend(2075) ->
    true;
is_extend(2076) ->
    true;
is_extend(2077) ->
    true;
is_extend(2078) ->
    true;
is_extend(2079) ->
    true;
is_extend(2080) ->
    true;
is_extend(2081) ->
    true;
is_extend(2082) ->
    true;
is_extend(2083) ->
    true;
is_extend(2085) ->
    true;
is_extend(2086) ->
    true;
is_extend(2087) ->
    true;
is_extend(2089) ->
    true;
is_extend(2090) ->
    true;
is_extend(2091) ->
    true;
is_extend(2092) ->
    true;
is_extend(2093) ->
    true;
is_extend(2137) ->
    true;
is_extend(2138) ->
    true;
is_extend(2139) ->
    true;
is_extend(2259) ->
    true;
is_extend(2260) ->
    true;
is_extend(2261) ->
    true;
is_extend(2262) ->
    true;
is_extend(2263) ->
    true;
is_extend(2264) ->
    true;
is_extend(2265) ->
    true;
is_extend(2266) ->
    true;
is_extend(2267) ->
    true;
is_extend(2268) ->
    true;
is_extend(2269) ->
    true;
is_extend(2270) ->
    true;
is_extend(2271) ->
    true;
is_extend(2272) ->
    true;
is_extend(2273) ->
    true;
is_extend(2275) ->
    true;
is_extend(2276) ->
    true;
is_extend(2277) ->
    true;
is_extend(2278) ->
    true;
is_extend(2279) ->
    true;
is_extend(2280) ->
    true;
is_extend(2281) ->
    true;
is_extend(2282) ->
    true;
is_extend(2283) ->
    true;
is_extend(2284) ->
    true;
is_extend(2285) ->
    true;
is_extend(2286) ->
    true;
is_extend(2287) ->
    true;
is_extend(2288) ->
    true;
is_extend(2289) ->
    true;
is_extend(2290) ->
    true;
is_extend(2291) ->
    true;
is_extend(2292) ->
    true;
is_extend(2293) ->
    true;
is_extend(2294) ->
    true;
is_extend(2295) ->
    true;
is_extend(2296) ->
    true;
is_extend(2297) ->
    true;
is_extend(2298) ->
    true;
is_extend(2299) ->
    true;
is_extend(2300) ->
    true;
is_extend(2301) ->
    true;
is_extend(2302) ->
    true;
is_extend(2303) ->
    true;
is_extend(2304) ->
    true;
is_extend(2305) ->
    true;
is_extend(2306) ->
    true;
is_extend(2307) ->
    true;
is_extend(2362) ->
    true;
is_extend(2363) ->
    true;
is_extend(2364) ->
    true;
is_extend(2366) ->
    true;
is_extend(2367) ->
    true;
is_extend(2368) ->
    true;
is_extend(2369) ->
    true;
is_extend(2370) ->
    true;
is_extend(2371) ->
    true;
is_extend(2372) ->
    true;
is_extend(2373) ->
    true;
is_extend(2374) ->
    true;
is_extend(2375) ->
    true;
is_extend(2376) ->
    true;
is_extend(2377) ->
    true;
is_extend(2378) ->
    true;
is_extend(2379) ->
    true;
is_extend(2380) ->
    true;
is_extend(2381) ->
    true;
is_extend(2382) ->
    true;
is_extend(2383) ->
    true;
is_extend(2385) ->
    true;
is_extend(2386) ->
    true;
is_extend(2387) ->
    true;
is_extend(2388) ->
    true;
is_extend(2389) ->
    true;
is_extend(2390) ->
    true;
is_extend(2391) ->
    true;
is_extend(2402) ->
    true;
is_extend(2403) ->
    true;
is_extend(2433) ->
    true;
is_extend(2434) ->
    true;
is_extend(2435) ->
    true;
is_extend(2492) ->
    true;
is_extend(2494) ->
    true;
is_extend(2495) ->
    true;
is_extend(2496) ->
    true;
is_extend(2497) ->
    true;
is_extend(2498) ->
    true;
is_extend(2499) ->
    true;
is_extend(2500) ->
    true;
is_extend(2503) ->
    true;
is_extend(2504) ->
    true;
is_extend(2507) ->
    true;
is_extend(2508) ->
    true;
is_extend(2509) ->
    true;
is_extend(2519) ->
    true;
is_extend(2530) ->
    true;
is_extend(2531) ->
    true;
is_extend(2558) ->
    true;
is_extend(2561) ->
    true;
is_extend(2562) ->
    true;
is_extend(2563) ->
    true;
is_extend(2620) ->
    true;
is_extend(2622) ->
    true;
is_extend(2623) ->
    true;
is_extend(2624) ->
    true;
is_extend(2625) ->
    true;
is_extend(2626) ->
    true;
is_extend(2631) ->
    true;
is_extend(2632) ->
    true;
is_extend(2635) ->
    true;
is_extend(2636) ->
    true;
is_extend(2637) ->
    true;
is_extend(2641) ->
    true;
is_extend(2672) ->
    true;
is_extend(2673) ->
    true;
is_extend(2677) ->
    true;
is_extend(2689) ->
    true;
is_extend(2690) ->
    true;
is_extend(2691) ->
    true;
is_extend(2748) ->
    true;
is_extend(2750) ->
    true;
is_extend(2751) ->
    true;
is_extend(2752) ->
    true;
is_extend(2753) ->
    true;
is_extend(2754) ->
    true;
is_extend(2755) ->
    true;
is_extend(2756) ->
    true;
is_extend(2757) ->
    true;
is_extend(2759) ->
    true;
is_extend(2760) ->
    true;
is_extend(2761) ->
    true;
is_extend(2763) ->
    true;
is_extend(2764) ->
    true;
is_extend(2765) ->
    true;
is_extend(2786) ->
    true;
is_extend(2787) ->
    true;
is_extend(2810) ->
    true;
is_extend(2811) ->
    true;
is_extend(2812) ->
    true;
is_extend(2813) ->
    true;
is_extend(2814) ->
    true;
is_extend(2815) ->
    true;
is_extend(2817) ->
    true;
is_extend(2818) ->
    true;
is_extend(2819) ->
    true;
is_extend(2876) ->
    true;
is_extend(2878) ->
    true;
is_extend(2879) ->
    true;
is_extend(2880) ->
    true;
is_extend(2881) ->
    true;
is_extend(2882) ->
    true;
is_extend(2883) ->
    true;
is_extend(2884) ->
    true;
is_extend(2887) ->
    true;
is_extend(2888) ->
    true;
is_extend(2891) ->
    true;
is_extend(2892) ->
    true;
is_extend(2893) ->
    true;
is_extend(2902) ->
    true;
is_extend(2903) ->
    true;
is_extend(2914) ->
    true;
is_extend(2915) ->
    true;
is_extend(2946) ->
    true;
is_extend(3006) ->
    true;
is_extend(3007) ->
    true;
is_extend(3008) ->
    true;
is_extend(3009) ->
    true;
is_extend(3010) ->
    true;
is_extend(3014) ->
    true;
is_extend(3015) ->
    true;
is_extend(3016) ->
    true;
is_extend(3018) ->
    true;
is_extend(3019) ->
    true;
is_extend(3020) ->
    true;
is_extend(3021) ->
    true;
is_extend(3031) ->
    true;
is_extend(3072) ->
    true;
is_extend(3073) ->
    true;
is_extend(3074) ->
    true;
is_extend(3075) ->
    true;
is_extend(3076) ->
    true;
is_extend(3134) ->
    true;
is_extend(3135) ->
    true;
is_extend(3136) ->
    true;
is_extend(3137) ->
    true;
is_extend(3138) ->
    true;
is_extend(3139) ->
    true;
is_extend(3140) ->
    true;
is_extend(3142) ->
    true;
is_extend(3143) ->
    true;
is_extend(3144) ->
    true;
is_extend(3146) ->
    true;
is_extend(3147) ->
    true;
is_extend(3148) ->
    true;
is_extend(3149) ->
    true;
is_extend(3157) ->
    true;
is_extend(3158) ->
    true;
is_extend(3170) ->
    true;
is_extend(3171) ->
    true;
is_extend(3201) ->
    true;
is_extend(3202) ->
    true;
is_extend(3203) ->
    true;
is_extend(3260) ->
    true;
is_extend(3262) ->
    true;
is_extend(3263) ->
    true;
is_extend(3264) ->
    true;
is_extend(3265) ->
    true;
is_extend(3266) ->
    true;
is_extend(3267) ->
    true;
is_extend(3268) ->
    true;
is_extend(3270) ->
    true;
is_extend(3271) ->
    true;
is_extend(3272) ->
    true;
is_extend(3274) ->
    true;
is_extend(3275) ->
    true;
is_extend(3276) ->
    true;
is_extend(3277) ->
    true;
is_extend(3285) ->
    true;
is_extend(3286) ->
    true;
is_extend(3298) ->
    true;
is_extend(3299) ->
    true;
is_extend(3328) ->
    true;
is_extend(3329) ->
    true;
is_extend(3330) ->
    true;
is_extend(3331) ->
    true;
is_extend(3387) ->
    true;
is_extend(3388) ->
    true;
is_extend(3390) ->
    true;
is_extend(3391) ->
    true;
is_extend(3392) ->
    true;
is_extend(3393) ->
    true;
is_extend(3394) ->
    true;
is_extend(3395) ->
    true;
is_extend(3396) ->
    true;
is_extend(3398) ->
    true;
is_extend(3399) ->
    true;
is_extend(3400) ->
    true;
is_extend(3402) ->
    true;
is_extend(3403) ->
    true;
is_extend(3404) ->
    true;
is_extend(3405) ->
    true;
is_extend(3415) ->
    true;
is_extend(3426) ->
    true;
is_extend(3427) ->
    true;
is_extend(3458) ->
    true;
is_extend(3459) ->
    true;
is_extend(3530) ->
    true;
is_extend(3535) ->
    true;
is_extend(3536) ->
    true;
is_extend(3537) ->
    true;
is_extend(3538) ->
    true;
is_extend(3539) ->
    true;
is_extend(3540) ->
    true;
is_extend(3542) ->
    true;
is_extend(3544) ->
    true;
is_extend(3545) ->
    true;
is_extend(3546) ->
    true;
is_extend(3547) ->
    true;
is_extend(3548) ->
    true;
is_extend(3549) ->
    true;
is_extend(3550) ->
    true;
is_extend(3551) ->
    true;
is_extend(3570) ->
    true;
is_extend(3571) ->
    true;
is_extend(3633) ->
    true;
is_extend(3635) ->
    true;
is_extend(3636) ->
    true;
is_extend(3637) ->
    true;
is_extend(3638) ->
    true;
is_extend(3639) ->
    true;
is_extend(3640) ->
    true;
is_extend(3641) ->
    true;
is_extend(3642) ->
    true;
is_extend(3655) ->
    true;
is_extend(3656) ->
    true;
is_extend(3657) ->
    true;
is_extend(3658) ->
    true;
is_extend(3659) ->
    true;
is_extend(3660) ->
    true;
is_extend(3661) ->
    true;
is_extend(3662) ->
    true;
is_extend(3761) ->
    true;
is_extend(3763) ->
    true;
is_extend(3764) ->
    true;
is_extend(3765) ->
    true;
is_extend(3766) ->
    true;
is_extend(3767) ->
    true;
is_extend(3768) ->
    true;
is_extend(3769) ->
    true;
is_extend(3770) ->
    true;
is_extend(3771) ->
    true;
is_extend(3772) ->
    true;
is_extend(3784) ->
    true;
is_extend(3785) ->
    true;
is_extend(3786) ->
    true;
is_extend(3787) ->
    true;
is_extend(3788) ->
    true;
is_extend(3789) ->
    true;
is_extend(3864) ->
    true;
is_extend(3865) ->
    true;
is_extend(3893) ->
    true;
is_extend(3895) ->
    true;
is_extend(3897) ->
    true;
is_extend(3902) ->
    true;
is_extend(3903) ->
    true;
is_extend(3953) ->
    true;
is_extend(3954) ->
    true;
is_extend(3955) ->
    true;
is_extend(3956) ->
    true;
is_extend(3957) ->
    true;
is_extend(3958) ->
    true;
is_extend(3959) ->
    true;
is_extend(3960) ->
    true;
is_extend(3961) ->
    true;
is_extend(3962) ->
    true;
is_extend(3963) ->
    true;
is_extend(3964) ->
    true;
is_extend(3965) ->
    true;
is_extend(3966) ->
    true;
is_extend(3967) ->
    true;
is_extend(3968) ->
    true;
is_extend(3969) ->
    true;
is_extend(3970) ->
    true;
is_extend(3971) ->
    true;
is_extend(3972) ->
    true;
is_extend(3974) ->
    true;
is_extend(3975) ->
    true;
is_extend(3981) ->
    true;
is_extend(3982) ->
    true;
is_extend(3983) ->
    true;
is_extend(3984) ->
    true;
is_extend(3985) ->
    true;
is_extend(3986) ->
    true;
is_extend(3987) ->
    true;
is_extend(3988) ->
    true;
is_extend(3989) ->
    true;
is_extend(3990) ->
    true;
is_extend(3991) ->
    true;
is_extend(3993) ->
    true;
is_extend(3994) ->
    true;
is_extend(3995) ->
    true;
is_extend(3996) ->
    true;
is_extend(3997) ->
    true;
is_extend(3998) ->
    true;
is_extend(3999) ->
    true;
is_extend(4000) ->
    true;
is_extend(4001) ->
    true;
is_extend(4002) ->
    true;
is_extend(4003) ->
    true;
is_extend(4004) ->
    true;
is_extend(4005) ->
    true;
is_extend(4006) ->
    true;
is_extend(4007) ->
    true;
is_extend(4008) ->
    true;
is_extend(4009) ->
    true;
is_extend(4010) ->
    true;
is_extend(4011) ->
    true;
is_extend(4012) ->
    true;
is_extend(4013) ->
    true;
is_extend(4014) ->
    true;
is_extend(4015) ->
    true;
is_extend(4016) ->
    true;
is_extend(4017) ->
    true;
is_extend(4018) ->
    true;
is_extend(4019) ->
    true;
is_extend(4020) ->
    true;
is_extend(4021) ->
    true;
is_extend(4022) ->
    true;
is_extend(4023) ->
    true;
is_extend(4024) ->
    true;
is_extend(4025) ->
    true;
is_extend(4026) ->
    true;
is_extend(4027) ->
    true;
is_extend(4028) ->
    true;
is_extend(4038) ->
    true;
is_extend(4141) ->
    true;
is_extend(4142) ->
    true;
is_extend(4143) ->
    true;
is_extend(4144) ->
    true;
is_extend(4145) ->
    true;
is_extend(4146) ->
    true;
is_extend(4147) ->
    true;
is_extend(4148) ->
    true;
is_extend(4149) ->
    true;
is_extend(4150) ->
    true;
is_extend(4151) ->
    true;
is_extend(4153) ->
    true;
is_extend(4154) ->
    true;
is_extend(4155) ->
    true;
is_extend(4156) ->
    true;
is_extend(4157) ->
    true;
is_extend(4158) ->
    true;
is_extend(4182) ->
    true;
is_extend(4183) ->
    true;
is_extend(4184) ->
    true;
is_extend(4185) ->
    true;
is_extend(4190) ->
    true;
is_extend(4191) ->
    true;
is_extend(4192) ->
    true;
is_extend(4209) ->
    true;
is_extend(4210) ->
    true;
is_extend(4211) ->
    true;
is_extend(4212) ->
    true;
is_extend(4226) ->
    true;
is_extend(4228) ->
    true;
is_extend(4229) ->
    true;
is_extend(4230) ->
    true;
is_extend(4237) ->
    true;
is_extend(4253) ->
    true;
is_extend(4957) ->
    true;
is_extend(4958) ->
    true;
is_extend(4959) ->
    true;
is_extend(5906) ->
    true;
is_extend(5907) ->
    true;
is_extend(5908) ->
    true;
is_extend(5938) ->
    true;
is_extend(5939) ->
    true;
is_extend(5940) ->
    true;
is_extend(5970) ->
    true;
is_extend(5971) ->
    true;
is_extend(6002) ->
    true;
is_extend(6003) ->
    true;
is_extend(6068) ->
    true;
is_extend(6069) ->
    true;
is_extend(6070) ->
    true;
is_extend(6071) ->
    true;
is_extend(6072) ->
    true;
is_extend(6073) ->
    true;
is_extend(6074) ->
    true;
is_extend(6075) ->
    true;
is_extend(6076) ->
    true;
is_extend(6077) ->
    true;
is_extend(6078) ->
    true;
is_extend(6079) ->
    true;
is_extend(6080) ->
    true;
is_extend(6081) ->
    true;
is_extend(6082) ->
    true;
is_extend(6083) ->
    true;
is_extend(6084) ->
    true;
is_extend(6085) ->
    true;
is_extend(6086) ->
    true;
is_extend(6087) ->
    true;
is_extend(6088) ->
    true;
is_extend(6089) ->
    true;
is_extend(6090) ->
    true;
is_extend(6091) ->
    true;
is_extend(6092) ->
    true;
is_extend(6093) ->
    true;
is_extend(6094) ->
    true;
is_extend(6095) ->
    true;
is_extend(6096) ->
    true;
is_extend(6097) ->
    true;
is_extend(6098) ->
    true;
is_extend(6099) ->
    true;
is_extend(6109) ->
    true;
is_extend(6155) ->
    true;
is_extend(6156) ->
    true;
is_extend(6157) ->
    true;
is_extend(6277) ->
    true;
is_extend(6278) ->
    true;
is_extend(6313) ->
    true;
is_extend(6432) ->
    true;
is_extend(6433) ->
    true;
is_extend(6434) ->
    true;
is_extend(6435) ->
    true;
is_extend(6436) ->
    true;
is_extend(6437) ->
    true;
is_extend(6438) ->
    true;
is_extend(6439) ->
    true;
is_extend(6440) ->
    true;
is_extend(6441) ->
    true;
is_extend(6442) ->
    true;
is_extend(6443) ->
    true;
is_extend(6448) ->
    true;
is_extend(6449) ->
    true;
is_extend(6450) ->
    true;
is_extend(6451) ->
    true;
is_extend(6452) ->
    true;
is_extend(6453) ->
    true;
is_extend(6454) ->
    true;
is_extend(6455) ->
    true;
is_extend(6456) ->
    true;
is_extend(6457) ->
    true;
is_extend(6458) ->
    true;
is_extend(6459) ->
    true;
is_extend(6679) ->
    true;
is_extend(6680) ->
    true;
is_extend(6681) ->
    true;
is_extend(6682) ->
    true;
is_extend(6683) ->
    true;
is_extend(6741) ->
    true;
is_extend(6742) ->
    true;
is_extend(6743) ->
    true;
is_extend(6744) ->
    true;
is_extend(6745) ->
    true;
is_extend(6746) ->
    true;
is_extend(6747) ->
    true;
is_extend(6748) ->
    true;
is_extend(6749) ->
    true;
is_extend(6750) ->
    true;
is_extend(6752) ->
    true;
is_extend(6754) ->
    true;
is_extend(6757) ->
    true;
is_extend(6758) ->
    true;
is_extend(6759) ->
    true;
is_extend(6760) ->
    true;
is_extend(6761) ->
    true;
is_extend(6762) ->
    true;
is_extend(6763) ->
    true;
is_extend(6764) ->
    true;
is_extend(6765) ->
    true;
is_extend(6766) ->
    true;
is_extend(6767) ->
    true;
is_extend(6768) ->
    true;
is_extend(6769) ->
    true;
is_extend(6770) ->
    true;
is_extend(6771) ->
    true;
is_extend(6772) ->
    true;
is_extend(6773) ->
    true;
is_extend(6774) ->
    true;
is_extend(6775) ->
    true;
is_extend(6776) ->
    true;
is_extend(6777) ->
    true;
is_extend(6778) ->
    true;
is_extend(6779) ->
    true;
is_extend(6780) ->
    true;
is_extend(6783) ->
    true;
is_extend(6832) ->
    true;
is_extend(6833) ->
    true;
is_extend(6834) ->
    true;
is_extend(6835) ->
    true;
is_extend(6836) ->
    true;
is_extend(6837) ->
    true;
is_extend(6838) ->
    true;
is_extend(6839) ->
    true;
is_extend(6840) ->
    true;
is_extend(6841) ->
    true;
is_extend(6842) ->
    true;
is_extend(6843) ->
    true;
is_extend(6844) ->
    true;
is_extend(6845) ->
    true;
is_extend(6846) ->
    true;
is_extend(6912) ->
    true;
is_extend(6913) ->
    true;
is_extend(6914) ->
    true;
is_extend(6915) ->
    true;
is_extend(6916) ->
    true;
is_extend(6964) ->
    true;
is_extend(6965) ->
    true;
is_extend(6966) ->
    true;
is_extend(6967) ->
    true;
is_extend(6968) ->
    true;
is_extend(6969) ->
    true;
is_extend(6970) ->
    true;
is_extend(6971) ->
    true;
is_extend(6972) ->
    true;
is_extend(6973) ->
    true;
is_extend(6974) ->
    true;
is_extend(6975) ->
    true;
is_extend(6976) ->
    true;
is_extend(6977) ->
    true;
is_extend(6978) ->
    true;
is_extend(6979) ->
    true;
is_extend(6980) ->
    true;
is_extend(7019) ->
    true;
is_extend(7020) ->
    true;
is_extend(7021) ->
    true;
is_extend(7022) ->
    true;
is_extend(7023) ->
    true;
is_extend(7024) ->
    true;
is_extend(7025) ->
    true;
is_extend(7026) ->
    true;
is_extend(7027) ->
    true;
is_extend(7040) ->
    true;
is_extend(7041) ->
    true;
is_extend(7042) ->
    true;
is_extend(7073) ->
    true;
is_extend(7074) ->
    true;
is_extend(7075) ->
    true;
is_extend(7076) ->
    true;
is_extend(7077) ->
    true;
is_extend(7078) ->
    true;
is_extend(7079) ->
    true;
is_extend(7080) ->
    true;
is_extend(7081) ->
    true;
is_extend(7082) ->
    true;
is_extend(7083) ->
    true;
is_extend(7084) ->
    true;
is_extend(7085) ->
    true;
is_extend(7142) ->
    true;
is_extend(7143) ->
    true;
is_extend(7144) ->
    true;
is_extend(7145) ->
    true;
is_extend(7146) ->
    true;
is_extend(7147) ->
    true;
is_extend(7148) ->
    true;
is_extend(7149) ->
    true;
is_extend(7150) ->
    true;
is_extend(7151) ->
    true;
is_extend(7152) ->
    true;
is_extend(7153) ->
    true;
is_extend(7154) ->
    true;
is_extend(7155) ->
    true;
is_extend(7204) ->
    true;
is_extend(7205) ->
    true;
is_extend(7206) ->
    true;
is_extend(7207) ->
    true;
is_extend(7208) ->
    true;
is_extend(7209) ->
    true;
is_extend(7210) ->
    true;
is_extend(7211) ->
    true;
is_extend(7212) ->
    true;
is_extend(7213) ->
    true;
is_extend(7214) ->
    true;
is_extend(7215) ->
    true;
is_extend(7216) ->
    true;
is_extend(7217) ->
    true;
is_extend(7218) ->
    true;
is_extend(7219) ->
    true;
is_extend(7220) ->
    true;
is_extend(7221) ->
    true;
is_extend(7222) ->
    true;
is_extend(7223) ->
    true;
is_extend(7376) ->
    true;
is_extend(7377) ->
    true;
is_extend(7378) ->
    true;
is_extend(7380) ->
    true;
is_extend(7381) ->
    true;
is_extend(7382) ->
    true;
is_extend(7383) ->
    true;
is_extend(7384) ->
    true;
is_extend(7385) ->
    true;
is_extend(7386) ->
    true;
is_extend(7387) ->
    true;
is_extend(7388) ->
    true;
is_extend(7389) ->
    true;
is_extend(7390) ->
    true;
is_extend(7391) ->
    true;
is_extend(7392) ->
    true;
is_extend(7393) ->
    true;
is_extend(7394) ->
    true;
is_extend(7395) ->
    true;
is_extend(7396) ->
    true;
is_extend(7397) ->
    true;
is_extend(7398) ->
    true;
is_extend(7399) ->
    true;
is_extend(7400) ->
    true;
is_extend(7405) ->
    true;
is_extend(7412) ->
    true;
is_extend(7415) ->
    true;
is_extend(7416) ->
    true;
is_extend(7417) ->
    true;
is_extend(7616) ->
    true;
is_extend(7617) ->
    true;
is_extend(7618) ->
    true;
is_extend(7619) ->
    true;
is_extend(7620) ->
    true;
is_extend(7621) ->
    true;
is_extend(7622) ->
    true;
is_extend(7623) ->
    true;
is_extend(7624) ->
    true;
is_extend(7625) ->
    true;
is_extend(7626) ->
    true;
is_extend(7627) ->
    true;
is_extend(7628) ->
    true;
is_extend(7629) ->
    true;
is_extend(7630) ->
    true;
is_extend(7631) ->
    true;
is_extend(7632) ->
    true;
is_extend(7633) ->
    true;
is_extend(7634) ->
    true;
is_extend(7635) ->
    true;
is_extend(7636) ->
    true;
is_extend(7637) ->
    true;
is_extend(7638) ->
    true;
is_extend(7639) ->
    true;
is_extend(7640) ->
    true;
is_extend(7641) ->
    true;
is_extend(7642) ->
    true;
is_extend(7643) ->
    true;
is_extend(7644) ->
    true;
is_extend(7645) ->
    true;
is_extend(7646) ->
    true;
is_extend(7647) ->
    true;
is_extend(7648) ->
    true;
is_extend(7649) ->
    true;
is_extend(7650) ->
    true;
is_extend(7651) ->
    true;
is_extend(7652) ->
    true;
is_extend(7653) ->
    true;
is_extend(7654) ->
    true;
is_extend(7655) ->
    true;
is_extend(7656) ->
    true;
is_extend(7657) ->
    true;
is_extend(7658) ->
    true;
is_extend(7659) ->
    true;
is_extend(7660) ->
    true;
is_extend(7661) ->
    true;
is_extend(7662) ->
    true;
is_extend(7663) ->
    true;
is_extend(7664) ->
    true;
is_extend(7665) ->
    true;
is_extend(7666) ->
    true;
is_extend(7667) ->
    true;
is_extend(7668) ->
    true;
is_extend(7669) ->
    true;
is_extend(7670) ->
    true;
is_extend(7671) ->
    true;
is_extend(7672) ->
    true;
is_extend(7673) ->
    true;
is_extend(7675) ->
    true;
is_extend(7676) ->
    true;
is_extend(7677) ->
    true;
is_extend(7678) ->
    true;
is_extend(7679) ->
    true;
is_extend(8204) ->
    true;
is_extend(8205) ->
    zwj;
is_extend(8400) ->
    true;
is_extend(8401) ->
    true;
is_extend(8402) ->
    true;
is_extend(8403) ->
    true;
is_extend(8404) ->
    true;
is_extend(8405) ->
    true;
is_extend(8406) ->
    true;
is_extend(8407) ->
    true;
is_extend(8408) ->
    true;
is_extend(8409) ->
    true;
is_extend(8410) ->
    true;
is_extend(8411) ->
    true;
is_extend(8412) ->
    true;
is_extend(8413) ->
    true;
is_extend(8414) ->
    true;
is_extend(8415) ->
    true;
is_extend(8416) ->
    true;
is_extend(8417) ->
    true;
is_extend(8418) ->
    true;
is_extend(8419) ->
    true;
is_extend(8420) ->
    true;
is_extend(8421) ->
    true;
is_extend(8422) ->
    true;
is_extend(8423) ->
    true;
is_extend(8424) ->
    true;
is_extend(8425) ->
    true;
is_extend(8426) ->
    true;
is_extend(8427) ->
    true;
is_extend(8428) ->
    true;
is_extend(8429) ->
    true;
is_extend(8430) ->
    true;
is_extend(8431) ->
    true;
is_extend(8432) ->
    true;
is_extend(11503) ->
    true;
is_extend(11504) ->
    true;
is_extend(11505) ->
    true;
is_extend(11647) ->
    true;
is_extend(11744) ->
    true;
is_extend(11745) ->
    true;
is_extend(11746) ->
    true;
is_extend(11747) ->
    true;
is_extend(11748) ->
    true;
is_extend(11749) ->
    true;
is_extend(11750) ->
    true;
is_extend(11751) ->
    true;
is_extend(11752) ->
    true;
is_extend(11753) ->
    true;
is_extend(11754) ->
    true;
is_extend(11755) ->
    true;
is_extend(11756) ->
    true;
is_extend(11757) ->
    true;
is_extend(11758) ->
    true;
is_extend(11759) ->
    true;
is_extend(11760) ->
    true;
is_extend(11761) ->
    true;
is_extend(11762) ->
    true;
is_extend(11763) ->
    true;
is_extend(11764) ->
    true;
is_extend(11765) ->
    true;
is_extend(11766) ->
    true;
is_extend(11767) ->
    true;
is_extend(11768) ->
    true;
is_extend(11769) ->
    true;
is_extend(11770) ->
    true;
is_extend(11771) ->
    true;
is_extend(11772) ->
    true;
is_extend(11773) ->
    true;
is_extend(11774) ->
    true;
is_extend(11775) ->
    true;
is_extend(12330) ->
    true;
is_extend(12331) ->
    true;
is_extend(12332) ->
    true;
is_extend(12333) ->
    true;
is_extend(12334) ->
    true;
is_extend(12335) ->
    true;
is_extend(12441) ->
    true;
is_extend(12442) ->
    true;
is_extend(42607) ->
    true;
is_extend(42608) ->
    true;
is_extend(42609) ->
    true;
is_extend(42610) ->
    true;
is_extend(42612) ->
    true;
is_extend(42613) ->
    true;
is_extend(42614) ->
    true;
is_extend(42615) ->
    true;
is_extend(42616) ->
    true;
is_extend(42617) ->
    true;
is_extend(42618) ->
    true;
is_extend(42619) ->
    true;
is_extend(42620) ->
    true;
is_extend(42621) ->
    true;
is_extend(42654) ->
    true;
is_extend(42655) ->
    true;
is_extend(42736) ->
    true;
is_extend(42737) ->
    true;
is_extend(43010) ->
    true;
is_extend(43014) ->
    true;
is_extend(43019) ->
    true;
is_extend(43043) ->
    true;
is_extend(43044) ->
    true;
is_extend(43045) ->
    true;
is_extend(43046) ->
    true;
is_extend(43047) ->
    true;
is_extend(43136) ->
    true;
is_extend(43137) ->
    true;
is_extend(43188) ->
    true;
is_extend(43189) ->
    true;
is_extend(43190) ->
    true;
is_extend(43191) ->
    true;
is_extend(43192) ->
    true;
is_extend(43193) ->
    true;
is_extend(43194) ->
    true;
is_extend(43195) ->
    true;
is_extend(43196) ->
    true;
is_extend(43197) ->
    true;
is_extend(43198) ->
    true;
is_extend(43199) ->
    true;
is_extend(43200) ->
    true;
is_extend(43201) ->
    true;
is_extend(43202) ->
    true;
is_extend(43203) ->
    true;
is_extend(43204) ->
    true;
is_extend(43205) ->
    true;
is_extend(43232) ->
    true;
is_extend(43233) ->
    true;
is_extend(43234) ->
    true;
is_extend(43235) ->
    true;
is_extend(43236) ->
    true;
is_extend(43237) ->
    true;
is_extend(43238) ->
    true;
is_extend(43239) ->
    true;
is_extend(43240) ->
    true;
is_extend(43241) ->
    true;
is_extend(43242) ->
    true;
is_extend(43243) ->
    true;
is_extend(43244) ->
    true;
is_extend(43245) ->
    true;
is_extend(43246) ->
    true;
is_extend(43247) ->
    true;
is_extend(43248) ->
    true;
is_extend(43249) ->
    true;
is_extend(43263) ->
    true;
is_extend(43302) ->
    true;
is_extend(43303) ->
    true;
is_extend(43304) ->
    true;
is_extend(43305) ->
    true;
is_extend(43306) ->
    true;
is_extend(43307) ->
    true;
is_extend(43308) ->
    true;
is_extend(43309) ->
    true;
is_extend(43335) ->
    true;
is_extend(43336) ->
    true;
is_extend(43337) ->
    true;
is_extend(43338) ->
    true;
is_extend(43339) ->
    true;
is_extend(43340) ->
    true;
is_extend(43341) ->
    true;
is_extend(43342) ->
    true;
is_extend(43343) ->
    true;
is_extend(43344) ->
    true;
is_extend(43345) ->
    true;
is_extend(43346) ->
    true;
is_extend(43347) ->
    true;
is_extend(43392) ->
    true;
is_extend(43393) ->
    true;
is_extend(43394) ->
    true;
is_extend(43395) ->
    true;
is_extend(43443) ->
    true;
is_extend(43444) ->
    true;
is_extend(43445) ->
    true;
is_extend(43446) ->
    true;
is_extend(43447) ->
    true;
is_extend(43448) ->
    true;
is_extend(43449) ->
    true;
is_extend(43450) ->
    true;
is_extend(43451) ->
    true;
is_extend(43452) ->
    true;
is_extend(43453) ->
    true;
is_extend(43454) ->
    true;
is_extend(43455) ->
    true;
is_extend(43456) ->
    true;
is_extend(43493) ->
    true;
is_extend(43561) ->
    true;
is_extend(43562) ->
    true;
is_extend(43563) ->
    true;
is_extend(43564) ->
    true;
is_extend(43565) ->
    true;
is_extend(43566) ->
    true;
is_extend(43567) ->
    true;
is_extend(43568) ->
    true;
is_extend(43569) ->
    true;
is_extend(43570) ->
    true;
is_extend(43571) ->
    true;
is_extend(43572) ->
    true;
is_extend(43573) ->
    true;
is_extend(43574) ->
    true;
is_extend(43587) ->
    true;
is_extend(43596) ->
    true;
is_extend(43597) ->
    true;
is_extend(43644) ->
    true;
is_extend(43696) ->
    true;
is_extend(43698) ->
    true;
is_extend(43699) ->
    true;
is_extend(43700) ->
    true;
is_extend(43703) ->
    true;
is_extend(43704) ->
    true;
is_extend(43710) ->
    true;
is_extend(43711) ->
    true;
is_extend(43713) ->
    true;
is_extend(43755) ->
    true;
is_extend(43756) ->
    true;
is_extend(43757) ->
    true;
is_extend(43758) ->
    true;
is_extend(43759) ->
    true;
is_extend(43765) ->
    true;
is_extend(43766) ->
    true;
is_extend(44003) ->
    true;
is_extend(44004) ->
    true;
is_extend(44005) ->
    true;
is_extend(44006) ->
    true;
is_extend(44007) ->
    true;
is_extend(44008) ->
    true;
is_extend(44009) ->
    true;
is_extend(44010) ->
    true;
is_extend(44012) ->
    true;
is_extend(44013) ->
    true;
is_extend(64286) ->
    true;
is_extend(65024) ->
    true;
is_extend(65025) ->
    true;
is_extend(65026) ->
    true;
is_extend(65027) ->
    true;
is_extend(65028) ->
    true;
is_extend(65029) ->
    true;
is_extend(65030) ->
    true;
is_extend(65031) ->
    true;
is_extend(65032) ->
    true;
is_extend(65033) ->
    true;
is_extend(65034) ->
    true;
is_extend(65035) ->
    true;
is_extend(65036) ->
    true;
is_extend(65037) ->
    true;
is_extend(65038) ->
    true;
is_extend(65039) ->
    true;
is_extend(65056) ->
    true;
is_extend(65057) ->
    true;
is_extend(65058) ->
    true;
is_extend(65059) ->
    true;
is_extend(65060) ->
    true;
is_extend(65061) ->
    true;
is_extend(65062) ->
    true;
is_extend(65063) ->
    true;
is_extend(65064) ->
    true;
is_extend(65065) ->
    true;
is_extend(65066) ->
    true;
is_extend(65067) ->
    true;
is_extend(65068) ->
    true;
is_extend(65069) ->
    true;
is_extend(65070) ->
    true;
is_extend(65071) ->
    true;
is_extend(65438) ->
    true;
is_extend(65439) ->
    true;
is_extend(66045) ->
    true;
is_extend(66272) ->
    true;
is_extend(66422) ->
    true;
is_extend(66423) ->
    true;
is_extend(66424) ->
    true;
is_extend(66425) ->
    true;
is_extend(66426) ->
    true;
is_extend(68097) ->
    true;
is_extend(68098) ->
    true;
is_extend(68099) ->
    true;
is_extend(68101) ->
    true;
is_extend(68102) ->
    true;
is_extend(68108) ->
    true;
is_extend(68109) ->
    true;
is_extend(68110) ->
    true;
is_extend(68111) ->
    true;
is_extend(68152) ->
    true;
is_extend(68153) ->
    true;
is_extend(68154) ->
    true;
is_extend(68159) ->
    true;
is_extend(68325) ->
    true;
is_extend(68326) ->
    true;
is_extend(68900) ->
    true;
is_extend(68901) ->
    true;
is_extend(68902) ->
    true;
is_extend(68903) ->
    true;
is_extend(69446) ->
    true;
is_extend(69447) ->
    true;
is_extend(69448) ->
    true;
is_extend(69449) ->
    true;
is_extend(69450) ->
    true;
is_extend(69451) ->
    true;
is_extend(69452) ->
    true;
is_extend(69453) ->
    true;
is_extend(69454) ->
    true;
is_extend(69455) ->
    true;
is_extend(69456) ->
    true;
is_extend(69632) ->
    true;
is_extend(69633) ->
    true;
is_extend(69634) ->
    true;
is_extend(69688) ->
    true;
is_extend(69689) ->
    true;
is_extend(69690) ->
    true;
is_extend(69691) ->
    true;
is_extend(69692) ->
    true;
is_extend(69693) ->
    true;
is_extend(69694) ->
    true;
is_extend(69695) ->
    true;
is_extend(69696) ->
    true;
is_extend(69697) ->
    true;
is_extend(69698) ->
    true;
is_extend(69699) ->
    true;
is_extend(69700) ->
    true;
is_extend(69701) ->
    true;
is_extend(69702) ->
    true;
is_extend(69759) ->
    true;
is_extend(69760) ->
    true;
is_extend(69761) ->
    true;
is_extend(69762) ->
    true;
is_extend(69808) ->
    true;
is_extend(69809) ->
    true;
is_extend(69810) ->
    true;
is_extend(69811) ->
    true;
is_extend(69812) ->
    true;
is_extend(69813) ->
    true;
is_extend(69814) ->
    true;
is_extend(69815) ->
    true;
is_extend(69816) ->
    true;
is_extend(69817) ->
    true;
is_extend(69818) ->
    true;
is_extend(69888) ->
    true;
is_extend(69889) ->
    true;
is_extend(69890) ->
    true;
is_extend(69927) ->
    true;
is_extend(69928) ->
    true;
is_extend(69929) ->
    true;
is_extend(69930) ->
    true;
is_extend(69931) ->
    true;
is_extend(69932) ->
    true;
is_extend(69933) ->
    true;
is_extend(69934) ->
    true;
is_extend(69935) ->
    true;
is_extend(69936) ->
    true;
is_extend(69937) ->
    true;
is_extend(69938) ->
    true;
is_extend(69939) ->
    true;
is_extend(69940) ->
    true;
is_extend(69957) ->
    true;
is_extend(69958) ->
    true;
is_extend(70003) ->
    true;
is_extend(70016) ->
    true;
is_extend(70017) ->
    true;
is_extend(70018) ->
    true;
is_extend(70067) ->
    true;
is_extend(70068) ->
    true;
is_extend(70069) ->
    true;
is_extend(70070) ->
    true;
is_extend(70071) ->
    true;
is_extend(70072) ->
    true;
is_extend(70073) ->
    true;
is_extend(70074) ->
    true;
is_extend(70075) ->
    true;
is_extend(70076) ->
    true;
is_extend(70077) ->
    true;
is_extend(70078) ->
    true;
is_extend(70079) ->
    true;
is_extend(70080) ->
    true;
is_extend(70089) ->
    true;
is_extend(70090) ->
    true;
is_extend(70091) ->
    true;
is_extend(70092) ->
    true;
is_extend(70188) ->
    true;
is_extend(70189) ->
    true;
is_extend(70190) ->
    true;
is_extend(70191) ->
    true;
is_extend(70192) ->
    true;
is_extend(70193) ->
    true;
is_extend(70194) ->
    true;
is_extend(70195) ->
    true;
is_extend(70196) ->
    true;
is_extend(70197) ->
    true;
is_extend(70198) ->
    true;
is_extend(70199) ->
    true;
is_extend(70206) ->
    true;
is_extend(70367) ->
    true;
is_extend(70368) ->
    true;
is_extend(70369) ->
    true;
is_extend(70370) ->
    true;
is_extend(70371) ->
    true;
is_extend(70372) ->
    true;
is_extend(70373) ->
    true;
is_extend(70374) ->
    true;
is_extend(70375) ->
    true;
is_extend(70376) ->
    true;
is_extend(70377) ->
    true;
is_extend(70378) ->
    true;
is_extend(70400) ->
    true;
is_extend(70401) ->
    true;
is_extend(70402) ->
    true;
is_extend(70403) ->
    true;
is_extend(70459) ->
    true;
is_extend(70460) ->
    true;
is_extend(70462) ->
    true;
is_extend(70463) ->
    true;
is_extend(70464) ->
    true;
is_extend(70465) ->
    true;
is_extend(70466) ->
    true;
is_extend(70467) ->
    true;
is_extend(70468) ->
    true;
is_extend(70471) ->
    true;
is_extend(70472) ->
    true;
is_extend(70475) ->
    true;
is_extend(70476) ->
    true;
is_extend(70477) ->
    true;
is_extend(70487) ->
    true;
is_extend(70498) ->
    true;
is_extend(70499) ->
    true;
is_extend(70502) ->
    true;
is_extend(70503) ->
    true;
is_extend(70504) ->
    true;
is_extend(70505) ->
    true;
is_extend(70506) ->
    true;
is_extend(70507) ->
    true;
is_extend(70508) ->
    true;
is_extend(70512) ->
    true;
is_extend(70513) ->
    true;
is_extend(70514) ->
    true;
is_extend(70515) ->
    true;
is_extend(70516) ->
    true;
is_extend(70709) ->
    true;
is_extend(70710) ->
    true;
is_extend(70711) ->
    true;
is_extend(70712) ->
    true;
is_extend(70713) ->
    true;
is_extend(70714) ->
    true;
is_extend(70715) ->
    true;
is_extend(70716) ->
    true;
is_extend(70717) ->
    true;
is_extend(70718) ->
    true;
is_extend(70719) ->
    true;
is_extend(70720) ->
    true;
is_extend(70721) ->
    true;
is_extend(70722) ->
    true;
is_extend(70723) ->
    true;
is_extend(70724) ->
    true;
is_extend(70725) ->
    true;
is_extend(70726) ->
    true;
is_extend(70750) ->
    true;
is_extend(70832) ->
    true;
is_extend(70833) ->
    true;
is_extend(70834) ->
    true;
is_extend(70835) ->
    true;
is_extend(70836) ->
    true;
is_extend(70837) ->
    true;
is_extend(70838) ->
    true;
is_extend(70839) ->
    true;
is_extend(70840) ->
    true;
is_extend(70841) ->
    true;
is_extend(70842) ->
    true;
is_extend(70843) ->
    true;
is_extend(70844) ->
    true;
is_extend(70845) ->
    true;
is_extend(70846) ->
    true;
is_extend(70847) ->
    true;
is_extend(70848) ->
    true;
is_extend(70849) ->
    true;
is_extend(70850) ->
    true;
is_extend(70851) ->
    true;
is_extend(71087) ->
    true;
is_extend(71088) ->
    true;
is_extend(71089) ->
    true;
is_extend(71090) ->
    true;
is_extend(71091) ->
    true;
is_extend(71092) ->
    true;
is_extend(71093) ->
    true;
is_extend(71096) ->
    true;
is_extend(71097) ->
    true;
is_extend(71098) ->
    true;
is_extend(71099) ->
    true;
is_extend(71100) ->
    true;
is_extend(71101) ->
    true;
is_extend(71102) ->
    true;
is_extend(71103) ->
    true;
is_extend(71104) ->
    true;
is_extend(71132) ->
    true;
is_extend(71133) ->
    true;
is_extend(71216) ->
    true;
is_extend(71217) ->
    true;
is_extend(71218) ->
    true;
is_extend(71219) ->
    true;
is_extend(71220) ->
    true;
is_extend(71221) ->
    true;
is_extend(71222) ->
    true;
is_extend(71223) ->
    true;
is_extend(71224) ->
    true;
is_extend(71225) ->
    true;
is_extend(71226) ->
    true;
is_extend(71227) ->
    true;
is_extend(71228) ->
    true;
is_extend(71229) ->
    true;
is_extend(71230) ->
    true;
is_extend(71231) ->
    true;
is_extend(71232) ->
    true;
is_extend(71339) ->
    true;
is_extend(71340) ->
    true;
is_extend(71341) ->
    true;
is_extend(71342) ->
    true;
is_extend(71343) ->
    true;
is_extend(71344) ->
    true;
is_extend(71345) ->
    true;
is_extend(71346) ->
    true;
is_extend(71347) ->
    true;
is_extend(71348) ->
    true;
is_extend(71349) ->
    true;
is_extend(71350) ->
    true;
is_extend(71351) ->
    true;
is_extend(71453) ->
    true;
is_extend(71454) ->
    true;
is_extend(71455) ->
    true;
is_extend(71456) ->
    true;
is_extend(71457) ->
    true;
is_extend(71458) ->
    true;
is_extend(71459) ->
    true;
is_extend(71460) ->
    true;
is_extend(71461) ->
    true;
is_extend(71462) ->
    true;
is_extend(71463) ->
    true;
is_extend(71464) ->
    true;
is_extend(71465) ->
    true;
is_extend(71466) ->
    true;
is_extend(71467) ->
    true;
is_extend(71724) ->
    true;
is_extend(71725) ->
    true;
is_extend(71726) ->
    true;
is_extend(71727) ->
    true;
is_extend(71728) ->
    true;
is_extend(71729) ->
    true;
is_extend(71730) ->
    true;
is_extend(71731) ->
    true;
is_extend(71732) ->
    true;
is_extend(71733) ->
    true;
is_extend(71734) ->
    true;
is_extend(71735) ->
    true;
is_extend(71736) ->
    true;
is_extend(71737) ->
    true;
is_extend(71738) ->
    true;
is_extend(72145) ->
    true;
is_extend(72146) ->
    true;
is_extend(72147) ->
    true;
is_extend(72148) ->
    true;
is_extend(72149) ->
    true;
is_extend(72150) ->
    true;
is_extend(72151) ->
    true;
is_extend(72154) ->
    true;
is_extend(72155) ->
    true;
is_extend(72156) ->
    true;
is_extend(72157) ->
    true;
is_extend(72158) ->
    true;
is_extend(72159) ->
    true;
is_extend(72160) ->
    true;
is_extend(72164) ->
    true;
is_extend(72193) ->
    true;
is_extend(72194) ->
    true;
is_extend(72195) ->
    true;
is_extend(72196) ->
    true;
is_extend(72197) ->
    true;
is_extend(72198) ->
    true;
is_extend(72199) ->
    true;
is_extend(72200) ->
    true;
is_extend(72201) ->
    true;
is_extend(72202) ->
    true;
is_extend(72243) ->
    true;
is_extend(72244) ->
    true;
is_extend(72245) ->
    true;
is_extend(72246) ->
    true;
is_extend(72247) ->
    true;
is_extend(72248) ->
    true;
is_extend(72249) ->
    true;
is_extend(72251) ->
    true;
is_extend(72252) ->
    true;
is_extend(72253) ->
    true;
is_extend(72254) ->
    true;
is_extend(72263) ->
    true;
is_extend(72273) ->
    true;
is_extend(72274) ->
    true;
is_extend(72275) ->
    true;
is_extend(72276) ->
    true;
is_extend(72277) ->
    true;
is_extend(72278) ->
    true;
is_extend(72279) ->
    true;
is_extend(72280) ->
    true;
is_extend(72281) ->
    true;
is_extend(72282) ->
    true;
is_extend(72283) ->
    true;
is_extend(72330) ->
    true;
is_extend(72331) ->
    true;
is_extend(72332) ->
    true;
is_extend(72333) ->
    true;
is_extend(72334) ->
    true;
is_extend(72335) ->
    true;
is_extend(72336) ->
    true;
is_extend(72337) ->
    true;
is_extend(72338) ->
    true;
is_extend(72339) ->
    true;
is_extend(72340) ->
    true;
is_extend(72341) ->
    true;
is_extend(72342) ->
    true;
is_extend(72343) ->
    true;
is_extend(72344) ->
    true;
is_extend(72345) ->
    true;
is_extend(72751) ->
    true;
is_extend(72752) ->
    true;
is_extend(72753) ->
    true;
is_extend(72754) ->
    true;
is_extend(72755) ->
    true;
is_extend(72756) ->
    true;
is_extend(72757) ->
    true;
is_extend(72758) ->
    true;
is_extend(72760) ->
    true;
is_extend(72761) ->
    true;
is_extend(72762) ->
    true;
is_extend(72763) ->
    true;
is_extend(72764) ->
    true;
is_extend(72765) ->
    true;
is_extend(72766) ->
    true;
is_extend(72767) ->
    true;
is_extend(72850) ->
    true;
is_extend(72851) ->
    true;
is_extend(72852) ->
    true;
is_extend(72853) ->
    true;
is_extend(72854) ->
    true;
is_extend(72855) ->
    true;
is_extend(72856) ->
    true;
is_extend(72857) ->
    true;
is_extend(72858) ->
    true;
is_extend(72859) ->
    true;
is_extend(72860) ->
    true;
is_extend(72861) ->
    true;
is_extend(72862) ->
    true;
is_extend(72863) ->
    true;
is_extend(72864) ->
    true;
is_extend(72865) ->
    true;
is_extend(72866) ->
    true;
is_extend(72867) ->
    true;
is_extend(72868) ->
    true;
is_extend(72869) ->
    true;
is_extend(72870) ->
    true;
is_extend(72871) ->
    true;
is_extend(72873) ->
    true;
is_extend(72874) ->
    true;
is_extend(72875) ->
    true;
is_extend(72876) ->
    true;
is_extend(72877) ->
    true;
is_extend(72878) ->
    true;
is_extend(72879) ->
    true;
is_extend(72880) ->
    true;
is_extend(72881) ->
    true;
is_extend(72882) ->
    true;
is_extend(72883) ->
    true;
is_extend(72884) ->
    true;
is_extend(72885) ->
    true;
is_extend(72886) ->
    true;
is_extend(73009) ->
    true;
is_extend(73010) ->
    true;
is_extend(73011) ->
    true;
is_extend(73012) ->
    true;
is_extend(73013) ->
    true;
is_extend(73014) ->
    true;
is_extend(73018) ->
    true;
is_extend(73020) ->
    true;
is_extend(73021) ->
    true;
is_extend(73023) ->
    true;
is_extend(73024) ->
    true;
is_extend(73025) ->
    true;
is_extend(73026) ->
    true;
is_extend(73027) ->
    true;
is_extend(73028) ->
    true;
is_extend(73029) ->
    true;
is_extend(73031) ->
    true;
is_extend(73098) ->
    true;
is_extend(73099) ->
    true;
is_extend(73100) ->
    true;
is_extend(73101) ->
    true;
is_extend(73102) ->
    true;
is_extend(73104) ->
    true;
is_extend(73105) ->
    true;
is_extend(73107) ->
    true;
is_extend(73108) ->
    true;
is_extend(73109) ->
    true;
is_extend(73110) ->
    true;
is_extend(73111) ->
    true;
is_extend(73459) ->
    true;
is_extend(73460) ->
    true;
is_extend(73461) ->
    true;
is_extend(73462) ->
    true;
is_extend(92912) ->
    true;
is_extend(92913) ->
    true;
is_extend(92914) ->
    true;
is_extend(92915) ->
    true;
is_extend(92916) ->
    true;
is_extend(92976) ->
    true;
is_extend(92977) ->
    true;
is_extend(92978) ->
    true;
is_extend(92979) ->
    true;
is_extend(92980) ->
    true;
is_extend(92981) ->
    true;
is_extend(92982) ->
    true;
is_extend(94031) ->
    true;
is_extend(94033) ->
    true;
is_extend(94034) ->
    true;
is_extend(94035) ->
    true;
is_extend(94036) ->
    true;
is_extend(94037) ->
    true;
is_extend(94038) ->
    true;
is_extend(94039) ->
    true;
is_extend(94040) ->
    true;
is_extend(94041) ->
    true;
is_extend(94042) ->
    true;
is_extend(94043) ->
    true;
is_extend(94044) ->
    true;
is_extend(94045) ->
    true;
is_extend(94046) ->
    true;
is_extend(94047) ->
    true;
is_extend(94048) ->
    true;
is_extend(94049) ->
    true;
is_extend(94050) ->
    true;
is_extend(94051) ->
    true;
is_extend(94052) ->
    true;
is_extend(94053) ->
    true;
is_extend(94054) ->
    true;
is_extend(94055) ->
    true;
is_extend(94056) ->
    true;
is_extend(94057) ->
    true;
is_extend(94058) ->
    true;
is_extend(94059) ->
    true;
is_extend(94060) ->
    true;
is_extend(94061) ->
    true;
is_extend(94062) ->
    true;
is_extend(94063) ->
    true;
is_extend(94064) ->
    true;
is_extend(94065) ->
    true;
is_extend(94066) ->
    true;
is_extend(94067) ->
    true;
is_extend(94068) ->
    true;
is_extend(94069) ->
    true;
is_extend(94070) ->
    true;
is_extend(94071) ->
    true;
is_extend(94072) ->
    true;
is_extend(94073) ->
    true;
is_extend(94074) ->
    true;
is_extend(94075) ->
    true;
is_extend(94076) ->
    true;
is_extend(94077) ->
    true;
is_extend(94078) ->
    true;
is_extend(94079) ->
    true;
is_extend(94080) ->
    true;
is_extend(94081) ->
    true;
is_extend(94082) ->
    true;
is_extend(94083) ->
    true;
is_extend(94084) ->
    true;
is_extend(94085) ->
    true;
is_extend(94086) ->
    true;
is_extend(94087) ->
    true;
is_extend(94095) ->
    true;
is_extend(94096) ->
    true;
is_extend(94097) ->
    true;
is_extend(94098) ->
    true;
is_extend(113821) ->
    true;
is_extend(113822) ->
    true;
is_extend(119141) ->
    true;
is_extend(119142) ->
    true;
is_extend(119143) ->
    true;
is_extend(119144) ->
    true;
is_extend(119145) ->
    true;
is_extend(119149) ->
    true;
is_extend(119150) ->
    true;
is_extend(119151) ->
    true;
is_extend(119152) ->
    true;
is_extend(119153) ->
    true;
is_extend(119154) ->
    true;
is_extend(119163) ->
    true;
is_extend(119164) ->
    true;
is_extend(119165) ->
    true;
is_extend(119166) ->
    true;
is_extend(119167) ->
    true;
is_extend(119168) ->
    true;
is_extend(119169) ->
    true;
is_extend(119170) ->
    true;
is_extend(119173) ->
    true;
is_extend(119174) ->
    true;
is_extend(119175) ->
    true;
is_extend(119176) ->
    true;
is_extend(119177) ->
    true;
is_extend(119178) ->
    true;
is_extend(119179) ->
    true;
is_extend(119210) ->
    true;
is_extend(119211) ->
    true;
is_extend(119212) ->
    true;
is_extend(119213) ->
    true;
is_extend(119362) ->
    true;
is_extend(119363) ->
    true;
is_extend(119364) ->
    true;
is_extend(121344) ->
    true;
is_extend(121345) ->
    true;
is_extend(121346) ->
    true;
is_extend(121347) ->
    true;
is_extend(121348) ->
    true;
is_extend(121349) ->
    true;
is_extend(121350) ->
    true;
is_extend(121351) ->
    true;
is_extend(121352) ->
    true;
is_extend(121353) ->
    true;
is_extend(121354) ->
    true;
is_extend(121355) ->
    true;
is_extend(121356) ->
    true;
is_extend(121357) ->
    true;
is_extend(121358) ->
    true;
is_extend(121359) ->
    true;
is_extend(121360) ->
    true;
is_extend(121361) ->
    true;
is_extend(121362) ->
    true;
is_extend(121363) ->
    true;
is_extend(121364) ->
    true;
is_extend(121365) ->
    true;
is_extend(121366) ->
    true;
is_extend(121367) ->
    true;
is_extend(121368) ->
    true;
is_extend(121369) ->
    true;
is_extend(121370) ->
    true;
is_extend(121371) ->
    true;
is_extend(121372) ->
    true;
is_extend(121373) ->
    true;
is_extend(121374) ->
    true;
is_extend(121375) ->
    true;
is_extend(121376) ->
    true;
is_extend(121377) ->
    true;
is_extend(121378) ->
    true;
is_extend(121379) ->
    true;
is_extend(121380) ->
    true;
is_extend(121381) ->
    true;
is_extend(121382) ->
    true;
is_extend(121383) ->
    true;
is_extend(121384) ->
    true;
is_extend(121385) ->
    true;
is_extend(121386) ->
    true;
is_extend(121387) ->
    true;
is_extend(121388) ->
    true;
is_extend(121389) ->
    true;
is_extend(121390) ->
    true;
is_extend(121391) ->
    true;
is_extend(121392) ->
    true;
is_extend(121393) ->
    true;
is_extend(121394) ->
    true;
is_extend(121395) ->
    true;
is_extend(121396) ->
    true;
is_extend(121397) ->
    true;
is_extend(121398) ->
    true;
is_extend(121403) ->
    true;
is_extend(121404) ->
    true;
is_extend(121405) ->
    true;
is_extend(121406) ->
    true;
is_extend(121407) ->
    true;
is_extend(121408) ->
    true;
is_extend(121409) ->
    true;
is_extend(121410) ->
    true;
is_extend(121411) ->
    true;
is_extend(121412) ->
    true;
is_extend(121413) ->
    true;
is_extend(121414) ->
    true;
is_extend(121415) ->
    true;
is_extend(121416) ->
    true;
is_extend(121417) ->
    true;
is_extend(121418) ->
    true;
is_extend(121419) ->
    true;
is_extend(121420) ->
    true;
is_extend(121421) ->
    true;
is_extend(121422) ->
    true;
is_extend(121423) ->
    true;
is_extend(121424) ->
    true;
is_extend(121425) ->
    true;
is_extend(121426) ->
    true;
is_extend(121427) ->
    true;
is_extend(121428) ->
    true;
is_extend(121429) ->
    true;
is_extend(121430) ->
    true;
is_extend(121431) ->
    true;
is_extend(121432) ->
    true;
is_extend(121433) ->
    true;
is_extend(121434) ->
    true;
is_extend(121435) ->
    true;
is_extend(121436) ->
    true;
is_extend(121437) ->
    true;
is_extend(121438) ->
    true;
is_extend(121439) ->
    true;
is_extend(121440) ->
    true;
is_extend(121441) ->
    true;
is_extend(121442) ->
    true;
is_extend(121443) ->
    true;
is_extend(121444) ->
    true;
is_extend(121445) ->
    true;
is_extend(121446) ->
    true;
is_extend(121447) ->
    true;
is_extend(121448) ->
    true;
is_extend(121449) ->
    true;
is_extend(121450) ->
    true;
is_extend(121451) ->
    true;
is_extend(121452) ->
    true;
is_extend(121461) ->
    true;
is_extend(121476) ->
    true;
is_extend(121499) ->
    true;
is_extend(121500) ->
    true;
is_extend(121501) ->
    true;
is_extend(121502) ->
    true;
is_extend(121503) ->
    true;
is_extend(121505) ->
    true;
is_extend(121506) ->
    true;
is_extend(121507) ->
    true;
is_extend(121508) ->
    true;
is_extend(121509) ->
    true;
is_extend(121510) ->
    true;
is_extend(121511) ->
    true;
is_extend(121512) ->
    true;
is_extend(121513) ->
    true;
is_extend(121514) ->
    true;
is_extend(121515) ->
    true;
is_extend(121516) ->
    true;
is_extend(121517) ->
    true;
is_extend(121518) ->
    true;
is_extend(121519) ->
    true;
is_extend(122880) ->
    true;
is_extend(122881) ->
    true;
is_extend(122882) ->
    true;
is_extend(122883) ->
    true;
is_extend(122884) ->
    true;
is_extend(122885) ->
    true;
is_extend(122886) ->
    true;
is_extend(122888) ->
    true;
is_extend(122889) ->
    true;
is_extend(122890) ->
    true;
is_extend(122891) ->
    true;
is_extend(122892) ->
    true;
is_extend(122893) ->
    true;
is_extend(122894) ->
    true;
is_extend(122895) ->
    true;
is_extend(122896) ->
    true;
is_extend(122897) ->
    true;
is_extend(122898) ->
    true;
is_extend(122899) ->
    true;
is_extend(122900) ->
    true;
is_extend(122901) ->
    true;
is_extend(122902) ->
    true;
is_extend(122903) ->
    true;
is_extend(122904) ->
    true;
is_extend(122907) ->
    true;
is_extend(122908) ->
    true;
is_extend(122909) ->
    true;
is_extend(122910) ->
    true;
is_extend(122911) ->
    true;
is_extend(122912) ->
    true;
is_extend(122913) ->
    true;
is_extend(122915) ->
    true;
is_extend(122916) ->
    true;
is_extend(122918) ->
    true;
is_extend(122919) ->
    true;
is_extend(122920) ->
    true;
is_extend(122921) ->
    true;
is_extend(122922) ->
    true;
is_extend(123184) ->
    true;
is_extend(123185) ->
    true;
is_extend(123186) ->
    true;
is_extend(123187) ->
    true;
is_extend(123188) ->
    true;
is_extend(123189) ->
    true;
is_extend(123190) ->
    true;
is_extend(123628) ->
    true;
is_extend(123629) ->
    true;
is_extend(123630) ->
    true;
is_extend(123631) ->
    true;
is_extend(125136) ->
    true;
is_extend(125137) ->
    true;
is_extend(125138) ->
    true;
is_extend(125139) ->
    true;
is_extend(125140) ->
    true;
is_extend(125141) ->
    true;
is_extend(125142) ->
    true;
is_extend(125252) ->
    true;
is_extend(125253) ->
    true;
is_extend(125254) ->
    true;
is_extend(125255) ->
    true;
is_extend(125256) ->
    true;
is_extend(125257) ->
    true;
is_extend(125258) ->
    true;
is_extend(127995) ->
    true;
is_extend(127996) ->
    true;
is_extend(127997) ->
    true;
is_extend(127998) ->
    true;
is_extend(127999) ->
    true;
is_extend(917536) ->
    true;
is_extend(917537) ->
    true;
is_extend(917538) ->
    true;
is_extend(917539) ->
    true;
is_extend(917540) ->
    true;
is_extend(917541) ->
    true;
is_extend(917542) ->
    true;
is_extend(917543) ->
    true;
is_extend(917544) ->
    true;
is_extend(917545) ->
    true;
is_extend(917546) ->
    true;
is_extend(917547) ->
    true;
is_extend(917548) ->
    true;
is_extend(917549) ->
    true;
is_extend(917550) ->
    true;
is_extend(917551) ->
    true;
is_extend(917552) ->
    true;
is_extend(917553) ->
    true;
is_extend(917554) ->
    true;
is_extend(917555) ->
    true;
is_extend(917556) ->
    true;
is_extend(917557) ->
    true;
is_extend(917558) ->
    true;
is_extend(917559) ->
    true;
is_extend(917560) ->
    true;
is_extend(917561) ->
    true;
is_extend(917562) ->
    true;
is_extend(917563) ->
    true;
is_extend(917564) ->
    true;
is_extend(917565) ->
    true;
is_extend(917566) ->
    true;
is_extend(917567) ->
    true;
is_extend(917568) ->
    true;
is_extend(917569) ->
    true;
is_extend(917570) ->
    true;
is_extend(917571) ->
    true;
is_extend(917572) ->
    true;
is_extend(917573) ->
    true;
is_extend(917574) ->
    true;
is_extend(917575) ->
    true;
is_extend(917576) ->
    true;
is_extend(917577) ->
    true;
is_extend(917578) ->
    true;
is_extend(917579) ->
    true;
is_extend(917580) ->
    true;
is_extend(917581) ->
    true;
is_extend(917582) ->
    true;
is_extend(917583) ->
    true;
is_extend(917584) ->
    true;
is_extend(917585) ->
    true;
is_extend(917586) ->
    true;
is_extend(917587) ->
    true;
is_extend(917588) ->
    true;
is_extend(917589) ->
    true;
is_extend(917590) ->
    true;
is_extend(917591) ->
    true;
is_extend(917592) ->
    true;
is_extend(917593) ->
    true;
is_extend(917594) ->
    true;
is_extend(917595) ->
    true;
is_extend(917596) ->
    true;
is_extend(917597) ->
    true;
is_extend(917598) ->
    true;
is_extend(917599) ->
    true;
is_extend(917600) ->
    true;
is_extend(917601) ->
    true;
is_extend(917602) ->
    true;
is_extend(917603) ->
    true;
is_extend(917604) ->
    true;
is_extend(917605) ->
    true;
is_extend(917606) ->
    true;
is_extend(917607) ->
    true;
is_extend(917608) ->
    true;
is_extend(917609) ->
    true;
is_extend(917610) ->
    true;
is_extend(917611) ->
    true;
is_extend(917612) ->
    true;
is_extend(917613) ->
    true;
is_extend(917614) ->
    true;
is_extend(917615) ->
    true;
is_extend(917616) ->
    true;
is_extend(917617) ->
    true;
is_extend(917618) ->
    true;
is_extend(917619) ->
    true;
is_extend(917620) ->
    true;
is_extend(917621) ->
    true;
is_extend(917622) ->
    true;
is_extend(917623) ->
    true;
is_extend(917624) ->
    true;
is_extend(917625) ->
    true;
is_extend(917626) ->
    true;
is_extend(917627) ->
    true;
is_extend(917628) ->
    true;
is_extend(917629) ->
    true;
is_extend(917630) ->
    true;
is_extend(917631) ->
    true;
is_extend(917760) ->
    true;
is_extend(917761) ->
    true;
is_extend(917762) ->
    true;
is_extend(917763) ->
    true;
is_extend(917764) ->
    true;
is_extend(917765) ->
    true;
is_extend(917766) ->
    true;
is_extend(917767) ->
    true;
is_extend(917768) ->
    true;
is_extend(917769) ->
    true;
is_extend(917770) ->
    true;
is_extend(917771) ->
    true;
is_extend(917772) ->
    true;
is_extend(917773) ->
    true;
is_extend(917774) ->
    true;
is_extend(917775) ->
    true;
is_extend(917776) ->
    true;
is_extend(917777) ->
    true;
is_extend(917778) ->
    true;
is_extend(917779) ->
    true;
is_extend(917780) ->
    true;
is_extend(917781) ->
    true;
is_extend(917782) ->
    true;
is_extend(917783) ->
    true;
is_extend(917784) ->
    true;
is_extend(917785) ->
    true;
is_extend(917786) ->
    true;
is_extend(917787) ->
    true;
is_extend(917788) ->
    true;
is_extend(917789) ->
    true;
is_extend(917790) ->
    true;
is_extend(917791) ->
    true;
is_extend(917792) ->
    true;
is_extend(917793) ->
    true;
is_extend(917794) ->
    true;
is_extend(917795) ->
    true;
is_extend(917796) ->
    true;
is_extend(917797) ->
    true;
is_extend(917798) ->
    true;
is_extend(917799) ->
    true;
is_extend(917800) ->
    true;
is_extend(917801) ->
    true;
is_extend(917802) ->
    true;
is_extend(917803) ->
    true;
is_extend(917804) ->
    true;
is_extend(917805) ->
    true;
is_extend(917806) ->
    true;
is_extend(917807) ->
    true;
is_extend(917808) ->
    true;
is_extend(917809) ->
    true;
is_extend(917810) ->
    true;
is_extend(917811) ->
    true;
is_extend(917812) ->
    true;
is_extend(917813) ->
    true;
is_extend(917814) ->
    true;
is_extend(917815) ->
    true;
is_extend(917816) ->
    true;
is_extend(917817) ->
    true;
is_extend(917818) ->
    true;
is_extend(917819) ->
    true;
is_extend(917820) ->
    true;
is_extend(917821) ->
    true;
is_extend(917822) ->
    true;
is_extend(917823) ->
    true;
is_extend(917824) ->
    true;
is_extend(917825) ->
    true;
is_extend(917826) ->
    true;
is_extend(917827) ->
    true;
is_extend(917828) ->
    true;
is_extend(917829) ->
    true;
is_extend(917830) ->
    true;
is_extend(917831) ->
    true;
is_extend(917832) ->
    true;
is_extend(917833) ->
    true;
is_extend(917834) ->
    true;
is_extend(917835) ->
    true;
is_extend(917836) ->
    true;
is_extend(917837) ->
    true;
is_extend(917838) ->
    true;
is_extend(917839) ->
    true;
is_extend(917840) ->
    true;
is_extend(917841) ->
    true;
is_extend(917842) ->
    true;
is_extend(917843) ->
    true;
is_extend(917844) ->
    true;
is_extend(917845) ->
    true;
is_extend(917846) ->
    true;
is_extend(917847) ->
    true;
is_extend(917848) ->
    true;
is_extend(917849) ->
    true;
is_extend(917850) ->
    true;
is_extend(917851) ->
    true;
is_extend(917852) ->
    true;
is_extend(917853) ->
    true;
is_extend(917854) ->
    true;
is_extend(917855) ->
    true;
is_extend(917856) ->
    true;
is_extend(917857) ->
    true;
is_extend(917858) ->
    true;
is_extend(917859) ->
    true;
is_extend(917860) ->
    true;
is_extend(917861) ->
    true;
is_extend(917862) ->
    true;
is_extend(917863) ->
    true;
is_extend(917864) ->
    true;
is_extend(917865) ->
    true;
is_extend(917866) ->
    true;
is_extend(917867) ->
    true;
is_extend(917868) ->
    true;
is_extend(917869) ->
    true;
is_extend(917870) ->
    true;
is_extend(917871) ->
    true;
is_extend(917872) ->
    true;
is_extend(917873) ->
    true;
is_extend(917874) ->
    true;
is_extend(917875) ->
    true;
is_extend(917876) ->
    true;
is_extend(917877) ->
    true;
is_extend(917878) ->
    true;
is_extend(917879) ->
    true;
is_extend(917880) ->
    true;
is_extend(917881) ->
    true;
is_extend(917882) ->
    true;
is_extend(917883) ->
    true;
is_extend(917884) ->
    true;
is_extend(917885) ->
    true;
is_extend(917886) ->
    true;
is_extend(917887) ->
    true;
is_extend(917888) ->
    true;
is_extend(917889) ->
    true;
is_extend(917890) ->
    true;
is_extend(917891) ->
    true;
is_extend(917892) ->
    true;
is_extend(917893) ->
    true;
is_extend(917894) ->
    true;
is_extend(917895) ->
    true;
is_extend(917896) ->
    true;
is_extend(917897) ->
    true;
is_extend(917898) ->
    true;
is_extend(917899) ->
    true;
is_extend(917900) ->
    true;
is_extend(917901) ->
    true;
is_extend(917902) ->
    true;
is_extend(917903) ->
    true;
is_extend(917904) ->
    true;
is_extend(917905) ->
    true;
is_extend(917906) ->
    true;
is_extend(917907) ->
    true;
is_extend(917908) ->
    true;
is_extend(917909) ->
    true;
is_extend(917910) ->
    true;
is_extend(917911) ->
    true;
is_extend(917912) ->
    true;
is_extend(917913) ->
    true;
is_extend(917914) ->
    true;
is_extend(917915) ->
    true;
is_extend(917916) ->
    true;
is_extend(917917) ->
    true;
is_extend(917918) ->
    true;
is_extend(917919) ->
    true;
is_extend(917920) ->
    true;
is_extend(917921) ->
    true;
is_extend(917922) ->
    true;
is_extend(917923) ->
    true;
is_extend(917924) ->
    true;
is_extend(917925) ->
    true;
is_extend(917926) ->
    true;
is_extend(917927) ->
    true;
is_extend(917928) ->
    true;
is_extend(917929) ->
    true;
is_extend(917930) ->
    true;
is_extend(917931) ->
    true;
is_extend(917932) ->
    true;
is_extend(917933) ->
    true;
is_extend(917934) ->
    true;
is_extend(917935) ->
    true;
is_extend(917936) ->
    true;
is_extend(917937) ->
    true;
is_extend(917938) ->
    true;
is_extend(917939) ->
    true;
is_extend(917940) ->
    true;
is_extend(917941) ->
    true;
is_extend(917942) ->
    true;
is_extend(917943) ->
    true;
is_extend(917944) ->
    true;
is_extend(917945) ->
    true;
is_extend(917946) ->
    true;
is_extend(917947) ->
    true;
is_extend(917948) ->
    true;
is_extend(917949) ->
    true;
is_extend(917950) ->
    true;
is_extend(917951) ->
    true;
is_extend(917952) ->
    true;
is_extend(917953) ->
    true;
is_extend(917954) ->
    true;
is_extend(917955) ->
    true;
is_extend(917956) ->
    true;
is_extend(917957) ->
    true;
is_extend(917958) ->
    true;
is_extend(917959) ->
    true;
is_extend(917960) ->
    true;
is_extend(917961) ->
    true;
is_extend(917962) ->
    true;
is_extend(917963) ->
    true;
is_extend(917964) ->
    true;
is_extend(917965) ->
    true;
is_extend(917966) ->
    true;
is_extend(917967) ->
    true;
is_extend(917968) ->
    true;
is_extend(917969) ->
    true;
is_extend(917970) ->
    true;
is_extend(917971) ->
    true;
is_extend(917972) ->
    true;
is_extend(917973) ->
    true;
is_extend(917974) ->
    true;
is_extend(917975) ->
    true;
is_extend(917976) ->
    true;
is_extend(917977) ->
    true;
is_extend(917978) ->
    true;
is_extend(917979) ->
    true;
is_extend(917980) ->
    true;
is_extend(917981) ->
    true;
is_extend(917982) ->
    true;
is_extend(917983) ->
    true;
is_extend(917984) ->
    true;
is_extend(917985) ->
    true;
is_extend(917986) ->
    true;
is_extend(917987) ->
    true;
is_extend(917988) ->
    true;
is_extend(917989) ->
    true;
is_extend(917990) ->
    true;
is_extend(917991) ->
    true;
is_extend(917992) ->
    true;
is_extend(917993) ->
    true;
is_extend(917994) ->
    true;
is_extend(917995) ->
    true;
is_extend(917996) ->
    true;
is_extend(917997) ->
    true;
is_extend(917998) ->
    true;
is_extend(917999) ->
    true;
is_extend(_) ->
    false.

gc_ext_pict(T,Acc) ->
    gc_ext_pict(cp(T),T,Acc).

gc_ext_pict([CP| R1],T0,Acc) ->
    case is_extend(CP) of
        zwj->
            gc_ext_pict_zwj(cp(R1),R1,[CP| Acc]);
        true->
            gc_ext_pict(R1,[CP| Acc]);
        false->
            case Acc of
                [A]->
                    [A| T0];
                _->
                    [lists:reverse(Acc)| T0]
            end
    end;
gc_ext_pict([],_T0,Acc) ->
    case Acc of
        [A]->
            [A];
        _->
            [lists:reverse(Acc)]
    end;
gc_ext_pict({error,R},T,Acc) ->
    gc_ext_pict([],T,Acc) ++ [R].

gc_ext_pict_zwj([CP| R1],T0,Acc) ->
    case is_ext_pict(CP) of
        true->
            gc_ext_pict(R1,[CP| Acc]);
        false->
            case Acc of
                [A]->
                    [A| T0];
                _->
                    [lists:reverse(Acc)| T0]
            end
    end;
gc_ext_pict_zwj([],_,Acc) ->
    case Acc of
        [A]->
            [A];
        _->
            [lists:reverse(Acc)]
    end;
gc_ext_pict_zwj({error,R},T,Acc) ->
    gc_ext_pict_zwj([],T,Acc) ++ [R].

is_ext_pict(169) ->
    true;
is_ext_pict(174) ->
    true;
is_ext_pict(8252) ->
    true;
is_ext_pict(8265) ->
    true;
is_ext_pict(8482) ->
    true;
is_ext_pict(8505) ->
    true;
is_ext_pict(9000) ->
    true;
is_ext_pict(9096) ->
    true;
is_ext_pict(9167) ->
    true;
is_ext_pict(9410) ->
    true;
is_ext_pict(9654) ->
    true;
is_ext_pict(9664) ->
    true;
is_ext_pict(10004) ->
    true;
is_ext_pict(10006) ->
    true;
is_ext_pict(10013) ->
    true;
is_ext_pict(10017) ->
    true;
is_ext_pict(10024) ->
    true;
is_ext_pict(10052) ->
    true;
is_ext_pict(10055) ->
    true;
is_ext_pict(10060) ->
    true;
is_ext_pict(10062) ->
    true;
is_ext_pict(10071) ->
    true;
is_ext_pict(10145) ->
    true;
is_ext_pict(10160) ->
    true;
is_ext_pict(10175) ->
    true;
is_ext_pict(11088) ->
    true;
is_ext_pict(11093) ->
    true;
is_ext_pict(12336) ->
    true;
is_ext_pict(12349) ->
    true;
is_ext_pict(12951) ->
    true;
is_ext_pict(12953) ->
    true;
is_ext_pict(127279) ->
    true;
is_ext_pict(127374) ->
    true;
is_ext_pict(127514) ->
    true;
is_ext_pict(127535) ->
    true;
is_ext_pict(CP)
    when 127340 =< CP,
    CP =< 127345->
    true;
is_ext_pict(CP)
    when 9872 =< CP,
    CP =< 9989->
    true;
is_ext_pict(CP)
    when 9642 =< CP,
    CP =< 9643->
    true;
is_ext_pict(CP)
    when 8986 =< CP,
    CP =< 8987->
    true;
is_ext_pict(CP)
    when 8596 =< CP,
    CP =< 8601->
    true;
is_ext_pict(CP)
    when 8617 =< CP,
    CP =< 8618->
    true;
is_ext_pict(CP)
    when 9193 =< CP,
    CP =< 9203->
    true;
is_ext_pict(CP)
    when 9208 =< CP,
    CP =< 9210->
    true;
is_ext_pict(CP)
    when 9735 =< CP,
    CP =< 9746->
    true;
is_ext_pict(CP)
    when 9723 =< CP,
    CP =< 9726->
    true;
is_ext_pict(CP)
    when 9728 =< CP,
    CP =< 9733->
    true;
is_ext_pict(CP)
    when 9748 =< CP,
    CP =< 9861->
    true;
is_ext_pict(CP)
    when 10548 =< CP,
    CP =< 10549->
    true;
is_ext_pict(CP)
    when 10067 =< CP,
    CP =< 10069->
    true;
is_ext_pict(CP)
    when 9992 =< CP,
    CP =< 10002->
    true;
is_ext_pict(CP)
    when 10035 =< CP,
    CP =< 10036->
    true;
is_ext_pict(CP)
    when 10083 =< CP,
    CP =< 10087->
    true;
is_ext_pict(CP)
    when 10133 =< CP,
    CP =< 10135->
    true;
is_ext_pict(CP)
    when 126976 =< CP,
    CP =< 127231->
    true;
is_ext_pict(CP)
    when 11013 =< CP,
    CP =< 11015->
    true;
is_ext_pict(CP)
    when 11035 =< CP,
    CP =< 11036->
    true;
is_ext_pict(CP)
    when 127245 =< CP,
    CP =< 127247->
    true;
is_ext_pict(CP)
    when 128884 =< CP,
    CP =< 128895->
    true;
is_ext_pict(CP)
    when 127548 =< CP,
    CP =< 127551->
    true;
is_ext_pict(CP)
    when 127405 =< CP,
    CP =< 127461->
    true;
is_ext_pict(CP)
    when 127358 =< CP,
    CP =< 127359->
    true;
is_ext_pict(CP)
    when 127377 =< CP,
    CP =< 127386->
    true;
is_ext_pict(CP)
    when 127489 =< CP,
    CP =< 127503->
    true;
is_ext_pict(CP)
    when 127538 =< CP,
    CP =< 127546->
    true;
is_ext_pict(CP)
    when 128326 =< CP,
    CP =< 128591->
    true;
is_ext_pict(CP)
    when 127561 =< CP,
    CP =< 127994->
    true;
is_ext_pict(CP)
    when 128000 =< CP,
    CP =< 128317->
    true;
is_ext_pict(CP)
    when 128640 =< CP,
    CP =< 128767->
    true;
is_ext_pict(CP)
    when 129160 =< CP,
    CP =< 129167->
    true;
is_ext_pict(CP)
    when 129096 =< CP,
    CP =< 129103->
    true;
is_ext_pict(CP)
    when 128981 =< CP,
    CP =< 129023->
    true;
is_ext_pict(CP)
    when 129036 =< CP,
    CP =< 129039->
    true;
is_ext_pict(CP)
    when 129114 =< CP,
    CP =< 129119->
    true;
is_ext_pict(CP)
    when 129340 =< CP,
    CP =< 129349->
    true;
is_ext_pict(CP)
    when 129198 =< CP,
    CP =< 129279->
    true;
is_ext_pict(CP)
    when 129292 =< CP,
    CP =< 129338->
    true;
is_ext_pict(CP)
    when 129351 =< CP,
    CP =< 131069->
    true;
is_ext_pict(_) ->
    false.

gc_regional(R0,CP0) ->
    case cp(R0) of
        [CP| R1]
            when 127462 =< CP,
            CP =< 127487->
            gc_extend2(cp(R1),R1,[CP, CP0]);
        R1->
            gc_extend(R1,R0,CP0)
    end.

gc_h_L(R0,Acc) ->
    case cp(R0) of
        [CP| R1]
            when 4352 =< CP,
            CP =< 4447->
            gc_h_L(R1,[CP| Acc]);
        [CP| R1]
            when 43360 =< CP,
            CP =< 43388->
            gc_h_L(R1,[CP| Acc]);
        [CP| R1]
            when 4448 =< CP,
            CP =< 4519->
            gc_h_V(R1,[CP| Acc]);
        [CP| R1]
            when 55216 =< CP,
            CP =< 55238->
            gc_h_V(R1,[CP| Acc]);
        R1->
            gc_h_lv_lvt(R1,R0,Acc)
    end.

gc_h_V(R0,Acc) ->
    case cp(R0) of
        [CP| R1]
            when 4448 =< CP,
            CP =< 4519->
            gc_h_V(R1,[CP| Acc]);
        [CP| R1]
            when 55216 =< CP,
            CP =< 55238->
            gc_h_V(R1,[CP| Acc]);
        [CP| R1]
            when 4520 =< CP,
            CP =< 4607->
            gc_h_T(R1,[CP| Acc]);
        [CP| R1]
            when 55243 =< CP,
            CP =< 55291->
            gc_h_T(R1,[CP| Acc]);
        R1->
            case Acc of
                [CP]->
                    gc_extend(R1,R0,CP);
                _->
                    gc_extend2(R1,R0,Acc)
            end
    end.

gc_h_T(R0,Acc) ->
    case cp(R0) of
        [CP| R1]
            when 4520 =< CP,
            CP =< 4607->
            gc_h_T(R1,[CP| Acc]);
        [CP| R1]
            when 55243 =< CP,
            CP =< 55291->
            gc_h_T(R1,[CP| Acc]);
        R1->
            case Acc of
                [CP]->
                    gc_extend(R1,R0,CP);
                _->
                    gc_extend2(R1,R0,Acc)
            end
    end.

gc_h_lv_lvt([44032 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44060 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44088 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44116 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44144 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44172 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44200 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44228 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44256 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44284 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44312 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44340 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44368 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44396 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44424 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44452 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44480 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44508 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44536 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44564 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44592 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44620 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44648 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44676 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44704 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44732 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44760 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44788 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44816 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44844 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44872 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44900 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44928 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44956 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([44984 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45012 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45040 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45068 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45096 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45124 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45152 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45180 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45208 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45236 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45264 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45292 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45320 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45348 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45376 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45404 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45432 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45460 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45488 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45516 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45544 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45572 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45600 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45628 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45656 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45684 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45712 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45740 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45768 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45796 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45824 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45852 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45880 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45908 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45936 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45964 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([45992 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46020 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46048 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46076 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46104 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46132 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46160 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46188 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46216 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46244 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46272 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46300 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46328 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46356 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46384 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46412 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46440 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46468 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46496 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46524 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46552 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46580 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46608 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46636 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46664 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46692 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46720 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46748 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46776 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46804 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46832 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46860 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46888 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46916 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46944 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([46972 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47000 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47028 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47056 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47084 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47112 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47140 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47168 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47196 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47224 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47252 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47280 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47308 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47336 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47364 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47392 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47420 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47448 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47476 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47504 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47532 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47560 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47588 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47616 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47644 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47672 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47700 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47728 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47756 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47784 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47812 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47840 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47868 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47896 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47924 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47952 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([47980 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48008 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48036 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48064 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48092 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48120 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48148 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48176 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48204 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48232 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48260 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48288 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48316 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48344 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48372 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48400 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48428 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48456 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48484 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48512 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48540 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48568 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48596 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48624 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48652 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48680 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48708 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48736 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48764 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48792 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48820 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48848 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48876 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48904 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48932 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48960 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([48988 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49016 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49044 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49072 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49100 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49128 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49156 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49184 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49212 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49240 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49268 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49296 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49324 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49352 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49380 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49408 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49436 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49464 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49492 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49520 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49548 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49576 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49604 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49632 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49660 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49688 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49716 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49744 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49772 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49800 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49828 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49856 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49884 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49912 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49940 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49968 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([49996 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50024 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50052 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50080 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50108 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50136 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50164 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50192 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50220 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50248 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50276 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50304 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50332 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50360 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50388 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50416 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50444 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50472 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50500 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50528 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50556 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50584 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50612 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50640 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50668 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50696 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50724 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50752 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50780 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50808 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50836 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50864 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50892 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50920 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50948 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([50976 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51004 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51032 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51060 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51088 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51116 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51144 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51172 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51200 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51228 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51256 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51284 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51312 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51340 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51368 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51396 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51424 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51452 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51480 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51508 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51536 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51564 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51592 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51620 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51648 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51676 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51704 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51732 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51760 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51788 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51816 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51844 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51872 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51900 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51928 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51956 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([51984 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52012 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52040 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52068 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52096 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52124 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52152 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52180 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52208 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52236 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52264 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52292 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52320 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52348 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52376 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52404 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52432 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52460 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52488 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52516 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52544 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52572 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52600 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52628 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52656 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52684 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52712 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52740 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52768 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52796 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52824 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52852 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52880 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52908 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52936 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52964 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([52992 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53020 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53048 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53076 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53104 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53132 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53160 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53188 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53216 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53244 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53272 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53300 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53328 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53356 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53384 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53412 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53440 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53468 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53496 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53524 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53552 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53580 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53608 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53636 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53664 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53692 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53720 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53748 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53776 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53804 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53832 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53860 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53888 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53916 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53944 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([53972 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54000 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54028 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54056 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54084 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54112 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54140 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54168 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54196 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54224 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54252 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54280 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54308 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54336 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54364 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54392 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54420 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54448 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54476 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54504 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54532 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54560 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54588 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54616 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54644 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54672 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54700 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54728 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54756 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54784 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54812 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54840 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54868 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54896 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54924 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54952 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([54980 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55008 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55036 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55064 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55092 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55120 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55148 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([55176 = CP| R1],R0,Acc) ->
    gc_h_V(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49605 =< CP,
    CP =< 49631->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46805 =< CP,
    CP =< 46831->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45405 =< CP,
    CP =< 45431->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44705 =< CP,
    CP =< 44731->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44369 =< CP,
    CP =< 44395->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44201 =< CP,
    CP =< 44227->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44117 =< CP,
    CP =< 44143->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44033 =< CP,
    CP =< 44059->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44061 =< CP,
    CP =< 44087->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44089 =< CP,
    CP =< 44115->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44145 =< CP,
    CP =< 44171->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44173 =< CP,
    CP =< 44199->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44285 =< CP,
    CP =< 44311->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44229 =< CP,
    CP =< 44255->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44257 =< CP,
    CP =< 44283->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44313 =< CP,
    CP =< 44339->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44341 =< CP,
    CP =< 44367->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44537 =< CP,
    CP =< 44563->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44453 =< CP,
    CP =< 44479->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44397 =< CP,
    CP =< 44423->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44425 =< CP,
    CP =< 44451->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44481 =< CP,
    CP =< 44507->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44509 =< CP,
    CP =< 44535->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44621 =< CP,
    CP =< 44647->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44565 =< CP,
    CP =< 44591->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44593 =< CP,
    CP =< 44619->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44649 =< CP,
    CP =< 44675->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44677 =< CP,
    CP =< 44703->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45069 =< CP,
    CP =< 45095->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44901 =< CP,
    CP =< 44927->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44817 =< CP,
    CP =< 44843->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44733 =< CP,
    CP =< 44759->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44761 =< CP,
    CP =< 44787->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44789 =< CP,
    CP =< 44815->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44845 =< CP,
    CP =< 44871->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44873 =< CP,
    CP =< 44899->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44985 =< CP,
    CP =< 45011->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44929 =< CP,
    CP =< 44955->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 44957 =< CP,
    CP =< 44983->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45013 =< CP,
    CP =< 45039->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45041 =< CP,
    CP =< 45067->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45237 =< CP,
    CP =< 45263->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45153 =< CP,
    CP =< 45179->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45097 =< CP,
    CP =< 45123->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45125 =< CP,
    CP =< 45151->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45181 =< CP,
    CP =< 45207->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45209 =< CP,
    CP =< 45235->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45321 =< CP,
    CP =< 45347->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45265 =< CP,
    CP =< 45291->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45293 =< CP,
    CP =< 45319->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45349 =< CP,
    CP =< 45375->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45377 =< CP,
    CP =< 45403->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46105 =< CP,
    CP =< 46131->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45769 =< CP,
    CP =< 45795->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45601 =< CP,
    CP =< 45627->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45517 =< CP,
    CP =< 45543->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45433 =< CP,
    CP =< 45459->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45461 =< CP,
    CP =< 45487->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45489 =< CP,
    CP =< 45515->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45545 =< CP,
    CP =< 45571->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45573 =< CP,
    CP =< 45599->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45685 =< CP,
    CP =< 45711->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45629 =< CP,
    CP =< 45655->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45657 =< CP,
    CP =< 45683->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45713 =< CP,
    CP =< 45739->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45741 =< CP,
    CP =< 45767->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45937 =< CP,
    CP =< 45963->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45853 =< CP,
    CP =< 45879->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45797 =< CP,
    CP =< 45823->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45825 =< CP,
    CP =< 45851->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45881 =< CP,
    CP =< 45907->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45909 =< CP,
    CP =< 45935->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46021 =< CP,
    CP =< 46047->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45965 =< CP,
    CP =< 45991->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 45993 =< CP,
    CP =< 46019->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46049 =< CP,
    CP =< 46075->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46077 =< CP,
    CP =< 46103->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46469 =< CP,
    CP =< 46495->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46301 =< CP,
    CP =< 46327->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46217 =< CP,
    CP =< 46243->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46133 =< CP,
    CP =< 46159->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46161 =< CP,
    CP =< 46187->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46189 =< CP,
    CP =< 46215->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46245 =< CP,
    CP =< 46271->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46273 =< CP,
    CP =< 46299->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46385 =< CP,
    CP =< 46411->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46329 =< CP,
    CP =< 46355->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46357 =< CP,
    CP =< 46383->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46413 =< CP,
    CP =< 46439->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46441 =< CP,
    CP =< 46467->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46637 =< CP,
    CP =< 46663->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46553 =< CP,
    CP =< 46579->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46497 =< CP,
    CP =< 46523->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46525 =< CP,
    CP =< 46551->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46581 =< CP,
    CP =< 46607->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46609 =< CP,
    CP =< 46635->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46721 =< CP,
    CP =< 46747->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46665 =< CP,
    CP =< 46691->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46693 =< CP,
    CP =< 46719->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46749 =< CP,
    CP =< 46775->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46777 =< CP,
    CP =< 46803->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48205 =< CP,
    CP =< 48231->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47505 =< CP,
    CP =< 47531->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47169 =< CP,
    CP =< 47195->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47001 =< CP,
    CP =< 47027->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46917 =< CP,
    CP =< 46943->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46833 =< CP,
    CP =< 46859->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46861 =< CP,
    CP =< 46887->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46889 =< CP,
    CP =< 46915->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46945 =< CP,
    CP =< 46971->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 46973 =< CP,
    CP =< 46999->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47085 =< CP,
    CP =< 47111->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47029 =< CP,
    CP =< 47055->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47057 =< CP,
    CP =< 47083->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47113 =< CP,
    CP =< 47139->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47141 =< CP,
    CP =< 47167->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47337 =< CP,
    CP =< 47363->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47253 =< CP,
    CP =< 47279->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47197 =< CP,
    CP =< 47223->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47225 =< CP,
    CP =< 47251->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47281 =< CP,
    CP =< 47307->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47309 =< CP,
    CP =< 47335->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47421 =< CP,
    CP =< 47447->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47365 =< CP,
    CP =< 47391->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47393 =< CP,
    CP =< 47419->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47449 =< CP,
    CP =< 47475->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47477 =< CP,
    CP =< 47503->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47869 =< CP,
    CP =< 47895->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47701 =< CP,
    CP =< 47727->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47617 =< CP,
    CP =< 47643->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47533 =< CP,
    CP =< 47559->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47561 =< CP,
    CP =< 47587->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47589 =< CP,
    CP =< 47615->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47645 =< CP,
    CP =< 47671->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47673 =< CP,
    CP =< 47699->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47785 =< CP,
    CP =< 47811->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47729 =< CP,
    CP =< 47755->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47757 =< CP,
    CP =< 47783->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47813 =< CP,
    CP =< 47839->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47841 =< CP,
    CP =< 47867->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48037 =< CP,
    CP =< 48063->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47953 =< CP,
    CP =< 47979->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47897 =< CP,
    CP =< 47923->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47925 =< CP,
    CP =< 47951->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 47981 =< CP,
    CP =< 48007->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48009 =< CP,
    CP =< 48035->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48121 =< CP,
    CP =< 48147->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48065 =< CP,
    CP =< 48091->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48093 =< CP,
    CP =< 48119->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48149 =< CP,
    CP =< 48175->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48177 =< CP,
    CP =< 48203->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48905 =< CP,
    CP =< 48931->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48569 =< CP,
    CP =< 48595->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48401 =< CP,
    CP =< 48427->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48317 =< CP,
    CP =< 48343->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48233 =< CP,
    CP =< 48259->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48261 =< CP,
    CP =< 48287->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48289 =< CP,
    CP =< 48315->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48345 =< CP,
    CP =< 48371->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48373 =< CP,
    CP =< 48399->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48485 =< CP,
    CP =< 48511->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48429 =< CP,
    CP =< 48455->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48457 =< CP,
    CP =< 48483->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48513 =< CP,
    CP =< 48539->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48541 =< CP,
    CP =< 48567->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48737 =< CP,
    CP =< 48763->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48653 =< CP,
    CP =< 48679->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48597 =< CP,
    CP =< 48623->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48625 =< CP,
    CP =< 48651->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48681 =< CP,
    CP =< 48707->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48709 =< CP,
    CP =< 48735->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48821 =< CP,
    CP =< 48847->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48765 =< CP,
    CP =< 48791->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48793 =< CP,
    CP =< 48819->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48849 =< CP,
    CP =< 48875->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48877 =< CP,
    CP =< 48903->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49269 =< CP,
    CP =< 49295->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49101 =< CP,
    CP =< 49127->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49017 =< CP,
    CP =< 49043->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48933 =< CP,
    CP =< 48959->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48961 =< CP,
    CP =< 48987->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 48989 =< CP,
    CP =< 49015->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49045 =< CP,
    CP =< 49071->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49073 =< CP,
    CP =< 49099->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49185 =< CP,
    CP =< 49211->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49129 =< CP,
    CP =< 49155->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49157 =< CP,
    CP =< 49183->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49213 =< CP,
    CP =< 49239->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49241 =< CP,
    CP =< 49267->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49437 =< CP,
    CP =< 49463->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49353 =< CP,
    CP =< 49379->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49297 =< CP,
    CP =< 49323->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49325 =< CP,
    CP =< 49351->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49381 =< CP,
    CP =< 49407->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49409 =< CP,
    CP =< 49435->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49521 =< CP,
    CP =< 49547->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49465 =< CP,
    CP =< 49491->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49493 =< CP,
    CP =< 49519->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49549 =< CP,
    CP =< 49575->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49577 =< CP,
    CP =< 49603->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52405 =< CP,
    CP =< 52431->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51005 =< CP,
    CP =< 51031->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50305 =< CP,
    CP =< 50331->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49969 =< CP,
    CP =< 49995->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49801 =< CP,
    CP =< 49827->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49717 =< CP,
    CP =< 49743->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49633 =< CP,
    CP =< 49659->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49661 =< CP,
    CP =< 49687->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49689 =< CP,
    CP =< 49715->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49745 =< CP,
    CP =< 49771->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49773 =< CP,
    CP =< 49799->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49885 =< CP,
    CP =< 49911->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49829 =< CP,
    CP =< 49855->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49857 =< CP,
    CP =< 49883->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49913 =< CP,
    CP =< 49939->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49941 =< CP,
    CP =< 49967->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50137 =< CP,
    CP =< 50163->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50053 =< CP,
    CP =< 50079->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 49997 =< CP,
    CP =< 50023->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50025 =< CP,
    CP =< 50051->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50081 =< CP,
    CP =< 50107->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50109 =< CP,
    CP =< 50135->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50221 =< CP,
    CP =< 50247->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50165 =< CP,
    CP =< 50191->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50193 =< CP,
    CP =< 50219->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50249 =< CP,
    CP =< 50275->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50277 =< CP,
    CP =< 50303->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50669 =< CP,
    CP =< 50695->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50501 =< CP,
    CP =< 50527->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50417 =< CP,
    CP =< 50443->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50333 =< CP,
    CP =< 50359->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50361 =< CP,
    CP =< 50387->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50389 =< CP,
    CP =< 50415->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50445 =< CP,
    CP =< 50471->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50473 =< CP,
    CP =< 50499->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50585 =< CP,
    CP =< 50611->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50529 =< CP,
    CP =< 50555->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50557 =< CP,
    CP =< 50583->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50613 =< CP,
    CP =< 50639->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50641 =< CP,
    CP =< 50667->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50837 =< CP,
    CP =< 50863->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50753 =< CP,
    CP =< 50779->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50697 =< CP,
    CP =< 50723->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50725 =< CP,
    CP =< 50751->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50781 =< CP,
    CP =< 50807->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50809 =< CP,
    CP =< 50835->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50921 =< CP,
    CP =< 50947->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50865 =< CP,
    CP =< 50891->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50893 =< CP,
    CP =< 50919->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50949 =< CP,
    CP =< 50975->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 50977 =< CP,
    CP =< 51003->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51705 =< CP,
    CP =< 51731->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51369 =< CP,
    CP =< 51395->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51201 =< CP,
    CP =< 51227->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51117 =< CP,
    CP =< 51143->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51033 =< CP,
    CP =< 51059->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51061 =< CP,
    CP =< 51087->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51089 =< CP,
    CP =< 51115->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51145 =< CP,
    CP =< 51171->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51173 =< CP,
    CP =< 51199->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51285 =< CP,
    CP =< 51311->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51229 =< CP,
    CP =< 51255->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51257 =< CP,
    CP =< 51283->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51313 =< CP,
    CP =< 51339->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51341 =< CP,
    CP =< 51367->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51537 =< CP,
    CP =< 51563->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51453 =< CP,
    CP =< 51479->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51397 =< CP,
    CP =< 51423->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51425 =< CP,
    CP =< 51451->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51481 =< CP,
    CP =< 51507->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51509 =< CP,
    CP =< 51535->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51621 =< CP,
    CP =< 51647->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51565 =< CP,
    CP =< 51591->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51593 =< CP,
    CP =< 51619->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51649 =< CP,
    CP =< 51675->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51677 =< CP,
    CP =< 51703->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52069 =< CP,
    CP =< 52095->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51901 =< CP,
    CP =< 51927->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51817 =< CP,
    CP =< 51843->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51733 =< CP,
    CP =< 51759->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51761 =< CP,
    CP =< 51787->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51789 =< CP,
    CP =< 51815->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51845 =< CP,
    CP =< 51871->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51873 =< CP,
    CP =< 51899->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51985 =< CP,
    CP =< 52011->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51929 =< CP,
    CP =< 51955->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 51957 =< CP,
    CP =< 51983->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52013 =< CP,
    CP =< 52039->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52041 =< CP,
    CP =< 52067->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52237 =< CP,
    CP =< 52263->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52153 =< CP,
    CP =< 52179->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52097 =< CP,
    CP =< 52123->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52125 =< CP,
    CP =< 52151->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52181 =< CP,
    CP =< 52207->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52209 =< CP,
    CP =< 52235->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52321 =< CP,
    CP =< 52347->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52265 =< CP,
    CP =< 52291->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52293 =< CP,
    CP =< 52319->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52349 =< CP,
    CP =< 52375->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52377 =< CP,
    CP =< 52403->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53805 =< CP,
    CP =< 53831->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53105 =< CP,
    CP =< 53131->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52769 =< CP,
    CP =< 52795->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52601 =< CP,
    CP =< 52627->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52517 =< CP,
    CP =< 52543->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52433 =< CP,
    CP =< 52459->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52461 =< CP,
    CP =< 52487->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52489 =< CP,
    CP =< 52515->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52545 =< CP,
    CP =< 52571->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52573 =< CP,
    CP =< 52599->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52685 =< CP,
    CP =< 52711->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52629 =< CP,
    CP =< 52655->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52657 =< CP,
    CP =< 52683->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52713 =< CP,
    CP =< 52739->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52741 =< CP,
    CP =< 52767->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52937 =< CP,
    CP =< 52963->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52853 =< CP,
    CP =< 52879->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52797 =< CP,
    CP =< 52823->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52825 =< CP,
    CP =< 52851->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52881 =< CP,
    CP =< 52907->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52909 =< CP,
    CP =< 52935->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53021 =< CP,
    CP =< 53047->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52965 =< CP,
    CP =< 52991->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 52993 =< CP,
    CP =< 53019->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53049 =< CP,
    CP =< 53075->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53077 =< CP,
    CP =< 53103->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53469 =< CP,
    CP =< 53495->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53301 =< CP,
    CP =< 53327->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53217 =< CP,
    CP =< 53243->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53133 =< CP,
    CP =< 53159->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53161 =< CP,
    CP =< 53187->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53189 =< CP,
    CP =< 53215->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53245 =< CP,
    CP =< 53271->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53273 =< CP,
    CP =< 53299->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53385 =< CP,
    CP =< 53411->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53329 =< CP,
    CP =< 53355->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53357 =< CP,
    CP =< 53383->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53413 =< CP,
    CP =< 53439->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53441 =< CP,
    CP =< 53467->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53637 =< CP,
    CP =< 53663->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53553 =< CP,
    CP =< 53579->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53497 =< CP,
    CP =< 53523->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53525 =< CP,
    CP =< 53551->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53581 =< CP,
    CP =< 53607->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53609 =< CP,
    CP =< 53635->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53721 =< CP,
    CP =< 53747->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53665 =< CP,
    CP =< 53691->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53693 =< CP,
    CP =< 53719->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53749 =< CP,
    CP =< 53775->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53777 =< CP,
    CP =< 53803->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54505 =< CP,
    CP =< 54531->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54169 =< CP,
    CP =< 54195->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54001 =< CP,
    CP =< 54027->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53917 =< CP,
    CP =< 53943->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53833 =< CP,
    CP =< 53859->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53861 =< CP,
    CP =< 53887->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53889 =< CP,
    CP =< 53915->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53945 =< CP,
    CP =< 53971->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 53973 =< CP,
    CP =< 53999->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54085 =< CP,
    CP =< 54111->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54029 =< CP,
    CP =< 54055->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54057 =< CP,
    CP =< 54083->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54113 =< CP,
    CP =< 54139->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54141 =< CP,
    CP =< 54167->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54337 =< CP,
    CP =< 54363->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54253 =< CP,
    CP =< 54279->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54197 =< CP,
    CP =< 54223->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54225 =< CP,
    CP =< 54251->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54281 =< CP,
    CP =< 54307->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54309 =< CP,
    CP =< 54335->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54421 =< CP,
    CP =< 54447->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54365 =< CP,
    CP =< 54391->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54393 =< CP,
    CP =< 54419->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54449 =< CP,
    CP =< 54475->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54477 =< CP,
    CP =< 54503->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54869 =< CP,
    CP =< 54895->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54701 =< CP,
    CP =< 54727->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54617 =< CP,
    CP =< 54643->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54533 =< CP,
    CP =< 54559->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54561 =< CP,
    CP =< 54587->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54589 =< CP,
    CP =< 54615->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54645 =< CP,
    CP =< 54671->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54673 =< CP,
    CP =< 54699->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54785 =< CP,
    CP =< 54811->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54729 =< CP,
    CP =< 54755->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54757 =< CP,
    CP =< 54783->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54813 =< CP,
    CP =< 54839->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54841 =< CP,
    CP =< 54867->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55037 =< CP,
    CP =< 55063->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54953 =< CP,
    CP =< 54979->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54897 =< CP,
    CP =< 54923->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54925 =< CP,
    CP =< 54951->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 54981 =< CP,
    CP =< 55007->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55009 =< CP,
    CP =< 55035->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55121 =< CP,
    CP =< 55147->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55065 =< CP,
    CP =< 55091->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55093 =< CP,
    CP =< 55119->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55149 =< CP,
    CP =< 55175->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],R0,Acc)
    when 55177 =< CP,
    CP =< 55203->
    gc_h_T(R1,[CP| Acc]);
gc_h_lv_lvt([CP| R1],_,[]) ->
    gc_extend(cp(R1),R1,CP);
gc_h_lv_lvt(R1,R0,[CP]) ->
    gc_extend(R1,R0,CP);
gc_h_lv_lvt(R1,R0,Acc) ->
    gc_extend2(R1,R0,Acc).

compose_pair(60,824) ->
    8814;
compose_pair(61,824) ->
    8800;
compose_pair(62,824) ->
    8815;
compose_pair(65,768) ->
    192;
compose_pair(65,769) ->
    193;
compose_pair(65,770) ->
    194;
compose_pair(65,771) ->
    195;
compose_pair(65,772) ->
    256;
compose_pair(65,774) ->
    258;
compose_pair(65,775) ->
    550;
compose_pair(65,776) ->
    196;
compose_pair(65,777) ->
    7842;
compose_pair(65,778) ->
    197;
compose_pair(65,780) ->
    461;
compose_pair(65,783) ->
    512;
compose_pair(65,785) ->
    514;
compose_pair(65,803) ->
    7840;
compose_pair(65,805) ->
    7680;
compose_pair(65,808) ->
    260;
compose_pair(66,775) ->
    7682;
compose_pair(66,803) ->
    7684;
compose_pair(66,817) ->
    7686;
compose_pair(67,769) ->
    262;
compose_pair(67,770) ->
    264;
compose_pair(67,775) ->
    266;
compose_pair(67,780) ->
    268;
compose_pair(67,807) ->
    199;
compose_pair(68,775) ->
    7690;
compose_pair(68,780) ->
    270;
compose_pair(68,803) ->
    7692;
compose_pair(68,807) ->
    7696;
compose_pair(68,813) ->
    7698;
compose_pair(68,817) ->
    7694;
compose_pair(69,768) ->
    200;
compose_pair(69,769) ->
    201;
compose_pair(69,770) ->
    202;
compose_pair(69,771) ->
    7868;
compose_pair(69,772) ->
    274;
compose_pair(69,774) ->
    276;
compose_pair(69,775) ->
    278;
compose_pair(69,776) ->
    203;
compose_pair(69,777) ->
    7866;
compose_pair(69,780) ->
    282;
compose_pair(69,783) ->
    516;
compose_pair(69,785) ->
    518;
compose_pair(69,803) ->
    7864;
compose_pair(69,807) ->
    552;
compose_pair(69,808) ->
    280;
compose_pair(69,813) ->
    7704;
compose_pair(69,816) ->
    7706;
compose_pair(70,775) ->
    7710;
compose_pair(71,769) ->
    500;
compose_pair(71,770) ->
    284;
compose_pair(71,772) ->
    7712;
compose_pair(71,774) ->
    286;
compose_pair(71,775) ->
    288;
compose_pair(71,780) ->
    486;
compose_pair(71,807) ->
    290;
compose_pair(72,770) ->
    292;
compose_pair(72,775) ->
    7714;
compose_pair(72,776) ->
    7718;
compose_pair(72,780) ->
    542;
compose_pair(72,803) ->
    7716;
compose_pair(72,807) ->
    7720;
compose_pair(72,814) ->
    7722;
compose_pair(73,768) ->
    204;
compose_pair(73,769) ->
    205;
compose_pair(73,770) ->
    206;
compose_pair(73,771) ->
    296;
compose_pair(73,772) ->
    298;
compose_pair(73,774) ->
    300;
compose_pair(73,775) ->
    304;
compose_pair(73,776) ->
    207;
compose_pair(73,777) ->
    7880;
compose_pair(73,780) ->
    463;
compose_pair(73,783) ->
    520;
compose_pair(73,785) ->
    522;
compose_pair(73,803) ->
    7882;
compose_pair(73,808) ->
    302;
compose_pair(73,816) ->
    7724;
compose_pair(74,770) ->
    308;
compose_pair(75,769) ->
    7728;
compose_pair(75,780) ->
    488;
compose_pair(75,803) ->
    7730;
compose_pair(75,807) ->
    310;
compose_pair(75,817) ->
    7732;
compose_pair(76,769) ->
    313;
compose_pair(76,780) ->
    317;
compose_pair(76,803) ->
    7734;
compose_pair(76,807) ->
    315;
compose_pair(76,813) ->
    7740;
compose_pair(76,817) ->
    7738;
compose_pair(77,769) ->
    7742;
compose_pair(77,775) ->
    7744;
compose_pair(77,803) ->
    7746;
compose_pair(78,768) ->
    504;
compose_pair(78,769) ->
    323;
compose_pair(78,771) ->
    209;
compose_pair(78,775) ->
    7748;
compose_pair(78,780) ->
    327;
compose_pair(78,803) ->
    7750;
compose_pair(78,807) ->
    325;
compose_pair(78,813) ->
    7754;
compose_pair(78,817) ->
    7752;
compose_pair(79,768) ->
    210;
compose_pair(79,769) ->
    211;
compose_pair(79,770) ->
    212;
compose_pair(79,771) ->
    213;
compose_pair(79,772) ->
    332;
compose_pair(79,774) ->
    334;
compose_pair(79,775) ->
    558;
compose_pair(79,776) ->
    214;
compose_pair(79,777) ->
    7886;
compose_pair(79,779) ->
    336;
compose_pair(79,780) ->
    465;
compose_pair(79,783) ->
    524;
compose_pair(79,785) ->
    526;
compose_pair(79,795) ->
    416;
compose_pair(79,803) ->
    7884;
compose_pair(79,808) ->
    490;
compose_pair(80,769) ->
    7764;
compose_pair(80,775) ->
    7766;
compose_pair(82,769) ->
    340;
compose_pair(82,775) ->
    7768;
compose_pair(82,780) ->
    344;
compose_pair(82,783) ->
    528;
compose_pair(82,785) ->
    530;
compose_pair(82,803) ->
    7770;
compose_pair(82,807) ->
    342;
compose_pair(82,817) ->
    7774;
compose_pair(83,769) ->
    346;
compose_pair(83,770) ->
    348;
compose_pair(83,775) ->
    7776;
compose_pair(83,780) ->
    352;
compose_pair(83,803) ->
    7778;
compose_pair(83,806) ->
    536;
compose_pair(83,807) ->
    350;
compose_pair(84,775) ->
    7786;
compose_pair(84,780) ->
    356;
compose_pair(84,803) ->
    7788;
compose_pair(84,806) ->
    538;
compose_pair(84,807) ->
    354;
compose_pair(84,813) ->
    7792;
compose_pair(84,817) ->
    7790;
compose_pair(85,768) ->
    217;
compose_pair(85,769) ->
    218;
compose_pair(85,770) ->
    219;
compose_pair(85,771) ->
    360;
compose_pair(85,772) ->
    362;
compose_pair(85,774) ->
    364;
compose_pair(85,776) ->
    220;
compose_pair(85,777) ->
    7910;
compose_pair(85,778) ->
    366;
compose_pair(85,779) ->
    368;
compose_pair(85,780) ->
    467;
compose_pair(85,783) ->
    532;
compose_pair(85,785) ->
    534;
compose_pair(85,795) ->
    431;
compose_pair(85,803) ->
    7908;
compose_pair(85,804) ->
    7794;
compose_pair(85,808) ->
    370;
compose_pair(85,813) ->
    7798;
compose_pair(85,816) ->
    7796;
compose_pair(86,771) ->
    7804;
compose_pair(86,803) ->
    7806;
compose_pair(87,768) ->
    7808;
compose_pair(87,769) ->
    7810;
compose_pair(87,770) ->
    372;
compose_pair(87,775) ->
    7814;
compose_pair(87,776) ->
    7812;
compose_pair(87,803) ->
    7816;
compose_pair(88,775) ->
    7818;
compose_pair(88,776) ->
    7820;
compose_pair(89,768) ->
    7922;
compose_pair(89,769) ->
    221;
compose_pair(89,770) ->
    374;
compose_pair(89,771) ->
    7928;
compose_pair(89,772) ->
    562;
compose_pair(89,775) ->
    7822;
compose_pair(89,776) ->
    376;
compose_pair(89,777) ->
    7926;
compose_pair(89,803) ->
    7924;
compose_pair(90,769) ->
    377;
compose_pair(90,770) ->
    7824;
compose_pair(90,775) ->
    379;
compose_pair(90,780) ->
    381;
compose_pair(90,803) ->
    7826;
compose_pair(90,817) ->
    7828;
compose_pair(97,768) ->
    224;
compose_pair(97,769) ->
    225;
compose_pair(97,770) ->
    226;
compose_pair(97,771) ->
    227;
compose_pair(97,772) ->
    257;
compose_pair(97,774) ->
    259;
compose_pair(97,775) ->
    551;
compose_pair(97,776) ->
    228;
compose_pair(97,777) ->
    7843;
compose_pair(97,778) ->
    229;
compose_pair(97,780) ->
    462;
compose_pair(97,783) ->
    513;
compose_pair(97,785) ->
    515;
compose_pair(97,803) ->
    7841;
compose_pair(97,805) ->
    7681;
compose_pair(97,808) ->
    261;
compose_pair(98,775) ->
    7683;
compose_pair(98,803) ->
    7685;
compose_pair(98,817) ->
    7687;
compose_pair(99,769) ->
    263;
compose_pair(99,770) ->
    265;
compose_pair(99,775) ->
    267;
compose_pair(99,780) ->
    269;
compose_pair(99,807) ->
    231;
compose_pair(100,775) ->
    7691;
compose_pair(100,780) ->
    271;
compose_pair(100,803) ->
    7693;
compose_pair(100,807) ->
    7697;
compose_pair(100,813) ->
    7699;
compose_pair(100,817) ->
    7695;
compose_pair(101,768) ->
    232;
compose_pair(101,769) ->
    233;
compose_pair(101,770) ->
    234;
compose_pair(101,771) ->
    7869;
compose_pair(101,772) ->
    275;
compose_pair(101,774) ->
    277;
compose_pair(101,775) ->
    279;
compose_pair(101,776) ->
    235;
compose_pair(101,777) ->
    7867;
compose_pair(101,780) ->
    283;
compose_pair(101,783) ->
    517;
compose_pair(101,785) ->
    519;
compose_pair(101,803) ->
    7865;
compose_pair(101,807) ->
    553;
compose_pair(101,808) ->
    281;
compose_pair(101,813) ->
    7705;
compose_pair(101,816) ->
    7707;
compose_pair(102,775) ->
    7711;
compose_pair(103,769) ->
    501;
compose_pair(103,770) ->
    285;
compose_pair(103,772) ->
    7713;
compose_pair(103,774) ->
    287;
compose_pair(103,775) ->
    289;
compose_pair(103,780) ->
    487;
compose_pair(103,807) ->
    291;
compose_pair(104,770) ->
    293;
compose_pair(104,775) ->
    7715;
compose_pair(104,776) ->
    7719;
compose_pair(104,780) ->
    543;
compose_pair(104,803) ->
    7717;
compose_pair(104,807) ->
    7721;
compose_pair(104,814) ->
    7723;
compose_pair(104,817) ->
    7830;
compose_pair(105,768) ->
    236;
compose_pair(105,769) ->
    237;
compose_pair(105,770) ->
    238;
compose_pair(105,771) ->
    297;
compose_pair(105,772) ->
    299;
compose_pair(105,774) ->
    301;
compose_pair(105,776) ->
    239;
compose_pair(105,777) ->
    7881;
compose_pair(105,780) ->
    464;
compose_pair(105,783) ->
    521;
compose_pair(105,785) ->
    523;
compose_pair(105,803) ->
    7883;
compose_pair(105,808) ->
    303;
compose_pair(105,816) ->
    7725;
compose_pair(106,770) ->
    309;
compose_pair(106,780) ->
    496;
compose_pair(107,769) ->
    7729;
compose_pair(107,780) ->
    489;
compose_pair(107,803) ->
    7731;
compose_pair(107,807) ->
    311;
compose_pair(107,817) ->
    7733;
compose_pair(108,769) ->
    314;
compose_pair(108,780) ->
    318;
compose_pair(108,803) ->
    7735;
compose_pair(108,807) ->
    316;
compose_pair(108,813) ->
    7741;
compose_pair(108,817) ->
    7739;
compose_pair(109,769) ->
    7743;
compose_pair(109,775) ->
    7745;
compose_pair(109,803) ->
    7747;
compose_pair(110,768) ->
    505;
compose_pair(110,769) ->
    324;
compose_pair(110,771) ->
    241;
compose_pair(110,775) ->
    7749;
compose_pair(110,780) ->
    328;
compose_pair(110,803) ->
    7751;
compose_pair(110,807) ->
    326;
compose_pair(110,813) ->
    7755;
compose_pair(110,817) ->
    7753;
compose_pair(111,768) ->
    242;
compose_pair(111,769) ->
    243;
compose_pair(111,770) ->
    244;
compose_pair(111,771) ->
    245;
compose_pair(111,772) ->
    333;
compose_pair(111,774) ->
    335;
compose_pair(111,775) ->
    559;
compose_pair(111,776) ->
    246;
compose_pair(111,777) ->
    7887;
compose_pair(111,779) ->
    337;
compose_pair(111,780) ->
    466;
compose_pair(111,783) ->
    525;
compose_pair(111,785) ->
    527;
compose_pair(111,795) ->
    417;
compose_pair(111,803) ->
    7885;
compose_pair(111,808) ->
    491;
compose_pair(112,769) ->
    7765;
compose_pair(112,775) ->
    7767;
compose_pair(114,769) ->
    341;
compose_pair(114,775) ->
    7769;
compose_pair(114,780) ->
    345;
compose_pair(114,783) ->
    529;
compose_pair(114,785) ->
    531;
compose_pair(114,803) ->
    7771;
compose_pair(114,807) ->
    343;
compose_pair(114,817) ->
    7775;
compose_pair(115,769) ->
    347;
compose_pair(115,770) ->
    349;
compose_pair(115,775) ->
    7777;
compose_pair(115,780) ->
    353;
compose_pair(115,803) ->
    7779;
compose_pair(115,806) ->
    537;
compose_pair(115,807) ->
    351;
compose_pair(116,775) ->
    7787;
compose_pair(116,776) ->
    7831;
compose_pair(116,780) ->
    357;
compose_pair(116,803) ->
    7789;
compose_pair(116,806) ->
    539;
compose_pair(116,807) ->
    355;
compose_pair(116,813) ->
    7793;
compose_pair(116,817) ->
    7791;
compose_pair(117,768) ->
    249;
compose_pair(117,769) ->
    250;
compose_pair(117,770) ->
    251;
compose_pair(117,771) ->
    361;
compose_pair(117,772) ->
    363;
compose_pair(117,774) ->
    365;
compose_pair(117,776) ->
    252;
compose_pair(117,777) ->
    7911;
compose_pair(117,778) ->
    367;
compose_pair(117,779) ->
    369;
compose_pair(117,780) ->
    468;
compose_pair(117,783) ->
    533;
compose_pair(117,785) ->
    535;
compose_pair(117,795) ->
    432;
compose_pair(117,803) ->
    7909;
compose_pair(117,804) ->
    7795;
compose_pair(117,808) ->
    371;
compose_pair(117,813) ->
    7799;
compose_pair(117,816) ->
    7797;
compose_pair(118,771) ->
    7805;
compose_pair(118,803) ->
    7807;
compose_pair(119,768) ->
    7809;
compose_pair(119,769) ->
    7811;
compose_pair(119,770) ->
    373;
compose_pair(119,775) ->
    7815;
compose_pair(119,776) ->
    7813;
compose_pair(119,778) ->
    7832;
compose_pair(119,803) ->
    7817;
compose_pair(120,775) ->
    7819;
compose_pair(120,776) ->
    7821;
compose_pair(121,768) ->
    7923;
compose_pair(121,769) ->
    253;
compose_pair(121,770) ->
    375;
compose_pair(121,771) ->
    7929;
compose_pair(121,772) ->
    563;
compose_pair(121,775) ->
    7823;
compose_pair(121,776) ->
    255;
compose_pair(121,777) ->
    7927;
compose_pair(121,778) ->
    7833;
compose_pair(121,803) ->
    7925;
compose_pair(122,769) ->
    378;
compose_pair(122,770) ->
    7825;
compose_pair(122,775) ->
    380;
compose_pair(122,780) ->
    382;
compose_pair(122,803) ->
    7827;
compose_pair(122,817) ->
    7829;
compose_pair(168,768) ->
    8173;
compose_pair(168,769) ->
    901;
compose_pair(168,834) ->
    8129;
compose_pair(194,768) ->
    7846;
compose_pair(194,769) ->
    7844;
compose_pair(194,771) ->
    7850;
compose_pair(194,777) ->
    7848;
compose_pair(196,772) ->
    478;
compose_pair(197,769) ->
    506;
compose_pair(198,769) ->
    508;
compose_pair(198,772) ->
    482;
compose_pair(199,769) ->
    7688;
compose_pair(202,768) ->
    7872;
compose_pair(202,769) ->
    7870;
compose_pair(202,771) ->
    7876;
compose_pair(202,777) ->
    7874;
compose_pair(207,769) ->
    7726;
compose_pair(212,768) ->
    7890;
compose_pair(212,769) ->
    7888;
compose_pair(212,771) ->
    7894;
compose_pair(212,777) ->
    7892;
compose_pair(213,769) ->
    7756;
compose_pair(213,772) ->
    556;
compose_pair(213,776) ->
    7758;
compose_pair(214,772) ->
    554;
compose_pair(216,769) ->
    510;
compose_pair(220,768) ->
    475;
compose_pair(220,769) ->
    471;
compose_pair(220,772) ->
    469;
compose_pair(220,780) ->
    473;
compose_pair(226,768) ->
    7847;
compose_pair(226,769) ->
    7845;
compose_pair(226,771) ->
    7851;
compose_pair(226,777) ->
    7849;
compose_pair(228,772) ->
    479;
compose_pair(229,769) ->
    507;
compose_pair(230,769) ->
    509;
compose_pair(230,772) ->
    483;
compose_pair(231,769) ->
    7689;
compose_pair(234,768) ->
    7873;
compose_pair(234,769) ->
    7871;
compose_pair(234,771) ->
    7877;
compose_pair(234,777) ->
    7875;
compose_pair(239,769) ->
    7727;
compose_pair(244,768) ->
    7891;
compose_pair(244,769) ->
    7889;
compose_pair(244,771) ->
    7895;
compose_pair(244,777) ->
    7893;
compose_pair(245,769) ->
    7757;
compose_pair(245,772) ->
    557;
compose_pair(245,776) ->
    7759;
compose_pair(246,772) ->
    555;
compose_pair(248,769) ->
    511;
compose_pair(252,768) ->
    476;
compose_pair(252,769) ->
    472;
compose_pair(252,772) ->
    470;
compose_pair(252,780) ->
    474;
compose_pair(258,768) ->
    7856;
compose_pair(258,769) ->
    7854;
compose_pair(258,771) ->
    7860;
compose_pair(258,777) ->
    7858;
compose_pair(259,768) ->
    7857;
compose_pair(259,769) ->
    7855;
compose_pair(259,771) ->
    7861;
compose_pair(259,777) ->
    7859;
compose_pair(274,768) ->
    7700;
compose_pair(274,769) ->
    7702;
compose_pair(275,768) ->
    7701;
compose_pair(275,769) ->
    7703;
compose_pair(332,768) ->
    7760;
compose_pair(332,769) ->
    7762;
compose_pair(333,768) ->
    7761;
compose_pair(333,769) ->
    7763;
compose_pair(346,775) ->
    7780;
compose_pair(347,775) ->
    7781;
compose_pair(352,775) ->
    7782;
compose_pair(353,775) ->
    7783;
compose_pair(360,769) ->
    7800;
compose_pair(361,769) ->
    7801;
compose_pair(362,776) ->
    7802;
compose_pair(363,776) ->
    7803;
compose_pair(383,775) ->
    7835;
compose_pair(416,768) ->
    7900;
compose_pair(416,769) ->
    7898;
compose_pair(416,771) ->
    7904;
compose_pair(416,777) ->
    7902;
compose_pair(416,803) ->
    7906;
compose_pair(417,768) ->
    7901;
compose_pair(417,769) ->
    7899;
compose_pair(417,771) ->
    7905;
compose_pair(417,777) ->
    7903;
compose_pair(417,803) ->
    7907;
compose_pair(431,768) ->
    7914;
compose_pair(431,769) ->
    7912;
compose_pair(431,771) ->
    7918;
compose_pair(431,777) ->
    7916;
compose_pair(431,803) ->
    7920;
compose_pair(432,768) ->
    7915;
compose_pair(432,769) ->
    7913;
compose_pair(432,771) ->
    7919;
compose_pair(432,777) ->
    7917;
compose_pair(432,803) ->
    7921;
compose_pair(439,780) ->
    494;
compose_pair(490,772) ->
    492;
compose_pair(491,772) ->
    493;
compose_pair(550,772) ->
    480;
compose_pair(551,772) ->
    481;
compose_pair(552,774) ->
    7708;
compose_pair(553,774) ->
    7709;
compose_pair(558,772) ->
    560;
compose_pair(559,772) ->
    561;
compose_pair(658,780) ->
    495;
compose_pair(913,768) ->
    8122;
compose_pair(913,769) ->
    902;
compose_pair(913,772) ->
    8121;
compose_pair(913,774) ->
    8120;
compose_pair(913,787) ->
    7944;
compose_pair(913,788) ->
    7945;
compose_pair(913,837) ->
    8124;
compose_pair(917,768) ->
    8136;
compose_pair(917,769) ->
    904;
compose_pair(917,787) ->
    7960;
compose_pair(917,788) ->
    7961;
compose_pair(919,768) ->
    8138;
compose_pair(919,769) ->
    905;
compose_pair(919,787) ->
    7976;
compose_pair(919,788) ->
    7977;
compose_pair(919,837) ->
    8140;
compose_pair(921,768) ->
    8154;
compose_pair(921,769) ->
    906;
compose_pair(921,772) ->
    8153;
compose_pair(921,774) ->
    8152;
compose_pair(921,776) ->
    938;
compose_pair(921,787) ->
    7992;
compose_pair(921,788) ->
    7993;
compose_pair(927,768) ->
    8184;
compose_pair(927,769) ->
    908;
compose_pair(927,787) ->
    8008;
compose_pair(927,788) ->
    8009;
compose_pair(929,788) ->
    8172;
compose_pair(933,768) ->
    8170;
compose_pair(933,769) ->
    910;
compose_pair(933,772) ->
    8169;
compose_pair(933,774) ->
    8168;
compose_pair(933,776) ->
    939;
compose_pair(933,788) ->
    8025;
compose_pair(937,768) ->
    8186;
compose_pair(937,769) ->
    911;
compose_pair(937,787) ->
    8040;
compose_pair(937,788) ->
    8041;
compose_pair(937,837) ->
    8188;
compose_pair(940,837) ->
    8116;
compose_pair(942,837) ->
    8132;
compose_pair(945,768) ->
    8048;
compose_pair(945,769) ->
    940;
compose_pair(945,772) ->
    8113;
compose_pair(945,774) ->
    8112;
compose_pair(945,787) ->
    7936;
compose_pair(945,788) ->
    7937;
compose_pair(945,834) ->
    8118;
compose_pair(945,837) ->
    8115;
compose_pair(949,768) ->
    8050;
compose_pair(949,769) ->
    941;
compose_pair(949,787) ->
    7952;
compose_pair(949,788) ->
    7953;
compose_pair(951,768) ->
    8052;
compose_pair(951,769) ->
    942;
compose_pair(951,787) ->
    7968;
compose_pair(951,788) ->
    7969;
compose_pair(951,834) ->
    8134;
compose_pair(951,837) ->
    8131;
compose_pair(953,768) ->
    8054;
compose_pair(953,769) ->
    943;
compose_pair(953,772) ->
    8145;
compose_pair(953,774) ->
    8144;
compose_pair(953,776) ->
    970;
compose_pair(953,787) ->
    7984;
compose_pair(953,788) ->
    7985;
compose_pair(953,834) ->
    8150;
compose_pair(959,768) ->
    8056;
compose_pair(959,769) ->
    972;
compose_pair(959,787) ->
    8000;
compose_pair(959,788) ->
    8001;
compose_pair(961,787) ->
    8164;
compose_pair(961,788) ->
    8165;
compose_pair(965,768) ->
    8058;
compose_pair(965,769) ->
    973;
compose_pair(965,772) ->
    8161;
compose_pair(965,774) ->
    8160;
compose_pair(965,776) ->
    971;
compose_pair(965,787) ->
    8016;
compose_pair(965,788) ->
    8017;
compose_pair(965,834) ->
    8166;
compose_pair(969,768) ->
    8060;
compose_pair(969,769) ->
    974;
compose_pair(969,787) ->
    8032;
compose_pair(969,788) ->
    8033;
compose_pair(969,834) ->
    8182;
compose_pair(969,837) ->
    8179;
compose_pair(970,768) ->
    8146;
compose_pair(970,769) ->
    912;
compose_pair(970,834) ->
    8151;
compose_pair(971,768) ->
    8162;
compose_pair(971,769) ->
    944;
compose_pair(971,834) ->
    8167;
compose_pair(974,837) ->
    8180;
compose_pair(978,769) ->
    979;
compose_pair(978,776) ->
    980;
compose_pair(1030,776) ->
    1031;
compose_pair(1040,774) ->
    1232;
compose_pair(1040,776) ->
    1234;
compose_pair(1043,769) ->
    1027;
compose_pair(1045,768) ->
    1024;
compose_pair(1045,774) ->
    1238;
compose_pair(1045,776) ->
    1025;
compose_pair(1046,774) ->
    1217;
compose_pair(1046,776) ->
    1244;
compose_pair(1047,776) ->
    1246;
compose_pair(1048,768) ->
    1037;
compose_pair(1048,772) ->
    1250;
compose_pair(1048,774) ->
    1049;
compose_pair(1048,776) ->
    1252;
compose_pair(1050,769) ->
    1036;
compose_pair(1054,776) ->
    1254;
compose_pair(1059,772) ->
    1262;
compose_pair(1059,774) ->
    1038;
compose_pair(1059,776) ->
    1264;
compose_pair(1059,779) ->
    1266;
compose_pair(1063,776) ->
    1268;
compose_pair(1067,776) ->
    1272;
compose_pair(1069,776) ->
    1260;
compose_pair(1072,774) ->
    1233;
compose_pair(1072,776) ->
    1235;
compose_pair(1075,769) ->
    1107;
compose_pair(1077,768) ->
    1104;
compose_pair(1077,774) ->
    1239;
compose_pair(1077,776) ->
    1105;
compose_pair(1078,774) ->
    1218;
compose_pair(1078,776) ->
    1245;
compose_pair(1079,776) ->
    1247;
compose_pair(1080,768) ->
    1117;
compose_pair(1080,772) ->
    1251;
compose_pair(1080,774) ->
    1081;
compose_pair(1080,776) ->
    1253;
compose_pair(1082,769) ->
    1116;
compose_pair(1086,776) ->
    1255;
compose_pair(1091,772) ->
    1263;
compose_pair(1091,774) ->
    1118;
compose_pair(1091,776) ->
    1265;
compose_pair(1091,779) ->
    1267;
compose_pair(1095,776) ->
    1269;
compose_pair(1099,776) ->
    1273;
compose_pair(1101,776) ->
    1261;
compose_pair(1110,776) ->
    1111;
compose_pair(1140,783) ->
    1142;
compose_pair(1141,783) ->
    1143;
compose_pair(1240,776) ->
    1242;
compose_pair(1241,776) ->
    1243;
compose_pair(1256,776) ->
    1258;
compose_pair(1257,776) ->
    1259;
compose_pair(1575,1619) ->
    1570;
compose_pair(1575,1620) ->
    1571;
compose_pair(1575,1621) ->
    1573;
compose_pair(1608,1620) ->
    1572;
compose_pair(1610,1620) ->
    1574;
compose_pair(1729,1620) ->
    1730;
compose_pair(1746,1620) ->
    1747;
compose_pair(1749,1620) ->
    1728;
compose_pair(2344,2364) ->
    2345;
compose_pair(2352,2364) ->
    2353;
compose_pair(2355,2364) ->
    2356;
compose_pair(2503,2494) ->
    2507;
compose_pair(2503,2519) ->
    2508;
compose_pair(2887,2878) ->
    2891;
compose_pair(2887,2902) ->
    2888;
compose_pair(2887,2903) ->
    2892;
compose_pair(2962,3031) ->
    2964;
compose_pair(3014,3006) ->
    3018;
compose_pair(3014,3031) ->
    3020;
compose_pair(3015,3006) ->
    3019;
compose_pair(3142,3158) ->
    3144;
compose_pair(3263,3285) ->
    3264;
compose_pair(3270,3266) ->
    3274;
compose_pair(3270,3285) ->
    3271;
compose_pair(3270,3286) ->
    3272;
compose_pair(3274,3285) ->
    3275;
compose_pair(3398,3390) ->
    3402;
compose_pair(3398,3415) ->
    3404;
compose_pair(3399,3390) ->
    3403;
compose_pair(3545,3530) ->
    3546;
compose_pair(3545,3535) ->
    3548;
compose_pair(3545,3551) ->
    3550;
compose_pair(3548,3530) ->
    3549;
compose_pair(4133,4142) ->
    4134;
compose_pair(6917,6965) ->
    6918;
compose_pair(6919,6965) ->
    6920;
compose_pair(6921,6965) ->
    6922;
compose_pair(6923,6965) ->
    6924;
compose_pair(6925,6965) ->
    6926;
compose_pair(6929,6965) ->
    6930;
compose_pair(6970,6965) ->
    6971;
compose_pair(6972,6965) ->
    6973;
compose_pair(6974,6965) ->
    6976;
compose_pair(6975,6965) ->
    6977;
compose_pair(6978,6965) ->
    6979;
compose_pair(7734,772) ->
    7736;
compose_pair(7735,772) ->
    7737;
compose_pair(7770,772) ->
    7772;
compose_pair(7771,772) ->
    7773;
compose_pair(7778,775) ->
    7784;
compose_pair(7779,775) ->
    7785;
compose_pair(7840,770) ->
    7852;
compose_pair(7840,774) ->
    7862;
compose_pair(7841,770) ->
    7853;
compose_pair(7841,774) ->
    7863;
compose_pair(7864,770) ->
    7878;
compose_pair(7865,770) ->
    7879;
compose_pair(7884,770) ->
    7896;
compose_pair(7885,770) ->
    7897;
compose_pair(7936,768) ->
    7938;
compose_pair(7936,769) ->
    7940;
compose_pair(7936,834) ->
    7942;
compose_pair(7936,837) ->
    8064;
compose_pair(7937,768) ->
    7939;
compose_pair(7937,769) ->
    7941;
compose_pair(7937,834) ->
    7943;
compose_pair(7937,837) ->
    8065;
compose_pair(7938,837) ->
    8066;
compose_pair(7939,837) ->
    8067;
compose_pair(7940,837) ->
    8068;
compose_pair(7941,837) ->
    8069;
compose_pair(7942,837) ->
    8070;
compose_pair(7943,837) ->
    8071;
compose_pair(7944,768) ->
    7946;
compose_pair(7944,769) ->
    7948;
compose_pair(7944,834) ->
    7950;
compose_pair(7944,837) ->
    8072;
compose_pair(7945,768) ->
    7947;
compose_pair(7945,769) ->
    7949;
compose_pair(7945,834) ->
    7951;
compose_pair(7945,837) ->
    8073;
compose_pair(7946,837) ->
    8074;
compose_pair(7947,837) ->
    8075;
compose_pair(7948,837) ->
    8076;
compose_pair(7949,837) ->
    8077;
compose_pair(7950,837) ->
    8078;
compose_pair(7951,837) ->
    8079;
compose_pair(7952,768) ->
    7954;
compose_pair(7952,769) ->
    7956;
compose_pair(7953,768) ->
    7955;
compose_pair(7953,769) ->
    7957;
compose_pair(7960,768) ->
    7962;
compose_pair(7960,769) ->
    7964;
compose_pair(7961,768) ->
    7963;
compose_pair(7961,769) ->
    7965;
compose_pair(7968,768) ->
    7970;
compose_pair(7968,769) ->
    7972;
compose_pair(7968,834) ->
    7974;
compose_pair(7968,837) ->
    8080;
compose_pair(7969,768) ->
    7971;
compose_pair(7969,769) ->
    7973;
compose_pair(7969,834) ->
    7975;
compose_pair(7969,837) ->
    8081;
compose_pair(7970,837) ->
    8082;
compose_pair(7971,837) ->
    8083;
compose_pair(7972,837) ->
    8084;
compose_pair(7973,837) ->
    8085;
compose_pair(7974,837) ->
    8086;
compose_pair(7975,837) ->
    8087;
compose_pair(7976,768) ->
    7978;
compose_pair(7976,769) ->
    7980;
compose_pair(7976,834) ->
    7982;
compose_pair(7976,837) ->
    8088;
compose_pair(7977,768) ->
    7979;
compose_pair(7977,769) ->
    7981;
compose_pair(7977,834) ->
    7983;
compose_pair(7977,837) ->
    8089;
compose_pair(7978,837) ->
    8090;
compose_pair(7979,837) ->
    8091;
compose_pair(7980,837) ->
    8092;
compose_pair(7981,837) ->
    8093;
compose_pair(7982,837) ->
    8094;
compose_pair(7983,837) ->
    8095;
compose_pair(7984,768) ->
    7986;
compose_pair(7984,769) ->
    7988;
compose_pair(7984,834) ->
    7990;
compose_pair(7985,768) ->
    7987;
compose_pair(7985,769) ->
    7989;
compose_pair(7985,834) ->
    7991;
compose_pair(7992,768) ->
    7994;
compose_pair(7992,769) ->
    7996;
compose_pair(7992,834) ->
    7998;
compose_pair(7993,768) ->
    7995;
compose_pair(7993,769) ->
    7997;
compose_pair(7993,834) ->
    7999;
compose_pair(8000,768) ->
    8002;
compose_pair(8000,769) ->
    8004;
compose_pair(8001,768) ->
    8003;
compose_pair(8001,769) ->
    8005;
compose_pair(8008,768) ->
    8010;
compose_pair(8008,769) ->
    8012;
compose_pair(8009,768) ->
    8011;
compose_pair(8009,769) ->
    8013;
compose_pair(8016,768) ->
    8018;
compose_pair(8016,769) ->
    8020;
compose_pair(8016,834) ->
    8022;
compose_pair(8017,768) ->
    8019;
compose_pair(8017,769) ->
    8021;
compose_pair(8017,834) ->
    8023;
compose_pair(8025,768) ->
    8027;
compose_pair(8025,769) ->
    8029;
compose_pair(8025,834) ->
    8031;
compose_pair(8032,768) ->
    8034;
compose_pair(8032,769) ->
    8036;
compose_pair(8032,834) ->
    8038;
compose_pair(8032,837) ->
    8096;
compose_pair(8033,768) ->
    8035;
compose_pair(8033,769) ->
    8037;
compose_pair(8033,834) ->
    8039;
compose_pair(8033,837) ->
    8097;
compose_pair(8034,837) ->
    8098;
compose_pair(8035,837) ->
    8099;
compose_pair(8036,837) ->
    8100;
compose_pair(8037,837) ->
    8101;
compose_pair(8038,837) ->
    8102;
compose_pair(8039,837) ->
    8103;
compose_pair(8040,768) ->
    8042;
compose_pair(8040,769) ->
    8044;
compose_pair(8040,834) ->
    8046;
compose_pair(8040,837) ->
    8104;
compose_pair(8041,768) ->
    8043;
compose_pair(8041,769) ->
    8045;
compose_pair(8041,834) ->
    8047;
compose_pair(8041,837) ->
    8105;
compose_pair(8042,837) ->
    8106;
compose_pair(8043,837) ->
    8107;
compose_pair(8044,837) ->
    8108;
compose_pair(8045,837) ->
    8109;
compose_pair(8046,837) ->
    8110;
compose_pair(8047,837) ->
    8111;
compose_pair(8048,837) ->
    8114;
compose_pair(8052,837) ->
    8130;
compose_pair(8060,837) ->
    8178;
compose_pair(8118,837) ->
    8119;
compose_pair(8127,768) ->
    8141;
compose_pair(8127,769) ->
    8142;
compose_pair(8127,834) ->
    8143;
compose_pair(8134,837) ->
    8135;
compose_pair(8182,837) ->
    8183;
compose_pair(8190,768) ->
    8157;
compose_pair(8190,769) ->
    8158;
compose_pair(8190,834) ->
    8159;
compose_pair(8592,824) ->
    8602;
compose_pair(8594,824) ->
    8603;
compose_pair(8596,824) ->
    8622;
compose_pair(8656,824) ->
    8653;
compose_pair(8658,824) ->
    8655;
compose_pair(8660,824) ->
    8654;
compose_pair(8707,824) ->
    8708;
compose_pair(8712,824) ->
    8713;
compose_pair(8715,824) ->
    8716;
compose_pair(8739,824) ->
    8740;
compose_pair(8741,824) ->
    8742;
compose_pair(8764,824) ->
    8769;
compose_pair(8771,824) ->
    8772;
compose_pair(8773,824) ->
    8775;
compose_pair(8776,824) ->
    8777;
compose_pair(8781,824) ->
    8813;
compose_pair(8801,824) ->
    8802;
compose_pair(8804,824) ->
    8816;
compose_pair(8805,824) ->
    8817;
compose_pair(8818,824) ->
    8820;
compose_pair(8819,824) ->
    8821;
compose_pair(8822,824) ->
    8824;
compose_pair(8823,824) ->
    8825;
compose_pair(8826,824) ->
    8832;
compose_pair(8827,824) ->
    8833;
compose_pair(8828,824) ->
    8928;
compose_pair(8829,824) ->
    8929;
compose_pair(8834,824) ->
    8836;
compose_pair(8835,824) ->
    8837;
compose_pair(8838,824) ->
    8840;
compose_pair(8839,824) ->
    8841;
compose_pair(8849,824) ->
    8930;
compose_pair(8850,824) ->
    8931;
compose_pair(8866,824) ->
    8876;
compose_pair(8872,824) ->
    8877;
compose_pair(8873,824) ->
    8878;
compose_pair(8875,824) ->
    8879;
compose_pair(8882,824) ->
    8938;
compose_pair(8883,824) ->
    8939;
compose_pair(8884,824) ->
    8940;
compose_pair(8885,824) ->
    8941;
compose_pair(12358,12441) ->
    12436;
compose_pair(12363,12441) ->
    12364;
compose_pair(12365,12441) ->
    12366;
compose_pair(12367,12441) ->
    12368;
compose_pair(12369,12441) ->
    12370;
compose_pair(12371,12441) ->
    12372;
compose_pair(12373,12441) ->
    12374;
compose_pair(12375,12441) ->
    12376;
compose_pair(12377,12441) ->
    12378;
compose_pair(12379,12441) ->
    12380;
compose_pair(12381,12441) ->
    12382;
compose_pair(12383,12441) ->
    12384;
compose_pair(12385,12441) ->
    12386;
compose_pair(12388,12441) ->
    12389;
compose_pair(12390,12441) ->
    12391;
compose_pair(12392,12441) ->
    12393;
compose_pair(12399,12441) ->
    12400;
compose_pair(12399,12442) ->
    12401;
compose_pair(12402,12441) ->
    12403;
compose_pair(12402,12442) ->
    12404;
compose_pair(12405,12441) ->
    12406;
compose_pair(12405,12442) ->
    12407;
compose_pair(12408,12441) ->
    12409;
compose_pair(12408,12442) ->
    12410;
compose_pair(12411,12441) ->
    12412;
compose_pair(12411,12442) ->
    12413;
compose_pair(12445,12441) ->
    12446;
compose_pair(12454,12441) ->
    12532;
compose_pair(12459,12441) ->
    12460;
compose_pair(12461,12441) ->
    12462;
compose_pair(12463,12441) ->
    12464;
compose_pair(12465,12441) ->
    12466;
compose_pair(12467,12441) ->
    12468;
compose_pair(12469,12441) ->
    12470;
compose_pair(12471,12441) ->
    12472;
compose_pair(12473,12441) ->
    12474;
compose_pair(12475,12441) ->
    12476;
compose_pair(12477,12441) ->
    12478;
compose_pair(12479,12441) ->
    12480;
compose_pair(12481,12441) ->
    12482;
compose_pair(12484,12441) ->
    12485;
compose_pair(12486,12441) ->
    12487;
compose_pair(12488,12441) ->
    12489;
compose_pair(12495,12441) ->
    12496;
compose_pair(12495,12442) ->
    12497;
compose_pair(12498,12441) ->
    12499;
compose_pair(12498,12442) ->
    12500;
compose_pair(12501,12441) ->
    12502;
compose_pair(12501,12442) ->
    12503;
compose_pair(12504,12441) ->
    12505;
compose_pair(12504,12442) ->
    12506;
compose_pair(12507,12441) ->
    12508;
compose_pair(12507,12442) ->
    12509;
compose_pair(12527,12441) ->
    12535;
compose_pair(12528,12441) ->
    12536;
compose_pair(12529,12441) ->
    12537;
compose_pair(12530,12441) ->
    12538;
compose_pair(12541,12441) ->
    12542;
compose_pair(69785,69818) ->
    69786;
compose_pair(69787,69818) ->
    69788;
compose_pair(69797,69818) ->
    69803;
compose_pair(69937,69927) ->
    69934;
compose_pair(69938,69927) ->
    69935;
compose_pair(70471,70462) ->
    70475;
compose_pair(70471,70487) ->
    70476;
compose_pair(70841,70832) ->
    70844;
compose_pair(70841,70842) ->
    70843;
compose_pair(70841,70845) ->
    70846;
compose_pair(71096,71087) ->
    71098;
compose_pair(71097,71087) ->
    71099;
compose_pair(_,_) ->
    false.

nolist(CP,[]) ->
    CP;
nolist(CP,L) ->
    [CP| L].

case_table(65) ->
    {65,97};
case_table(66) ->
    {66,98};
case_table(67) ->
    {67,99};
case_table(68) ->
    {68,100};
case_table(69) ->
    {69,101};
case_table(70) ->
    {70,102};
case_table(71) ->
    {71,103};
case_table(72) ->
    {72,104};
case_table(73) ->
    {73,105};
case_table(74) ->
    {74,106};
case_table(75) ->
    {75,107};
case_table(76) ->
    {76,108};
case_table(77) ->
    {77,109};
case_table(78) ->
    {78,110};
case_table(79) ->
    {79,111};
case_table(80) ->
    {80,112};
case_table(81) ->
    {81,113};
case_table(82) ->
    {82,114};
case_table(83) ->
    {83,115};
case_table(84) ->
    {84,116};
case_table(85) ->
    {85,117};
case_table(86) ->
    {86,118};
case_table(87) ->
    {87,119};
case_table(88) ->
    {88,120};
case_table(89) ->
    {89,121};
case_table(90) ->
    {90,122};
case_table(97) ->
    {65,97};
case_table(98) ->
    {66,98};
case_table(99) ->
    {67,99};
case_table(100) ->
    {68,100};
case_table(101) ->
    {69,101};
case_table(102) ->
    {70,102};
case_table(103) ->
    {71,103};
case_table(104) ->
    {72,104};
case_table(105) ->
    {73,105};
case_table(106) ->
    {74,106};
case_table(107) ->
    {75,107};
case_table(108) ->
    {76,108};
case_table(109) ->
    {77,109};
case_table(110) ->
    {78,110};
case_table(111) ->
    {79,111};
case_table(112) ->
    {80,112};
case_table(113) ->
    {81,113};
case_table(114) ->
    {82,114};
case_table(115) ->
    {83,115};
case_table(116) ->
    {84,116};
case_table(117) ->
    {85,117};
case_table(118) ->
    {86,118};
case_table(119) ->
    {87,119};
case_table(120) ->
    {88,120};
case_table(121) ->
    {89,121};
case_table(122) ->
    {90,122};
case_table(181) ->
    {924,181,924,956};
case_table(192) ->
    {192,224};
case_table(193) ->
    {193,225};
case_table(194) ->
    {194,226};
case_table(195) ->
    {195,227};
case_table(196) ->
    {196,228};
case_table(197) ->
    {197,229};
case_table(198) ->
    {198,230};
case_table(199) ->
    {199,231};
case_table(200) ->
    {200,232};
case_table(201) ->
    {201,233};
case_table(202) ->
    {202,234};
case_table(203) ->
    {203,235};
case_table(204) ->
    {204,236};
case_table(205) ->
    {205,237};
case_table(206) ->
    {206,238};
case_table(207) ->
    {207,239};
case_table(208) ->
    {208,240};
case_table(209) ->
    {209,241};
case_table(210) ->
    {210,242};
case_table(211) ->
    {211,243};
case_table(212) ->
    {212,244};
case_table(213) ->
    {213,245};
case_table(214) ->
    {214,246};
case_table(216) ->
    {216,248};
case_table(217) ->
    {217,249};
case_table(218) ->
    {218,250};
case_table(219) ->
    {219,251};
case_table(220) ->
    {220,252};
case_table(221) ->
    {221,253};
case_table(222) ->
    {222,254};
case_table(223) ->
    {[83, 83],223,[83, 115],[115, 115]};
case_table(224) ->
    {192,224};
case_table(225) ->
    {193,225};
case_table(226) ->
    {194,226};
case_table(227) ->
    {195,227};
case_table(228) ->
    {196,228};
case_table(229) ->
    {197,229};
case_table(230) ->
    {198,230};
case_table(231) ->
    {199,231};
case_table(232) ->
    {200,232};
case_table(233) ->
    {201,233};
case_table(234) ->
    {202,234};
case_table(235) ->
    {203,235};
case_table(236) ->
    {204,236};
case_table(237) ->
    {205,237};
case_table(238) ->
    {206,238};
case_table(239) ->
    {207,239};
case_table(240) ->
    {208,240};
case_table(241) ->
    {209,241};
case_table(242) ->
    {210,242};
case_table(243) ->
    {211,243};
case_table(244) ->
    {212,244};
case_table(245) ->
    {213,245};
case_table(246) ->
    {214,246};
case_table(248) ->
    {216,248};
case_table(249) ->
    {217,249};
case_table(250) ->
    {218,250};
case_table(251) ->
    {219,251};
case_table(252) ->
    {220,252};
case_table(253) ->
    {221,253};
case_table(254) ->
    {222,254};
case_table(255) ->
    {376,255};
case_table(256) ->
    {256,257};
case_table(257) ->
    {256,257};
case_table(258) ->
    {258,259};
case_table(259) ->
    {258,259};
case_table(260) ->
    {260,261};
case_table(261) ->
    {260,261};
case_table(262) ->
    {262,263};
case_table(263) ->
    {262,263};
case_table(264) ->
    {264,265};
case_table(265) ->
    {264,265};
case_table(266) ->
    {266,267};
case_table(267) ->
    {266,267};
case_table(268) ->
    {268,269};
case_table(269) ->
    {268,269};
case_table(270) ->
    {270,271};
case_table(271) ->
    {270,271};
case_table(272) ->
    {272,273};
case_table(273) ->
    {272,273};
case_table(274) ->
    {274,275};
case_table(275) ->
    {274,275};
case_table(276) ->
    {276,277};
case_table(277) ->
    {276,277};
case_table(278) ->
    {278,279};
case_table(279) ->
    {278,279};
case_table(280) ->
    {280,281};
case_table(281) ->
    {280,281};
case_table(282) ->
    {282,283};
case_table(283) ->
    {282,283};
case_table(284) ->
    {284,285};
case_table(285) ->
    {284,285};
case_table(286) ->
    {286,287};
case_table(287) ->
    {286,287};
case_table(288) ->
    {288,289};
case_table(289) ->
    {288,289};
case_table(290) ->
    {290,291};
case_table(291) ->
    {290,291};
case_table(292) ->
    {292,293};
case_table(293) ->
    {292,293};
case_table(294) ->
    {294,295};
case_table(295) ->
    {294,295};
case_table(296) ->
    {296,297};
case_table(297) ->
    {296,297};
case_table(298) ->
    {298,299};
case_table(299) ->
    {298,299};
case_table(300) ->
    {300,301};
case_table(301) ->
    {300,301};
case_table(302) ->
    {302,303};
case_table(303) ->
    {302,303};
case_table(304) ->
    {304,[105, 775]};
case_table(305) ->
    {73,305};
case_table(306) ->
    {306,307};
case_table(307) ->
    {306,307};
case_table(308) ->
    {308,309};
case_table(309) ->
    {308,309};
case_table(310) ->
    {310,311};
case_table(311) ->
    {310,311};
case_table(313) ->
    {313,314};
case_table(314) ->
    {313,314};
case_table(315) ->
    {315,316};
case_table(316) ->
    {315,316};
case_table(317) ->
    {317,318};
case_table(318) ->
    {317,318};
case_table(319) ->
    {319,320};
case_table(320) ->
    {319,320};
case_table(321) ->
    {321,322};
case_table(322) ->
    {321,322};
case_table(323) ->
    {323,324};
case_table(324) ->
    {323,324};
case_table(325) ->
    {325,326};
case_table(326) ->
    {325,326};
case_table(327) ->
    {327,328};
case_table(328) ->
    {327,328};
case_table(329) ->
    {[700, 78],329,[700, 78],[700, 110]};
case_table(330) ->
    {330,331};
case_table(331) ->
    {330,331};
case_table(332) ->
    {332,333};
case_table(333) ->
    {332,333};
case_table(334) ->
    {334,335};
case_table(335) ->
    {334,335};
case_table(336) ->
    {336,337};
case_table(337) ->
    {336,337};
case_table(338) ->
    {338,339};
case_table(339) ->
    {338,339};
case_table(340) ->
    {340,341};
case_table(341) ->
    {340,341};
case_table(342) ->
    {342,343};
case_table(343) ->
    {342,343};
case_table(344) ->
    {344,345};
case_table(345) ->
    {344,345};
case_table(346) ->
    {346,347};
case_table(347) ->
    {346,347};
case_table(348) ->
    {348,349};
case_table(349) ->
    {348,349};
case_table(350) ->
    {350,351};
case_table(351) ->
    {350,351};
case_table(352) ->
    {352,353};
case_table(353) ->
    {352,353};
case_table(354) ->
    {354,355};
case_table(355) ->
    {354,355};
case_table(356) ->
    {356,357};
case_table(357) ->
    {356,357};
case_table(358) ->
    {358,359};
case_table(359) ->
    {358,359};
case_table(360) ->
    {360,361};
case_table(361) ->
    {360,361};
case_table(362) ->
    {362,363};
case_table(363) ->
    {362,363};
case_table(364) ->
    {364,365};
case_table(365) ->
    {364,365};
case_table(366) ->
    {366,367};
case_table(367) ->
    {366,367};
case_table(368) ->
    {368,369};
case_table(369) ->
    {368,369};
case_table(370) ->
    {370,371};
case_table(371) ->
    {370,371};
case_table(372) ->
    {372,373};
case_table(373) ->
    {372,373};
case_table(374) ->
    {374,375};
case_table(375) ->
    {374,375};
case_table(376) ->
    {376,255};
case_table(377) ->
    {377,378};
case_table(378) ->
    {377,378};
case_table(379) ->
    {379,380};
case_table(380) ->
    {379,380};
case_table(381) ->
    {381,382};
case_table(382) ->
    {381,382};
case_table(383) ->
    {83,383,83,115};
case_table(384) ->
    {579,384};
case_table(385) ->
    {385,595};
case_table(386) ->
    {386,387};
case_table(387) ->
    {386,387};
case_table(388) ->
    {388,389};
case_table(389) ->
    {388,389};
case_table(390) ->
    {390,596};
case_table(391) ->
    {391,392};
case_table(392) ->
    {391,392};
case_table(393) ->
    {393,598};
case_table(394) ->
    {394,599};
case_table(395) ->
    {395,396};
case_table(396) ->
    {395,396};
case_table(398) ->
    {398,477};
case_table(399) ->
    {399,601};
case_table(400) ->
    {400,603};
case_table(401) ->
    {401,402};
case_table(402) ->
    {401,402};
case_table(403) ->
    {403,608};
case_table(404) ->
    {404,611};
case_table(405) ->
    {502,405};
case_table(406) ->
    {406,617};
case_table(407) ->
    {407,616};
case_table(408) ->
    {408,409};
case_table(409) ->
    {408,409};
case_table(410) ->
    {573,410};
case_table(412) ->
    {412,623};
case_table(413) ->
    {413,626};
case_table(414) ->
    {544,414};
case_table(415) ->
    {415,629};
case_table(416) ->
    {416,417};
case_table(417) ->
    {416,417};
case_table(418) ->
    {418,419};
case_table(419) ->
    {418,419};
case_table(420) ->
    {420,421};
case_table(421) ->
    {420,421};
case_table(422) ->
    {422,640};
case_table(423) ->
    {423,424};
case_table(424) ->
    {423,424};
case_table(425) ->
    {425,643};
case_table(428) ->
    {428,429};
case_table(429) ->
    {428,429};
case_table(430) ->
    {430,648};
case_table(431) ->
    {431,432};
case_table(432) ->
    {431,432};
case_table(433) ->
    {433,650};
case_table(434) ->
    {434,651};
case_table(435) ->
    {435,436};
case_table(436) ->
    {435,436};
case_table(437) ->
    {437,438};
case_table(438) ->
    {437,438};
case_table(439) ->
    {439,658};
case_table(440) ->
    {440,441};
case_table(441) ->
    {440,441};
case_table(444) ->
    {444,445};
case_table(445) ->
    {444,445};
case_table(447) ->
    {503,447};
case_table(452) ->
    {452,454,453,454};
case_table(453) ->
    {452,454,453,454};
case_table(454) ->
    {452,454,453,454};
case_table(455) ->
    {455,457,456,457};
case_table(456) ->
    {455,457,456,457};
case_table(457) ->
    {455,457,456,457};
case_table(458) ->
    {458,460,459,460};
case_table(459) ->
    {458,460,459,460};
case_table(460) ->
    {458,460,459,460};
case_table(461) ->
    {461,462};
case_table(462) ->
    {461,462};
case_table(463) ->
    {463,464};
case_table(464) ->
    {463,464};
case_table(465) ->
    {465,466};
case_table(466) ->
    {465,466};
case_table(467) ->
    {467,468};
case_table(468) ->
    {467,468};
case_table(469) ->
    {469,470};
case_table(470) ->
    {469,470};
case_table(471) ->
    {471,472};
case_table(472) ->
    {471,472};
case_table(473) ->
    {473,474};
case_table(474) ->
    {473,474};
case_table(475) ->
    {475,476};
case_table(476) ->
    {475,476};
case_table(477) ->
    {398,477};
case_table(478) ->
    {478,479};
case_table(479) ->
    {478,479};
case_table(480) ->
    {480,481};
case_table(481) ->
    {480,481};
case_table(482) ->
    {482,483};
case_table(483) ->
    {482,483};
case_table(484) ->
    {484,485};
case_table(485) ->
    {484,485};
case_table(486) ->
    {486,487};
case_table(487) ->
    {486,487};
case_table(488) ->
    {488,489};
case_table(489) ->
    {488,489};
case_table(490) ->
    {490,491};
case_table(491) ->
    {490,491};
case_table(492) ->
    {492,493};
case_table(493) ->
    {492,493};
case_table(494) ->
    {494,495};
case_table(495) ->
    {494,495};
case_table(496) ->
    {[74, 780],496,[74, 780],[106, 780]};
case_table(497) ->
    {497,499,498,499};
case_table(498) ->
    {497,499,498,499};
case_table(499) ->
    {497,499,498,499};
case_table(500) ->
    {500,501};
case_table(501) ->
    {500,501};
case_table(502) ->
    {502,405};
case_table(503) ->
    {503,447};
case_table(504) ->
    {504,505};
case_table(505) ->
    {504,505};
case_table(506) ->
    {506,507};
case_table(507) ->
    {506,507};
case_table(508) ->
    {508,509};
case_table(509) ->
    {508,509};
case_table(510) ->
    {510,511};
case_table(511) ->
    {510,511};
case_table(512) ->
    {512,513};
case_table(513) ->
    {512,513};
case_table(514) ->
    {514,515};
case_table(515) ->
    {514,515};
case_table(516) ->
    {516,517};
case_table(517) ->
    {516,517};
case_table(518) ->
    {518,519};
case_table(519) ->
    {518,519};
case_table(520) ->
    {520,521};
case_table(521) ->
    {520,521};
case_table(522) ->
    {522,523};
case_table(523) ->
    {522,523};
case_table(524) ->
    {524,525};
case_table(525) ->
    {524,525};
case_table(526) ->
    {526,527};
case_table(527) ->
    {526,527};
case_table(528) ->
    {528,529};
case_table(529) ->
    {528,529};
case_table(530) ->
    {530,531};
case_table(531) ->
    {530,531};
case_table(532) ->
    {532,533};
case_table(533) ->
    {532,533};
case_table(534) ->
    {534,535};
case_table(535) ->
    {534,535};
case_table(536) ->
    {536,537};
case_table(537) ->
    {536,537};
case_table(538) ->
    {538,539};
case_table(539) ->
    {538,539};
case_table(540) ->
    {540,541};
case_table(541) ->
    {540,541};
case_table(542) ->
    {542,543};
case_table(543) ->
    {542,543};
case_table(544) ->
    {544,414};
case_table(546) ->
    {546,547};
case_table(547) ->
    {546,547};
case_table(548) ->
    {548,549};
case_table(549) ->
    {548,549};
case_table(550) ->
    {550,551};
case_table(551) ->
    {550,551};
case_table(552) ->
    {552,553};
case_table(553) ->
    {552,553};
case_table(554) ->
    {554,555};
case_table(555) ->
    {554,555};
case_table(556) ->
    {556,557};
case_table(557) ->
    {556,557};
case_table(558) ->
    {558,559};
case_table(559) ->
    {558,559};
case_table(560) ->
    {560,561};
case_table(561) ->
    {560,561};
case_table(562) ->
    {562,563};
case_table(563) ->
    {562,563};
case_table(570) ->
    {570,11365};
case_table(571) ->
    {571,572};
case_table(572) ->
    {571,572};
case_table(573) ->
    {573,410};
case_table(574) ->
    {574,11366};
case_table(575) ->
    {11390,575};
case_table(576) ->
    {11391,576};
case_table(577) ->
    {577,578};
case_table(578) ->
    {577,578};
case_table(579) ->
    {579,384};
case_table(580) ->
    {580,649};
case_table(581) ->
    {581,652};
case_table(582) ->
    {582,583};
case_table(583) ->
    {582,583};
case_table(584) ->
    {584,585};
case_table(585) ->
    {584,585};
case_table(586) ->
    {586,587};
case_table(587) ->
    {586,587};
case_table(588) ->
    {588,589};
case_table(589) ->
    {588,589};
case_table(590) ->
    {590,591};
case_table(591) ->
    {590,591};
case_table(592) ->
    {11375,592};
case_table(593) ->
    {11373,593};
case_table(594) ->
    {11376,594};
case_table(595) ->
    {385,595};
case_table(596) ->
    {390,596};
case_table(598) ->
    {393,598};
case_table(599) ->
    {394,599};
case_table(601) ->
    {399,601};
case_table(603) ->
    {400,603};
case_table(604) ->
    {42923,604};
case_table(608) ->
    {403,608};
case_table(609) ->
    {42924,609};
case_table(611) ->
    {404,611};
case_table(613) ->
    {42893,613};
case_table(614) ->
    {42922,614};
case_table(616) ->
    {407,616};
case_table(617) ->
    {406,617};
case_table(618) ->
    {42926,618};
case_table(619) ->
    {11362,619};
case_table(620) ->
    {42925,620};
case_table(623) ->
    {412,623};
case_table(625) ->
    {11374,625};
case_table(626) ->
    {413,626};
case_table(629) ->
    {415,629};
case_table(637) ->
    {11364,637};
case_table(640) ->
    {422,640};
case_table(642) ->
    {42949,642};
case_table(643) ->
    {425,643};
case_table(647) ->
    {42929,647};
case_table(648) ->
    {430,648};
case_table(649) ->
    {580,649};
case_table(650) ->
    {433,650};
case_table(651) ->
    {434,651};
case_table(652) ->
    {581,652};
case_table(658) ->
    {439,658};
case_table(669) ->
    {42930,669};
case_table(670) ->
    {42928,670};
case_table(837) ->
    {921,837,921,953};
case_table(880) ->
    {880,881};
case_table(881) ->
    {880,881};
case_table(882) ->
    {882,883};
case_table(883) ->
    {882,883};
case_table(886) ->
    {886,887};
case_table(887) ->
    {886,887};
case_table(891) ->
    {1021,891};
case_table(892) ->
    {1022,892};
case_table(893) ->
    {1023,893};
case_table(895) ->
    {895,1011};
case_table(902) ->
    {902,940};
case_table(904) ->
    {904,941};
case_table(905) ->
    {905,942};
case_table(906) ->
    {906,943};
case_table(908) ->
    {908,972};
case_table(910) ->
    {910,973};
case_table(911) ->
    {911,974};
case_table(912) ->
    {[921, 776, 769],912,[921, 776, 769],[953, 776, 769]};
case_table(913) ->
    {913,945};
case_table(914) ->
    {914,946};
case_table(915) ->
    {915,947};
case_table(916) ->
    {916,948};
case_table(917) ->
    {917,949};
case_table(918) ->
    {918,950};
case_table(919) ->
    {919,951};
case_table(920) ->
    {920,952};
case_table(921) ->
    {921,953};
case_table(922) ->
    {922,954};
case_table(923) ->
    {923,955};
case_table(924) ->
    {924,956};
case_table(925) ->
    {925,957};
case_table(926) ->
    {926,958};
case_table(927) ->
    {927,959};
case_table(928) ->
    {928,960};
case_table(929) ->
    {929,961};
case_table(931) ->
    {931,963};
case_table(932) ->
    {932,964};
case_table(933) ->
    {933,965};
case_table(934) ->
    {934,966};
case_table(935) ->
    {935,967};
case_table(936) ->
    {936,968};
case_table(937) ->
    {937,969};
case_table(938) ->
    {938,970};
case_table(939) ->
    {939,971};
case_table(940) ->
    {902,940};
case_table(941) ->
    {904,941};
case_table(942) ->
    {905,942};
case_table(943) ->
    {906,943};
case_table(944) ->
    {[933, 776, 769],944,[933, 776, 769],[965, 776, 769]};
case_table(945) ->
    {913,945};
case_table(946) ->
    {914,946};
case_table(947) ->
    {915,947};
case_table(948) ->
    {916,948};
case_table(949) ->
    {917,949};
case_table(950) ->
    {918,950};
case_table(951) ->
    {919,951};
case_table(952) ->
    {920,952};
case_table(953) ->
    {921,953};
case_table(954) ->
    {922,954};
case_table(955) ->
    {923,955};
case_table(956) ->
    {924,956};
case_table(957) ->
    {925,957};
case_table(958) ->
    {926,958};
case_table(959) ->
    {927,959};
case_table(960) ->
    {928,960};
case_table(961) ->
    {929,961};
case_table(962) ->
    {931,962,931,963};
case_table(963) ->
    {931,963};
case_table(964) ->
    {932,964};
case_table(965) ->
    {933,965};
case_table(966) ->
    {934,966};
case_table(967) ->
    {935,967};
case_table(968) ->
    {936,968};
case_table(969) ->
    {937,969};
case_table(970) ->
    {938,970};
case_table(971) ->
    {939,971};
case_table(972) ->
    {908,972};
case_table(973) ->
    {910,973};
case_table(974) ->
    {911,974};
case_table(975) ->
    {975,983};
case_table(976) ->
    {914,976,914,946};
case_table(977) ->
    {920,977,920,952};
case_table(981) ->
    {934,981,934,966};
case_table(982) ->
    {928,982,928,960};
case_table(983) ->
    {975,983};
case_table(984) ->
    {984,985};
case_table(985) ->
    {984,985};
case_table(986) ->
    {986,987};
case_table(987) ->
    {986,987};
case_table(988) ->
    {988,989};
case_table(989) ->
    {988,989};
case_table(990) ->
    {990,991};
case_table(991) ->
    {990,991};
case_table(992) ->
    {992,993};
case_table(993) ->
    {992,993};
case_table(994) ->
    {994,995};
case_table(995) ->
    {994,995};
case_table(996) ->
    {996,997};
case_table(997) ->
    {996,997};
case_table(998) ->
    {998,999};
case_table(999) ->
    {998,999};
case_table(1000) ->
    {1000,1001};
case_table(1001) ->
    {1000,1001};
case_table(1002) ->
    {1002,1003};
case_table(1003) ->
    {1002,1003};
case_table(1004) ->
    {1004,1005};
case_table(1005) ->
    {1004,1005};
case_table(1006) ->
    {1006,1007};
case_table(1007) ->
    {1006,1007};
case_table(1008) ->
    {922,1008,922,954};
case_table(1009) ->
    {929,1009,929,961};
case_table(1010) ->
    {1017,1010};
case_table(1011) ->
    {895,1011};
case_table(1012) ->
    {1012,952};
case_table(1013) ->
    {917,1013,917,949};
case_table(1015) ->
    {1015,1016};
case_table(1016) ->
    {1015,1016};
case_table(1017) ->
    {1017,1010};
case_table(1018) ->
    {1018,1019};
case_table(1019) ->
    {1018,1019};
case_table(1021) ->
    {1021,891};
case_table(1022) ->
    {1022,892};
case_table(1023) ->
    {1023,893};
case_table(1024) ->
    {1024,1104};
case_table(1025) ->
    {1025,1105};
case_table(1026) ->
    {1026,1106};
case_table(1027) ->
    {1027,1107};
case_table(1028) ->
    {1028,1108};
case_table(1029) ->
    {1029,1109};
case_table(1030) ->
    {1030,1110};
case_table(1031) ->
    {1031,1111};
case_table(1032) ->
    {1032,1112};
case_table(1033) ->
    {1033,1113};
case_table(1034) ->
    {1034,1114};
case_table(1035) ->
    {1035,1115};
case_table(1036) ->
    {1036,1116};
case_table(1037) ->
    {1037,1117};
case_table(1038) ->
    {1038,1118};
case_table(1039) ->
    {1039,1119};
case_table(1040) ->
    {1040,1072};
case_table(1041) ->
    {1041,1073};
case_table(1042) ->
    {1042,1074};
case_table(1043) ->
    {1043,1075};
case_table(1044) ->
    {1044,1076};
case_table(1045) ->
    {1045,1077};
case_table(1046) ->
    {1046,1078};
case_table(1047) ->
    {1047,1079};
case_table(1048) ->
    {1048,1080};
case_table(1049) ->
    {1049,1081};
case_table(1050) ->
    {1050,1082};
case_table(1051) ->
    {1051,1083};
case_table(1052) ->
    {1052,1084};
case_table(1053) ->
    {1053,1085};
case_table(1054) ->
    {1054,1086};
case_table(1055) ->
    {1055,1087};
case_table(1056) ->
    {1056,1088};
case_table(1057) ->
    {1057,1089};
case_table(1058) ->
    {1058,1090};
case_table(1059) ->
    {1059,1091};
case_table(1060) ->
    {1060,1092};
case_table(1061) ->
    {1061,1093};
case_table(1062) ->
    {1062,1094};
case_table(1063) ->
    {1063,1095};
case_table(1064) ->
    {1064,1096};
case_table(1065) ->
    {1065,1097};
case_table(1066) ->
    {1066,1098};
case_table(1067) ->
    {1067,1099};
case_table(1068) ->
    {1068,1100};
case_table(1069) ->
    {1069,1101};
case_table(1070) ->
    {1070,1102};
case_table(1071) ->
    {1071,1103};
case_table(1072) ->
    {1040,1072};
case_table(1073) ->
    {1041,1073};
case_table(1074) ->
    {1042,1074};
case_table(1075) ->
    {1043,1075};
case_table(1076) ->
    {1044,1076};
case_table(1077) ->
    {1045,1077};
case_table(1078) ->
    {1046,1078};
case_table(1079) ->
    {1047,1079};
case_table(1080) ->
    {1048,1080};
case_table(1081) ->
    {1049,1081};
case_table(1082) ->
    {1050,1082};
case_table(1083) ->
    {1051,1083};
case_table(1084) ->
    {1052,1084};
case_table(1085) ->
    {1053,1085};
case_table(1086) ->
    {1054,1086};
case_table(1087) ->
    {1055,1087};
case_table(1088) ->
    {1056,1088};
case_table(1089) ->
    {1057,1089};
case_table(1090) ->
    {1058,1090};
case_table(1091) ->
    {1059,1091};
case_table(1092) ->
    {1060,1092};
case_table(1093) ->
    {1061,1093};
case_table(1094) ->
    {1062,1094};
case_table(1095) ->
    {1063,1095};
case_table(1096) ->
    {1064,1096};
case_table(1097) ->
    {1065,1097};
case_table(1098) ->
    {1066,1098};
case_table(1099) ->
    {1067,1099};
case_table(1100) ->
    {1068,1100};
case_table(1101) ->
    {1069,1101};
case_table(1102) ->
    {1070,1102};
case_table(1103) ->
    {1071,1103};
case_table(1104) ->
    {1024,1104};
case_table(1105) ->
    {1025,1105};
case_table(1106) ->
    {1026,1106};
case_table(1107) ->
    {1027,1107};
case_table(1108) ->
    {1028,1108};
case_table(1109) ->
    {1029,1109};
case_table(1110) ->
    {1030,1110};
case_table(1111) ->
    {1031,1111};
case_table(1112) ->
    {1032,1112};
case_table(1113) ->
    {1033,1113};
case_table(1114) ->
    {1034,1114};
case_table(1115) ->
    {1035,1115};
case_table(1116) ->
    {1036,1116};
case_table(1117) ->
    {1037,1117};
case_table(1118) ->
    {1038,1118};
case_table(1119) ->
    {1039,1119};
case_table(1120) ->
    {1120,1121};
case_table(1121) ->
    {1120,1121};
case_table(1122) ->
    {1122,1123};
case_table(1123) ->
    {1122,1123};
case_table(1124) ->
    {1124,1125};
case_table(1125) ->
    {1124,1125};
case_table(1126) ->
    {1126,1127};
case_table(1127) ->
    {1126,1127};
case_table(1128) ->
    {1128,1129};
case_table(1129) ->
    {1128,1129};
case_table(1130) ->
    {1130,1131};
case_table(1131) ->
    {1130,1131};
case_table(1132) ->
    {1132,1133};
case_table(1133) ->
    {1132,1133};
case_table(1134) ->
    {1134,1135};
case_table(1135) ->
    {1134,1135};
case_table(1136) ->
    {1136,1137};
case_table(1137) ->
    {1136,1137};
case_table(1138) ->
    {1138,1139};
case_table(1139) ->
    {1138,1139};
case_table(1140) ->
    {1140,1141};
case_table(1141) ->
    {1140,1141};
case_table(1142) ->
    {1142,1143};
case_table(1143) ->
    {1142,1143};
case_table(1144) ->
    {1144,1145};
case_table(1145) ->
    {1144,1145};
case_table(1146) ->
    {1146,1147};
case_table(1147) ->
    {1146,1147};
case_table(1148) ->
    {1148,1149};
case_table(1149) ->
    {1148,1149};
case_table(1150) ->
    {1150,1151};
case_table(1151) ->
    {1150,1151};
case_table(1152) ->
    {1152,1153};
case_table(1153) ->
    {1152,1153};
case_table(1162) ->
    {1162,1163};
case_table(1163) ->
    {1162,1163};
case_table(1164) ->
    {1164,1165};
case_table(1165) ->
    {1164,1165};
case_table(1166) ->
    {1166,1167};
case_table(1167) ->
    {1166,1167};
case_table(1168) ->
    {1168,1169};
case_table(1169) ->
    {1168,1169};
case_table(1170) ->
    {1170,1171};
case_table(1171) ->
    {1170,1171};
case_table(1172) ->
    {1172,1173};
case_table(1173) ->
    {1172,1173};
case_table(1174) ->
    {1174,1175};
case_table(1175) ->
    {1174,1175};
case_table(1176) ->
    {1176,1177};
case_table(1177) ->
    {1176,1177};
case_table(1178) ->
    {1178,1179};
case_table(1179) ->
    {1178,1179};
case_table(1180) ->
    {1180,1181};
case_table(1181) ->
    {1180,1181};
case_table(1182) ->
    {1182,1183};
case_table(1183) ->
    {1182,1183};
case_table(1184) ->
    {1184,1185};
case_table(1185) ->
    {1184,1185};
case_table(1186) ->
    {1186,1187};
case_table(1187) ->
    {1186,1187};
case_table(1188) ->
    {1188,1189};
case_table(1189) ->
    {1188,1189};
case_table(1190) ->
    {1190,1191};
case_table(1191) ->
    {1190,1191};
case_table(1192) ->
    {1192,1193};
case_table(1193) ->
    {1192,1193};
case_table(1194) ->
    {1194,1195};
case_table(1195) ->
    {1194,1195};
case_table(1196) ->
    {1196,1197};
case_table(1197) ->
    {1196,1197};
case_table(1198) ->
    {1198,1199};
case_table(1199) ->
    {1198,1199};
case_table(1200) ->
    {1200,1201};
case_table(1201) ->
    {1200,1201};
case_table(1202) ->
    {1202,1203};
case_table(1203) ->
    {1202,1203};
case_table(1204) ->
    {1204,1205};
case_table(1205) ->
    {1204,1205};
case_table(1206) ->
    {1206,1207};
case_table(1207) ->
    {1206,1207};
case_table(1208) ->
    {1208,1209};
case_table(1209) ->
    {1208,1209};
case_table(1210) ->
    {1210,1211};
case_table(1211) ->
    {1210,1211};
case_table(1212) ->
    {1212,1213};
case_table(1213) ->
    {1212,1213};
case_table(1214) ->
    {1214,1215};
case_table(1215) ->
    {1214,1215};
case_table(1216) ->
    {1216,1231};
case_table(1217) ->
    {1217,1218};
case_table(1218) ->
    {1217,1218};
case_table(1219) ->
    {1219,1220};
case_table(1220) ->
    {1219,1220};
case_table(1221) ->
    {1221,1222};
case_table(1222) ->
    {1221,1222};
case_table(1223) ->
    {1223,1224};
case_table(1224) ->
    {1223,1224};
case_table(1225) ->
    {1225,1226};
case_table(1226) ->
    {1225,1226};
case_table(1227) ->
    {1227,1228};
case_table(1228) ->
    {1227,1228};
case_table(1229) ->
    {1229,1230};
case_table(1230) ->
    {1229,1230};
case_table(1231) ->
    {1216,1231};
case_table(1232) ->
    {1232,1233};
case_table(1233) ->
    {1232,1233};
case_table(1234) ->
    {1234,1235};
case_table(1235) ->
    {1234,1235};
case_table(1236) ->
    {1236,1237};
case_table(1237) ->
    {1236,1237};
case_table(1238) ->
    {1238,1239};
case_table(1239) ->
    {1238,1239};
case_table(1240) ->
    {1240,1241};
case_table(1241) ->
    {1240,1241};
case_table(1242) ->
    {1242,1243};
case_table(1243) ->
    {1242,1243};
case_table(1244) ->
    {1244,1245};
case_table(1245) ->
    {1244,1245};
case_table(1246) ->
    {1246,1247};
case_table(1247) ->
    {1246,1247};
case_table(1248) ->
    {1248,1249};
case_table(1249) ->
    {1248,1249};
case_table(1250) ->
    {1250,1251};
case_table(1251) ->
    {1250,1251};
case_table(1252) ->
    {1252,1253};
case_table(1253) ->
    {1252,1253};
case_table(1254) ->
    {1254,1255};
case_table(1255) ->
    {1254,1255};
case_table(1256) ->
    {1256,1257};
case_table(1257) ->
    {1256,1257};
case_table(1258) ->
    {1258,1259};
case_table(1259) ->
    {1258,1259};
case_table(1260) ->
    {1260,1261};
case_table(1261) ->
    {1260,1261};
case_table(1262) ->
    {1262,1263};
case_table(1263) ->
    {1262,1263};
case_table(1264) ->
    {1264,1265};
case_table(1265) ->
    {1264,1265};
case_table(1266) ->
    {1266,1267};
case_table(1267) ->
    {1266,1267};
case_table(1268) ->
    {1268,1269};
case_table(1269) ->
    {1268,1269};
case_table(1270) ->
    {1270,1271};
case_table(1271) ->
    {1270,1271};
case_table(1272) ->
    {1272,1273};
case_table(1273) ->
    {1272,1273};
case_table(1274) ->
    {1274,1275};
case_table(1275) ->
    {1274,1275};
case_table(1276) ->
    {1276,1277};
case_table(1277) ->
    {1276,1277};
case_table(1278) ->
    {1278,1279};
case_table(1279) ->
    {1278,1279};
case_table(1280) ->
    {1280,1281};
case_table(1281) ->
    {1280,1281};
case_table(1282) ->
    {1282,1283};
case_table(1283) ->
    {1282,1283};
case_table(1284) ->
    {1284,1285};
case_table(1285) ->
    {1284,1285};
case_table(1286) ->
    {1286,1287};
case_table(1287) ->
    {1286,1287};
case_table(1288) ->
    {1288,1289};
case_table(1289) ->
    {1288,1289};
case_table(1290) ->
    {1290,1291};
case_table(1291) ->
    {1290,1291};
case_table(1292) ->
    {1292,1293};
case_table(1293) ->
    {1292,1293};
case_table(1294) ->
    {1294,1295};
case_table(1295) ->
    {1294,1295};
case_table(1296) ->
    {1296,1297};
case_table(1297) ->
    {1296,1297};
case_table(1298) ->
    {1298,1299};
case_table(1299) ->
    {1298,1299};
case_table(1300) ->
    {1300,1301};
case_table(1301) ->
    {1300,1301};
case_table(1302) ->
    {1302,1303};
case_table(1303) ->
    {1302,1303};
case_table(1304) ->
    {1304,1305};
case_table(1305) ->
    {1304,1305};
case_table(1306) ->
    {1306,1307};
case_table(1307) ->
    {1306,1307};
case_table(1308) ->
    {1308,1309};
case_table(1309) ->
    {1308,1309};
case_table(1310) ->
    {1310,1311};
case_table(1311) ->
    {1310,1311};
case_table(1312) ->
    {1312,1313};
case_table(1313) ->
    {1312,1313};
case_table(1314) ->
    {1314,1315};
case_table(1315) ->
    {1314,1315};
case_table(1316) ->
    {1316,1317};
case_table(1317) ->
    {1316,1317};
case_table(1318) ->
    {1318,1319};
case_table(1319) ->
    {1318,1319};
case_table(1320) ->
    {1320,1321};
case_table(1321) ->
    {1320,1321};
case_table(1322) ->
    {1322,1323};
case_table(1323) ->
    {1322,1323};
case_table(1324) ->
    {1324,1325};
case_table(1325) ->
    {1324,1325};
case_table(1326) ->
    {1326,1327};
case_table(1327) ->
    {1326,1327};
case_table(1329) ->
    {1329,1377};
case_table(1330) ->
    {1330,1378};
case_table(1331) ->
    {1331,1379};
case_table(1332) ->
    {1332,1380};
case_table(1333) ->
    {1333,1381};
case_table(1334) ->
    {1334,1382};
case_table(1335) ->
    {1335,1383};
case_table(1336) ->
    {1336,1384};
case_table(1337) ->
    {1337,1385};
case_table(1338) ->
    {1338,1386};
case_table(1339) ->
    {1339,1387};
case_table(1340) ->
    {1340,1388};
case_table(1341) ->
    {1341,1389};
case_table(1342) ->
    {1342,1390};
case_table(1343) ->
    {1343,1391};
case_table(1344) ->
    {1344,1392};
case_table(1345) ->
    {1345,1393};
case_table(1346) ->
    {1346,1394};
case_table(1347) ->
    {1347,1395};
case_table(1348) ->
    {1348,1396};
case_table(1349) ->
    {1349,1397};
case_table(1350) ->
    {1350,1398};
case_table(1351) ->
    {1351,1399};
case_table(1352) ->
    {1352,1400};
case_table(1353) ->
    {1353,1401};
case_table(1354) ->
    {1354,1402};
case_table(1355) ->
    {1355,1403};
case_table(1356) ->
    {1356,1404};
case_table(1357) ->
    {1357,1405};
case_table(1358) ->
    {1358,1406};
case_table(1359) ->
    {1359,1407};
case_table(1360) ->
    {1360,1408};
case_table(1361) ->
    {1361,1409};
case_table(1362) ->
    {1362,1410};
case_table(1363) ->
    {1363,1411};
case_table(1364) ->
    {1364,1412};
case_table(1365) ->
    {1365,1413};
case_table(1366) ->
    {1366,1414};
case_table(1377) ->
    {1329,1377};
case_table(1378) ->
    {1330,1378};
case_table(1379) ->
    {1331,1379};
case_table(1380) ->
    {1332,1380};
case_table(1381) ->
    {1333,1381};
case_table(1382) ->
    {1334,1382};
case_table(1383) ->
    {1335,1383};
case_table(1384) ->
    {1336,1384};
case_table(1385) ->
    {1337,1385};
case_table(1386) ->
    {1338,1386};
case_table(1387) ->
    {1339,1387};
case_table(1388) ->
    {1340,1388};
case_table(1389) ->
    {1341,1389};
case_table(1390) ->
    {1342,1390};
case_table(1391) ->
    {1343,1391};
case_table(1392) ->
    {1344,1392};
case_table(1393) ->
    {1345,1393};
case_table(1394) ->
    {1346,1394};
case_table(1395) ->
    {1347,1395};
case_table(1396) ->
    {1348,1396};
case_table(1397) ->
    {1349,1397};
case_table(1398) ->
    {1350,1398};
case_table(1399) ->
    {1351,1399};
case_table(1400) ->
    {1352,1400};
case_table(1401) ->
    {1353,1401};
case_table(1402) ->
    {1354,1402};
case_table(1403) ->
    {1355,1403};
case_table(1404) ->
    {1356,1404};
case_table(1405) ->
    {1357,1405};
case_table(1406) ->
    {1358,1406};
case_table(1407) ->
    {1359,1407};
case_table(1408) ->
    {1360,1408};
case_table(1409) ->
    {1361,1409};
case_table(1410) ->
    {1362,1410};
case_table(1411) ->
    {1363,1411};
case_table(1412) ->
    {1364,1412};
case_table(1413) ->
    {1365,1413};
case_table(1414) ->
    {1366,1414};
case_table(1415) ->
    {[1333, 1362],1415,[1333, 1410],[1381, 1410]};
case_table(4256) ->
    {4256,11520};
case_table(4257) ->
    {4257,11521};
case_table(4258) ->
    {4258,11522};
case_table(4259) ->
    {4259,11523};
case_table(4260) ->
    {4260,11524};
case_table(4261) ->
    {4261,11525};
case_table(4262) ->
    {4262,11526};
case_table(4263) ->
    {4263,11527};
case_table(4264) ->
    {4264,11528};
case_table(4265) ->
    {4265,11529};
case_table(4266) ->
    {4266,11530};
case_table(4267) ->
    {4267,11531};
case_table(4268) ->
    {4268,11532};
case_table(4269) ->
    {4269,11533};
case_table(4270) ->
    {4270,11534};
case_table(4271) ->
    {4271,11535};
case_table(4272) ->
    {4272,11536};
case_table(4273) ->
    {4273,11537};
case_table(4274) ->
    {4274,11538};
case_table(4275) ->
    {4275,11539};
case_table(4276) ->
    {4276,11540};
case_table(4277) ->
    {4277,11541};
case_table(4278) ->
    {4278,11542};
case_table(4279) ->
    {4279,11543};
case_table(4280) ->
    {4280,11544};
case_table(4281) ->
    {4281,11545};
case_table(4282) ->
    {4282,11546};
case_table(4283) ->
    {4283,11547};
case_table(4284) ->
    {4284,11548};
case_table(4285) ->
    {4285,11549};
case_table(4286) ->
    {4286,11550};
case_table(4287) ->
    {4287,11551};
case_table(4288) ->
    {4288,11552};
case_table(4289) ->
    {4289,11553};
case_table(4290) ->
    {4290,11554};
case_table(4291) ->
    {4291,11555};
case_table(4292) ->
    {4292,11556};
case_table(4293) ->
    {4293,11557};
case_table(4295) ->
    {4295,11559};
case_table(4301) ->
    {4301,11565};
case_table(4304) ->
    {7312,4304,4304,4304};
case_table(4305) ->
    {7313,4305,4305,4305};
case_table(4306) ->
    {7314,4306,4306,4306};
case_table(4307) ->
    {7315,4307,4307,4307};
case_table(4308) ->
    {7316,4308,4308,4308};
case_table(4309) ->
    {7317,4309,4309,4309};
case_table(4310) ->
    {7318,4310,4310,4310};
case_table(4311) ->
    {7319,4311,4311,4311};
case_table(4312) ->
    {7320,4312,4312,4312};
case_table(4313) ->
    {7321,4313,4313,4313};
case_table(4314) ->
    {7322,4314,4314,4314};
case_table(4315) ->
    {7323,4315,4315,4315};
case_table(4316) ->
    {7324,4316,4316,4316};
case_table(4317) ->
    {7325,4317,4317,4317};
case_table(4318) ->
    {7326,4318,4318,4318};
case_table(4319) ->
    {7327,4319,4319,4319};
case_table(4320) ->
    {7328,4320,4320,4320};
case_table(4321) ->
    {7329,4321,4321,4321};
case_table(4322) ->
    {7330,4322,4322,4322};
case_table(4323) ->
    {7331,4323,4323,4323};
case_table(4324) ->
    {7332,4324,4324,4324};
case_table(4325) ->
    {7333,4325,4325,4325};
case_table(4326) ->
    {7334,4326,4326,4326};
case_table(4327) ->
    {7335,4327,4327,4327};
case_table(4328) ->
    {7336,4328,4328,4328};
case_table(4329) ->
    {7337,4329,4329,4329};
case_table(4330) ->
    {7338,4330,4330,4330};
case_table(4331) ->
    {7339,4331,4331,4331};
case_table(4332) ->
    {7340,4332,4332,4332};
case_table(4333) ->
    {7341,4333,4333,4333};
case_table(4334) ->
    {7342,4334,4334,4334};
case_table(4335) ->
    {7343,4335,4335,4335};
case_table(4336) ->
    {7344,4336,4336,4336};
case_table(4337) ->
    {7345,4337,4337,4337};
case_table(4338) ->
    {7346,4338,4338,4338};
case_table(4339) ->
    {7347,4339,4339,4339};
case_table(4340) ->
    {7348,4340,4340,4340};
case_table(4341) ->
    {7349,4341,4341,4341};
case_table(4342) ->
    {7350,4342,4342,4342};
case_table(4343) ->
    {7351,4343,4343,4343};
case_table(4344) ->
    {7352,4344,4344,4344};
case_table(4345) ->
    {7353,4345,4345,4345};
case_table(4346) ->
    {7354,4346,4346,4346};
case_table(4349) ->
    {7357,4349,4349,4349};
case_table(4350) ->
    {7358,4350,4350,4350};
case_table(4351) ->
    {7359,4351,4351,4351};
case_table(5024) ->
    {5024,43888,5024,5024};
case_table(5025) ->
    {5025,43889,5025,5025};
case_table(5026) ->
    {5026,43890,5026,5026};
case_table(5027) ->
    {5027,43891,5027,5027};
case_table(5028) ->
    {5028,43892,5028,5028};
case_table(5029) ->
    {5029,43893,5029,5029};
case_table(5030) ->
    {5030,43894,5030,5030};
case_table(5031) ->
    {5031,43895,5031,5031};
case_table(5032) ->
    {5032,43896,5032,5032};
case_table(5033) ->
    {5033,43897,5033,5033};
case_table(5034) ->
    {5034,43898,5034,5034};
case_table(5035) ->
    {5035,43899,5035,5035};
case_table(5036) ->
    {5036,43900,5036,5036};
case_table(5037) ->
    {5037,43901,5037,5037};
case_table(5038) ->
    {5038,43902,5038,5038};
case_table(5039) ->
    {5039,43903,5039,5039};
case_table(5040) ->
    {5040,43904,5040,5040};
case_table(5041) ->
    {5041,43905,5041,5041};
case_table(5042) ->
    {5042,43906,5042,5042};
case_table(5043) ->
    {5043,43907,5043,5043};
case_table(5044) ->
    {5044,43908,5044,5044};
case_table(5045) ->
    {5045,43909,5045,5045};
case_table(5046) ->
    {5046,43910,5046,5046};
case_table(5047) ->
    {5047,43911,5047,5047};
case_table(5048) ->
    {5048,43912,5048,5048};
case_table(5049) ->
    {5049,43913,5049,5049};
case_table(5050) ->
    {5050,43914,5050,5050};
case_table(5051) ->
    {5051,43915,5051,5051};
case_table(5052) ->
    {5052,43916,5052,5052};
case_table(5053) ->
    {5053,43917,5053,5053};
case_table(5054) ->
    {5054,43918,5054,5054};
case_table(5055) ->
    {5055,43919,5055,5055};
case_table(5056) ->
    {5056,43920,5056,5056};
case_table(5057) ->
    {5057,43921,5057,5057};
case_table(5058) ->
    {5058,43922,5058,5058};
case_table(5059) ->
    {5059,43923,5059,5059};
case_table(5060) ->
    {5060,43924,5060,5060};
case_table(5061) ->
    {5061,43925,5061,5061};
case_table(5062) ->
    {5062,43926,5062,5062};
case_table(5063) ->
    {5063,43927,5063,5063};
case_table(5064) ->
    {5064,43928,5064,5064};
case_table(5065) ->
    {5065,43929,5065,5065};
case_table(5066) ->
    {5066,43930,5066,5066};
case_table(5067) ->
    {5067,43931,5067,5067};
case_table(5068) ->
    {5068,43932,5068,5068};
case_table(5069) ->
    {5069,43933,5069,5069};
case_table(5070) ->
    {5070,43934,5070,5070};
case_table(5071) ->
    {5071,43935,5071,5071};
case_table(5072) ->
    {5072,43936,5072,5072};
case_table(5073) ->
    {5073,43937,5073,5073};
case_table(5074) ->
    {5074,43938,5074,5074};
case_table(5075) ->
    {5075,43939,5075,5075};
case_table(5076) ->
    {5076,43940,5076,5076};
case_table(5077) ->
    {5077,43941,5077,5077};
case_table(5078) ->
    {5078,43942,5078,5078};
case_table(5079) ->
    {5079,43943,5079,5079};
case_table(5080) ->
    {5080,43944,5080,5080};
case_table(5081) ->
    {5081,43945,5081,5081};
case_table(5082) ->
    {5082,43946,5082,5082};
case_table(5083) ->
    {5083,43947,5083,5083};
case_table(5084) ->
    {5084,43948,5084,5084};
case_table(5085) ->
    {5085,43949,5085,5085};
case_table(5086) ->
    {5086,43950,5086,5086};
case_table(5087) ->
    {5087,43951,5087,5087};
case_table(5088) ->
    {5088,43952,5088,5088};
case_table(5089) ->
    {5089,43953,5089,5089};
case_table(5090) ->
    {5090,43954,5090,5090};
case_table(5091) ->
    {5091,43955,5091,5091};
case_table(5092) ->
    {5092,43956,5092,5092};
case_table(5093) ->
    {5093,43957,5093,5093};
case_table(5094) ->
    {5094,43958,5094,5094};
case_table(5095) ->
    {5095,43959,5095,5095};
case_table(5096) ->
    {5096,43960,5096,5096};
case_table(5097) ->
    {5097,43961,5097,5097};
case_table(5098) ->
    {5098,43962,5098,5098};
case_table(5099) ->
    {5099,43963,5099,5099};
case_table(5100) ->
    {5100,43964,5100,5100};
case_table(5101) ->
    {5101,43965,5101,5101};
case_table(5102) ->
    {5102,43966,5102,5102};
case_table(5103) ->
    {5103,43967,5103,5103};
case_table(5104) ->
    {5104,5112,5104,5104};
case_table(5105) ->
    {5105,5113,5105,5105};
case_table(5106) ->
    {5106,5114,5106,5106};
case_table(5107) ->
    {5107,5115,5107,5107};
case_table(5108) ->
    {5108,5116,5108,5108};
case_table(5109) ->
    {5109,5117,5109,5109};
case_table(5112) ->
    {5104,5112,5104,5104};
case_table(5113) ->
    {5105,5113,5105,5105};
case_table(5114) ->
    {5106,5114,5106,5106};
case_table(5115) ->
    {5107,5115,5107,5107};
case_table(5116) ->
    {5108,5116,5108,5108};
case_table(5117) ->
    {5109,5117,5109,5109};
case_table(7296) ->
    {1042,7296,1042,1074};
case_table(7297) ->
    {1044,7297,1044,1076};
case_table(7298) ->
    {1054,7298,1054,1086};
case_table(7299) ->
    {1057,7299,1057,1089};
case_table(7300) ->
    {1058,7300,1058,1090};
case_table(7301) ->
    {1058,7301,1058,1090};
case_table(7302) ->
    {1066,7302,1066,1098};
case_table(7303) ->
    {1122,7303,1122,1123};
case_table(7304) ->
    {42570,7304,42570,42571};
case_table(7312) ->
    {7312,4304};
case_table(7313) ->
    {7313,4305};
case_table(7314) ->
    {7314,4306};
case_table(7315) ->
    {7315,4307};
case_table(7316) ->
    {7316,4308};
case_table(7317) ->
    {7317,4309};
case_table(7318) ->
    {7318,4310};
case_table(7319) ->
    {7319,4311};
case_table(7320) ->
    {7320,4312};
case_table(7321) ->
    {7321,4313};
case_table(7322) ->
    {7322,4314};
case_table(7323) ->
    {7323,4315};
case_table(7324) ->
    {7324,4316};
case_table(7325) ->
    {7325,4317};
case_table(7326) ->
    {7326,4318};
case_table(7327) ->
    {7327,4319};
case_table(7328) ->
    {7328,4320};
case_table(7329) ->
    {7329,4321};
case_table(7330) ->
    {7330,4322};
case_table(7331) ->
    {7331,4323};
case_table(7332) ->
    {7332,4324};
case_table(7333) ->
    {7333,4325};
case_table(7334) ->
    {7334,4326};
case_table(7335) ->
    {7335,4327};
case_table(7336) ->
    {7336,4328};
case_table(7337) ->
    {7337,4329};
case_table(7338) ->
    {7338,4330};
case_table(7339) ->
    {7339,4331};
case_table(7340) ->
    {7340,4332};
case_table(7341) ->
    {7341,4333};
case_table(7342) ->
    {7342,4334};
case_table(7343) ->
    {7343,4335};
case_table(7344) ->
    {7344,4336};
case_table(7345) ->
    {7345,4337};
case_table(7346) ->
    {7346,4338};
case_table(7347) ->
    {7347,4339};
case_table(7348) ->
    {7348,4340};
case_table(7349) ->
    {7349,4341};
case_table(7350) ->
    {7350,4342};
case_table(7351) ->
    {7351,4343};
case_table(7352) ->
    {7352,4344};
case_table(7353) ->
    {7353,4345};
case_table(7354) ->
    {7354,4346};
case_table(7357) ->
    {7357,4349};
case_table(7358) ->
    {7358,4350};
case_table(7359) ->
    {7359,4351};
case_table(7545) ->
    {42877,7545};
case_table(7549) ->
    {11363,7549};
case_table(7566) ->
    {42950,7566};
case_table(7680) ->
    {7680,7681};
case_table(7681) ->
    {7680,7681};
case_table(7682) ->
    {7682,7683};
case_table(7683) ->
    {7682,7683};
case_table(7684) ->
    {7684,7685};
case_table(7685) ->
    {7684,7685};
case_table(7686) ->
    {7686,7687};
case_table(7687) ->
    {7686,7687};
case_table(7688) ->
    {7688,7689};
case_table(7689) ->
    {7688,7689};
case_table(7690) ->
    {7690,7691};
case_table(7691) ->
    {7690,7691};
case_table(7692) ->
    {7692,7693};
case_table(7693) ->
    {7692,7693};
case_table(7694) ->
    {7694,7695};
case_table(7695) ->
    {7694,7695};
case_table(7696) ->
    {7696,7697};
case_table(7697) ->
    {7696,7697};
case_table(7698) ->
    {7698,7699};
case_table(7699) ->
    {7698,7699};
case_table(7700) ->
    {7700,7701};
case_table(7701) ->
    {7700,7701};
case_table(7702) ->
    {7702,7703};
case_table(7703) ->
    {7702,7703};
case_table(7704) ->
    {7704,7705};
case_table(7705) ->
    {7704,7705};
case_table(7706) ->
    {7706,7707};
case_table(7707) ->
    {7706,7707};
case_table(7708) ->
    {7708,7709};
case_table(7709) ->
    {7708,7709};
case_table(7710) ->
    {7710,7711};
case_table(7711) ->
    {7710,7711};
case_table(7712) ->
    {7712,7713};
case_table(7713) ->
    {7712,7713};
case_table(7714) ->
    {7714,7715};
case_table(7715) ->
    {7714,7715};
case_table(7716) ->
    {7716,7717};
case_table(7717) ->
    {7716,7717};
case_table(7718) ->
    {7718,7719};
case_table(7719) ->
    {7718,7719};
case_table(7720) ->
    {7720,7721};
case_table(7721) ->
    {7720,7721};
case_table(7722) ->
    {7722,7723};
case_table(7723) ->
    {7722,7723};
case_table(7724) ->
    {7724,7725};
case_table(7725) ->
    {7724,7725};
case_table(7726) ->
    {7726,7727};
case_table(7727) ->
    {7726,7727};
case_table(7728) ->
    {7728,7729};
case_table(7729) ->
    {7728,7729};
case_table(7730) ->
    {7730,7731};
case_table(7731) ->
    {7730,7731};
case_table(7732) ->
    {7732,7733};
case_table(7733) ->
    {7732,7733};
case_table(7734) ->
    {7734,7735};
case_table(7735) ->
    {7734,7735};
case_table(7736) ->
    {7736,7737};
case_table(7737) ->
    {7736,7737};
case_table(7738) ->
    {7738,7739};
case_table(7739) ->
    {7738,7739};
case_table(7740) ->
    {7740,7741};
case_table(7741) ->
    {7740,7741};
case_table(7742) ->
    {7742,7743};
case_table(7743) ->
    {7742,7743};
case_table(7744) ->
    {7744,7745};
case_table(7745) ->
    {7744,7745};
case_table(7746) ->
    {7746,7747};
case_table(7747) ->
    {7746,7747};
case_table(7748) ->
    {7748,7749};
case_table(7749) ->
    {7748,7749};
case_table(7750) ->
    {7750,7751};
case_table(7751) ->
    {7750,7751};
case_table(7752) ->
    {7752,7753};
case_table(7753) ->
    {7752,7753};
case_table(7754) ->
    {7754,7755};
case_table(7755) ->
    {7754,7755};
case_table(7756) ->
    {7756,7757};
case_table(7757) ->
    {7756,7757};
case_table(7758) ->
    {7758,7759};
case_table(7759) ->
    {7758,7759};
case_table(7760) ->
    {7760,7761};
case_table(7761) ->
    {7760,7761};
case_table(7762) ->
    {7762,7763};
case_table(7763) ->
    {7762,7763};
case_table(7764) ->
    {7764,7765};
case_table(7765) ->
    {7764,7765};
case_table(7766) ->
    {7766,7767};
case_table(7767) ->
    {7766,7767};
case_table(7768) ->
    {7768,7769};
case_table(7769) ->
    {7768,7769};
case_table(7770) ->
    {7770,7771};
case_table(7771) ->
    {7770,7771};
case_table(7772) ->
    {7772,7773};
case_table(7773) ->
    {7772,7773};
case_table(7774) ->
    {7774,7775};
case_table(7775) ->
    {7774,7775};
case_table(7776) ->
    {7776,7777};
case_table(7777) ->
    {7776,7777};
case_table(7778) ->
    {7778,7779};
case_table(7779) ->
    {7778,7779};
case_table(7780) ->
    {7780,7781};
case_table(7781) ->
    {7780,7781};
case_table(7782) ->
    {7782,7783};
case_table(7783) ->
    {7782,7783};
case_table(7784) ->
    {7784,7785};
case_table(7785) ->
    {7784,7785};
case_table(7786) ->
    {7786,7787};
case_table(7787) ->
    {7786,7787};
case_table(7788) ->
    {7788,7789};
case_table(7789) ->
    {7788,7789};
case_table(7790) ->
    {7790,7791};
case_table(7791) ->
    {7790,7791};
case_table(7792) ->
    {7792,7793};
case_table(7793) ->
    {7792,7793};
case_table(7794) ->
    {7794,7795};
case_table(7795) ->
    {7794,7795};
case_table(7796) ->
    {7796,7797};
case_table(7797) ->
    {7796,7797};
case_table(7798) ->
    {7798,7799};
case_table(7799) ->
    {7798,7799};
case_table(7800) ->
    {7800,7801};
case_table(7801) ->
    {7800,7801};
case_table(7802) ->
    {7802,7803};
case_table(7803) ->
    {7802,7803};
case_table(7804) ->
    {7804,7805};
case_table(7805) ->
    {7804,7805};
case_table(7806) ->
    {7806,7807};
case_table(7807) ->
    {7806,7807};
case_table(7808) ->
    {7808,7809};
case_table(7809) ->
    {7808,7809};
case_table(7810) ->
    {7810,7811};
case_table(7811) ->
    {7810,7811};
case_table(7812) ->
    {7812,7813};
case_table(7813) ->
    {7812,7813};
case_table(7814) ->
    {7814,7815};
case_table(7815) ->
    {7814,7815};
case_table(7816) ->
    {7816,7817};
case_table(7817) ->
    {7816,7817};
case_table(7818) ->
    {7818,7819};
case_table(7819) ->
    {7818,7819};
case_table(7820) ->
    {7820,7821};
case_table(7821) ->
    {7820,7821};
case_table(7822) ->
    {7822,7823};
case_table(7823) ->
    {7822,7823};
case_table(7824) ->
    {7824,7825};
case_table(7825) ->
    {7824,7825};
case_table(7826) ->
    {7826,7827};
case_table(7827) ->
    {7826,7827};
case_table(7828) ->
    {7828,7829};
case_table(7829) ->
    {7828,7829};
case_table(7830) ->
    {[72, 817],7830,[72, 817],[104, 817]};
case_table(7831) ->
    {[84, 776],7831,[84, 776],[116, 776]};
case_table(7832) ->
    {[87, 778],7832,[87, 778],[119, 778]};
case_table(7833) ->
    {[89, 778],7833,[89, 778],[121, 778]};
case_table(7834) ->
    {[65, 702],7834,[65, 702],[97, 702]};
case_table(7835) ->
    {7776,7835,7776,7777};
case_table(7838) ->
    {7838,223,7838,[115, 115]};
case_table(7840) ->
    {7840,7841};
case_table(7841) ->
    {7840,7841};
case_table(7842) ->
    {7842,7843};
case_table(7843) ->
    {7842,7843};
case_table(7844) ->
    {7844,7845};
case_table(7845) ->
    {7844,7845};
case_table(7846) ->
    {7846,7847};
case_table(7847) ->
    {7846,7847};
case_table(7848) ->
    {7848,7849};
case_table(7849) ->
    {7848,7849};
case_table(7850) ->
    {7850,7851};
case_table(7851) ->
    {7850,7851};
case_table(7852) ->
    {7852,7853};
case_table(7853) ->
    {7852,7853};
case_table(7854) ->
    {7854,7855};
case_table(7855) ->
    {7854,7855};
case_table(7856) ->
    {7856,7857};
case_table(7857) ->
    {7856,7857};
case_table(7858) ->
    {7858,7859};
case_table(7859) ->
    {7858,7859};
case_table(7860) ->
    {7860,7861};
case_table(7861) ->
    {7860,7861};
case_table(7862) ->
    {7862,7863};
case_table(7863) ->
    {7862,7863};
case_table(7864) ->
    {7864,7865};
case_table(7865) ->
    {7864,7865};
case_table(7866) ->
    {7866,7867};
case_table(7867) ->
    {7866,7867};
case_table(7868) ->
    {7868,7869};
case_table(7869) ->
    {7868,7869};
case_table(7870) ->
    {7870,7871};
case_table(7871) ->
    {7870,7871};
case_table(7872) ->
    {7872,7873};
case_table(7873) ->
    {7872,7873};
case_table(7874) ->
    {7874,7875};
case_table(7875) ->
    {7874,7875};
case_table(7876) ->
    {7876,7877};
case_table(7877) ->
    {7876,7877};
case_table(7878) ->
    {7878,7879};
case_table(7879) ->
    {7878,7879};
case_table(7880) ->
    {7880,7881};
case_table(7881) ->
    {7880,7881};
case_table(7882) ->
    {7882,7883};
case_table(7883) ->
    {7882,7883};
case_table(7884) ->
    {7884,7885};
case_table(7885) ->
    {7884,7885};
case_table(7886) ->
    {7886,7887};
case_table(7887) ->
    {7886,7887};
case_table(7888) ->
    {7888,7889};
case_table(7889) ->
    {7888,7889};
case_table(7890) ->
    {7890,7891};
case_table(7891) ->
    {7890,7891};
case_table(7892) ->
    {7892,7893};
case_table(7893) ->
    {7892,7893};
case_table(7894) ->
    {7894,7895};
case_table(7895) ->
    {7894,7895};
case_table(7896) ->
    {7896,7897};
case_table(7897) ->
    {7896,7897};
case_table(7898) ->
    {7898,7899};
case_table(7899) ->
    {7898,7899};
case_table(7900) ->
    {7900,7901};
case_table(7901) ->
    {7900,7901};
case_table(7902) ->
    {7902,7903};
case_table(7903) ->
    {7902,7903};
case_table(7904) ->
    {7904,7905};
case_table(7905) ->
    {7904,7905};
case_table(7906) ->
    {7906,7907};
case_table(7907) ->
    {7906,7907};
case_table(7908) ->
    {7908,7909};
case_table(7909) ->
    {7908,7909};
case_table(7910) ->
    {7910,7911};
case_table(7911) ->
    {7910,7911};
case_table(7912) ->
    {7912,7913};
case_table(7913) ->
    {7912,7913};
case_table(7914) ->
    {7914,7915};
case_table(7915) ->
    {7914,7915};
case_table(7916) ->
    {7916,7917};
case_table(7917) ->
    {7916,7917};
case_table(7918) ->
    {7918,7919};
case_table(7919) ->
    {7918,7919};
case_table(7920) ->
    {7920,7921};
case_table(7921) ->
    {7920,7921};
case_table(7922) ->
    {7922,7923};
case_table(7923) ->
    {7922,7923};
case_table(7924) ->
    {7924,7925};
case_table(7925) ->
    {7924,7925};
case_table(7926) ->
    {7926,7927};
case_table(7927) ->
    {7926,7927};
case_table(7928) ->
    {7928,7929};
case_table(7929) ->
    {7928,7929};
case_table(7930) ->
    {7930,7931};
case_table(7931) ->
    {7930,7931};
case_table(7932) ->
    {7932,7933};
case_table(7933) ->
    {7932,7933};
case_table(7934) ->
    {7934,7935};
case_table(7935) ->
    {7934,7935};
case_table(7936) ->
    {7944,7936};
case_table(7937) ->
    {7945,7937};
case_table(7938) ->
    {7946,7938};
case_table(7939) ->
    {7947,7939};
case_table(7940) ->
    {7948,7940};
case_table(7941) ->
    {7949,7941};
case_table(7942) ->
    {7950,7942};
case_table(7943) ->
    {7951,7943};
case_table(7944) ->
    {7944,7936};
case_table(7945) ->
    {7945,7937};
case_table(7946) ->
    {7946,7938};
case_table(7947) ->
    {7947,7939};
case_table(7948) ->
    {7948,7940};
case_table(7949) ->
    {7949,7941};
case_table(7950) ->
    {7950,7942};
case_table(7951) ->
    {7951,7943};
case_table(7952) ->
    {7960,7952};
case_table(7953) ->
    {7961,7953};
case_table(7954) ->
    {7962,7954};
case_table(7955) ->
    {7963,7955};
case_table(7956) ->
    {7964,7956};
case_table(7957) ->
    {7965,7957};
case_table(7960) ->
    {7960,7952};
case_table(7961) ->
    {7961,7953};
case_table(7962) ->
    {7962,7954};
case_table(7963) ->
    {7963,7955};
case_table(7964) ->
    {7964,7956};
case_table(7965) ->
    {7965,7957};
case_table(7968) ->
    {7976,7968};
case_table(7969) ->
    {7977,7969};
case_table(7970) ->
    {7978,7970};
case_table(7971) ->
    {7979,7971};
case_table(7972) ->
    {7980,7972};
case_table(7973) ->
    {7981,7973};
case_table(7974) ->
    {7982,7974};
case_table(7975) ->
    {7983,7975};
case_table(7976) ->
    {7976,7968};
case_table(7977) ->
    {7977,7969};
case_table(7978) ->
    {7978,7970};
case_table(7979) ->
    {7979,7971};
case_table(7980) ->
    {7980,7972};
case_table(7981) ->
    {7981,7973};
case_table(7982) ->
    {7982,7974};
case_table(7983) ->
    {7983,7975};
case_table(7984) ->
    {7992,7984};
case_table(7985) ->
    {7993,7985};
case_table(7986) ->
    {7994,7986};
case_table(7987) ->
    {7995,7987};
case_table(7988) ->
    {7996,7988};
case_table(7989) ->
    {7997,7989};
case_table(7990) ->
    {7998,7990};
case_table(7991) ->
    {7999,7991};
case_table(7992) ->
    {7992,7984};
case_table(7993) ->
    {7993,7985};
case_table(7994) ->
    {7994,7986};
case_table(7995) ->
    {7995,7987};
case_table(7996) ->
    {7996,7988};
case_table(7997) ->
    {7997,7989};
case_table(7998) ->
    {7998,7990};
case_table(7999) ->
    {7999,7991};
case_table(8000) ->
    {8008,8000};
case_table(8001) ->
    {8009,8001};
case_table(8002) ->
    {8010,8002};
case_table(8003) ->
    {8011,8003};
case_table(8004) ->
    {8012,8004};
case_table(8005) ->
    {8013,8005};
case_table(8008) ->
    {8008,8000};
case_table(8009) ->
    {8009,8001};
case_table(8010) ->
    {8010,8002};
case_table(8011) ->
    {8011,8003};
case_table(8012) ->
    {8012,8004};
case_table(8013) ->
    {8013,8005};
case_table(8016) ->
    {[933, 787],8016,[933, 787],[965, 787]};
case_table(8017) ->
    {8025,8017};
case_table(8018) ->
    {[933, 787, 768],8018,[933, 787, 768],[965, 787, 768]};
case_table(8019) ->
    {8027,8019};
case_table(8020) ->
    {[933, 787, 769],8020,[933, 787, 769],[965, 787, 769]};
case_table(8021) ->
    {8029,8021};
case_table(8022) ->
    {[933, 787, 834],8022,[933, 787, 834],[965, 787, 834]};
case_table(8023) ->
    {8031,8023};
case_table(8025) ->
    {8025,8017};
case_table(8027) ->
    {8027,8019};
case_table(8029) ->
    {8029,8021};
case_table(8031) ->
    {8031,8023};
case_table(8032) ->
    {8040,8032};
case_table(8033) ->
    {8041,8033};
case_table(8034) ->
    {8042,8034};
case_table(8035) ->
    {8043,8035};
case_table(8036) ->
    {8044,8036};
case_table(8037) ->
    {8045,8037};
case_table(8038) ->
    {8046,8038};
case_table(8039) ->
    {8047,8039};
case_table(8040) ->
    {8040,8032};
case_table(8041) ->
    {8041,8033};
case_table(8042) ->
    {8042,8034};
case_table(8043) ->
    {8043,8035};
case_table(8044) ->
    {8044,8036};
case_table(8045) ->
    {8045,8037};
case_table(8046) ->
    {8046,8038};
case_table(8047) ->
    {8047,8039};
case_table(8048) ->
    {8122,8048};
case_table(8049) ->
    {8123,8049};
case_table(8050) ->
    {8136,8050};
case_table(8051) ->
    {8137,8051};
case_table(8052) ->
    {8138,8052};
case_table(8053) ->
    {8139,8053};
case_table(8054) ->
    {8154,8054};
case_table(8055) ->
    {8155,8055};
case_table(8056) ->
    {8184,8056};
case_table(8057) ->
    {8185,8057};
case_table(8058) ->
    {8170,8058};
case_table(8059) ->
    {8171,8059};
case_table(8060) ->
    {8186,8060};
case_table(8061) ->
    {8187,8061};
case_table(8064) ->
    {[7944, 921],8064,8072,[7936, 953]};
case_table(8065) ->
    {[7945, 921],8065,8073,[7937, 953]};
case_table(8066) ->
    {[7946, 921],8066,8074,[7938, 953]};
case_table(8067) ->
    {[7947, 921],8067,8075,[7939, 953]};
case_table(8068) ->
    {[7948, 921],8068,8076,[7940, 953]};
case_table(8069) ->
    {[7949, 921],8069,8077,[7941, 953]};
case_table(8070) ->
    {[7950, 921],8070,8078,[7942, 953]};
case_table(8071) ->
    {[7951, 921],8071,8079,[7943, 953]};
case_table(8072) ->
    {[7944, 921],8064,8072,[7936, 953]};
case_table(8073) ->
    {[7945, 921],8065,8073,[7937, 953]};
case_table(8074) ->
    {[7946, 921],8066,8074,[7938, 953]};
case_table(8075) ->
    {[7947, 921],8067,8075,[7939, 953]};
case_table(8076) ->
    {[7948, 921],8068,8076,[7940, 953]};
case_table(8077) ->
    {[7949, 921],8069,8077,[7941, 953]};
case_table(8078) ->
    {[7950, 921],8070,8078,[7942, 953]};
case_table(8079) ->
    {[7951, 921],8071,8079,[7943, 953]};
case_table(8080) ->
    {[7976, 921],8080,8088,[7968, 953]};
case_table(8081) ->
    {[7977, 921],8081,8089,[7969, 953]};
case_table(8082) ->
    {[7978, 921],8082,8090,[7970, 953]};
case_table(8083) ->
    {[7979, 921],8083,8091,[7971, 953]};
case_table(8084) ->
    {[7980, 921],8084,8092,[7972, 953]};
case_table(8085) ->
    {[7981, 921],8085,8093,[7973, 953]};
case_table(8086) ->
    {[7982, 921],8086,8094,[7974, 953]};
case_table(8087) ->
    {[7983, 921],8087,8095,[7975, 953]};
case_table(8088) ->
    {[7976, 921],8080,8088,[7968, 953]};
case_table(8089) ->
    {[7977, 921],8081,8089,[7969, 953]};
case_table(8090) ->
    {[7978, 921],8082,8090,[7970, 953]};
case_table(8091) ->
    {[7979, 921],8083,8091,[7971, 953]};
case_table(8092) ->
    {[7980, 921],8084,8092,[7972, 953]};
case_table(8093) ->
    {[7981, 921],8085,8093,[7973, 953]};
case_table(8094) ->
    {[7982, 921],8086,8094,[7974, 953]};
case_table(8095) ->
    {[7983, 921],8087,8095,[7975, 953]};
case_table(8096) ->
    {[8040, 921],8096,8104,[8032, 953]};
case_table(8097) ->
    {[8041, 921],8097,8105,[8033, 953]};
case_table(8098) ->
    {[8042, 921],8098,8106,[8034, 953]};
case_table(8099) ->
    {[8043, 921],8099,8107,[8035, 953]};
case_table(8100) ->
    {[8044, 921],8100,8108,[8036, 953]};
case_table(8101) ->
    {[8045, 921],8101,8109,[8037, 953]};
case_table(8102) ->
    {[8046, 921],8102,8110,[8038, 953]};
case_table(8103) ->
    {[8047, 921],8103,8111,[8039, 953]};
case_table(8104) ->
    {[8040, 921],8096,8104,[8032, 953]};
case_table(8105) ->
    {[8041, 921],8097,8105,[8033, 953]};
case_table(8106) ->
    {[8042, 921],8098,8106,[8034, 953]};
case_table(8107) ->
    {[8043, 921],8099,8107,[8035, 953]};
case_table(8108) ->
    {[8044, 921],8100,8108,[8036, 953]};
case_table(8109) ->
    {[8045, 921],8101,8109,[8037, 953]};
case_table(8110) ->
    {[8046, 921],8102,8110,[8038, 953]};
case_table(8111) ->
    {[8047, 921],8103,8111,[8039, 953]};
case_table(8112) ->
    {8120,8112};
case_table(8113) ->
    {8121,8113};
case_table(8114) ->
    {[8122, 921],8114,[8122, 837],[8048, 953]};
case_table(8115) ->
    {[913, 921],8115,8124,[945, 953]};
case_table(8116) ->
    {[902, 921],8116,[902, 837],[940, 953]};
case_table(8118) ->
    {[913, 834],8118,[913, 834],[945, 834]};
case_table(8119) ->
    {[913, 834, 921],8119,[913, 834, 837],[945, 834, 953]};
case_table(8120) ->
    {8120,8112};
case_table(8121) ->
    {8121,8113};
case_table(8122) ->
    {8122,8048};
case_table(8123) ->
    {8123,8049};
case_table(8124) ->
    {[913, 921],8115,8124,[945, 953]};
case_table(8126) ->
    {921,8126,921,953};
case_table(8130) ->
    {[8138, 921],8130,[8138, 837],[8052, 953]};
case_table(8131) ->
    {[919, 921],8131,8140,[951, 953]};
case_table(8132) ->
    {[905, 921],8132,[905, 837],[942, 953]};
case_table(8134) ->
    {[919, 834],8134,[919, 834],[951, 834]};
case_table(8135) ->
    {[919, 834, 921],8135,[919, 834, 837],[951, 834, 953]};
case_table(8136) ->
    {8136,8050};
case_table(8137) ->
    {8137,8051};
case_table(8138) ->
    {8138,8052};
case_table(8139) ->
    {8139,8053};
case_table(8140) ->
    {[919, 921],8131,8140,[951, 953]};
case_table(8144) ->
    {8152,8144};
case_table(8145) ->
    {8153,8145};
case_table(8146) ->
    {[921, 776, 768],8146,[921, 776, 768],[953, 776, 768]};
case_table(8147) ->
    {[921, 776, 769],8147,[921, 776, 769],[953, 776, 769]};
case_table(8150) ->
    {[921, 834],8150,[921, 834],[953, 834]};
case_table(8151) ->
    {[921, 776, 834],8151,[921, 776, 834],[953, 776, 834]};
case_table(8152) ->
    {8152,8144};
case_table(8153) ->
    {8153,8145};
case_table(8154) ->
    {8154,8054};
case_table(8155) ->
    {8155,8055};
case_table(8160) ->
    {8168,8160};
case_table(8161) ->
    {8169,8161};
case_table(8162) ->
    {[933, 776, 768],8162,[933, 776, 768],[965, 776, 768]};
case_table(8163) ->
    {[933, 776, 769],8163,[933, 776, 769],[965, 776, 769]};
case_table(8164) ->
    {[929, 787],8164,[929, 787],[961, 787]};
case_table(8165) ->
    {8172,8165};
case_table(8166) ->
    {[933, 834],8166,[933, 834],[965, 834]};
case_table(8167) ->
    {[933, 776, 834],8167,[933, 776, 834],[965, 776, 834]};
case_table(8168) ->
    {8168,8160};
case_table(8169) ->
    {8169,8161};
case_table(8170) ->
    {8170,8058};
case_table(8171) ->
    {8171,8059};
case_table(8172) ->
    {8172,8165};
case_table(8178) ->
    {[8186, 921],8178,[8186, 837],[8060, 953]};
case_table(8179) ->
    {[937, 921],8179,8188,[969, 953]};
case_table(8180) ->
    {[911, 921],8180,[911, 837],[974, 953]};
case_table(8182) ->
    {[937, 834],8182,[937, 834],[969, 834]};
case_table(8183) ->
    {[937, 834, 921],8183,[937, 834, 837],[969, 834, 953]};
case_table(8184) ->
    {8184,8056};
case_table(8185) ->
    {8185,8057};
case_table(8186) ->
    {8186,8060};
case_table(8187) ->
    {8187,8061};
case_table(8188) ->
    {[937, 921],8179,8188,[969, 953]};
case_table(8486) ->
    {8486,969};
case_table(8490) ->
    {8490,107};
case_table(8491) ->
    {8491,229};
case_table(8498) ->
    {8498,8526};
case_table(8526) ->
    {8498,8526};
case_table(8544) ->
    {8544,8560};
case_table(8545) ->
    {8545,8561};
case_table(8546) ->
    {8546,8562};
case_table(8547) ->
    {8547,8563};
case_table(8548) ->
    {8548,8564};
case_table(8549) ->
    {8549,8565};
case_table(8550) ->
    {8550,8566};
case_table(8551) ->
    {8551,8567};
case_table(8552) ->
    {8552,8568};
case_table(8553) ->
    {8553,8569};
case_table(8554) ->
    {8554,8570};
case_table(8555) ->
    {8555,8571};
case_table(8556) ->
    {8556,8572};
case_table(8557) ->
    {8557,8573};
case_table(8558) ->
    {8558,8574};
case_table(8559) ->
    {8559,8575};
case_table(8560) ->
    {8544,8560};
case_table(8561) ->
    {8545,8561};
case_table(8562) ->
    {8546,8562};
case_table(8563) ->
    {8547,8563};
case_table(8564) ->
    {8548,8564};
case_table(8565) ->
    {8549,8565};
case_table(8566) ->
    {8550,8566};
case_table(8567) ->
    {8551,8567};
case_table(8568) ->
    {8552,8568};
case_table(8569) ->
    {8553,8569};
case_table(8570) ->
    {8554,8570};
case_table(8571) ->
    {8555,8571};
case_table(8572) ->
    {8556,8572};
case_table(8573) ->
    {8557,8573};
case_table(8574) ->
    {8558,8574};
case_table(8575) ->
    {8559,8575};
case_table(8579) ->
    {8579,8580};
case_table(8580) ->
    {8579,8580};
case_table(9398) ->
    {9398,9424};
case_table(9399) ->
    {9399,9425};
case_table(9400) ->
    {9400,9426};
case_table(9401) ->
    {9401,9427};
case_table(9402) ->
    {9402,9428};
case_table(9403) ->
    {9403,9429};
case_table(9404) ->
    {9404,9430};
case_table(9405) ->
    {9405,9431};
case_table(9406) ->
    {9406,9432};
case_table(9407) ->
    {9407,9433};
case_table(9408) ->
    {9408,9434};
case_table(9409) ->
    {9409,9435};
case_table(9410) ->
    {9410,9436};
case_table(9411) ->
    {9411,9437};
case_table(9412) ->
    {9412,9438};
case_table(9413) ->
    {9413,9439};
case_table(9414) ->
    {9414,9440};
case_table(9415) ->
    {9415,9441};
case_table(9416) ->
    {9416,9442};
case_table(9417) ->
    {9417,9443};
case_table(9418) ->
    {9418,9444};
case_table(9419) ->
    {9419,9445};
case_table(9420) ->
    {9420,9446};
case_table(9421) ->
    {9421,9447};
case_table(9422) ->
    {9422,9448};
case_table(9423) ->
    {9423,9449};
case_table(9424) ->
    {9398,9424};
case_table(9425) ->
    {9399,9425};
case_table(9426) ->
    {9400,9426};
case_table(9427) ->
    {9401,9427};
case_table(9428) ->
    {9402,9428};
case_table(9429) ->
    {9403,9429};
case_table(9430) ->
    {9404,9430};
case_table(9431) ->
    {9405,9431};
case_table(9432) ->
    {9406,9432};
case_table(9433) ->
    {9407,9433};
case_table(9434) ->
    {9408,9434};
case_table(9435) ->
    {9409,9435};
case_table(9436) ->
    {9410,9436};
case_table(9437) ->
    {9411,9437};
case_table(9438) ->
    {9412,9438};
case_table(9439) ->
    {9413,9439};
case_table(9440) ->
    {9414,9440};
case_table(9441) ->
    {9415,9441};
case_table(9442) ->
    {9416,9442};
case_table(9443) ->
    {9417,9443};
case_table(9444) ->
    {9418,9444};
case_table(9445) ->
    {9419,9445};
case_table(9446) ->
    {9420,9446};
case_table(9447) ->
    {9421,9447};
case_table(9448) ->
    {9422,9448};
case_table(9449) ->
    {9423,9449};
case_table(11264) ->
    {11264,11312};
case_table(11265) ->
    {11265,11313};
case_table(11266) ->
    {11266,11314};
case_table(11267) ->
    {11267,11315};
case_table(11268) ->
    {11268,11316};
case_table(11269) ->
    {11269,11317};
case_table(11270) ->
    {11270,11318};
case_table(11271) ->
    {11271,11319};
case_table(11272) ->
    {11272,11320};
case_table(11273) ->
    {11273,11321};
case_table(11274) ->
    {11274,11322};
case_table(11275) ->
    {11275,11323};
case_table(11276) ->
    {11276,11324};
case_table(11277) ->
    {11277,11325};
case_table(11278) ->
    {11278,11326};
case_table(11279) ->
    {11279,11327};
case_table(11280) ->
    {11280,11328};
case_table(11281) ->
    {11281,11329};
case_table(11282) ->
    {11282,11330};
case_table(11283) ->
    {11283,11331};
case_table(11284) ->
    {11284,11332};
case_table(11285) ->
    {11285,11333};
case_table(11286) ->
    {11286,11334};
case_table(11287) ->
    {11287,11335};
case_table(11288) ->
    {11288,11336};
case_table(11289) ->
    {11289,11337};
case_table(11290) ->
    {11290,11338};
case_table(11291) ->
    {11291,11339};
case_table(11292) ->
    {11292,11340};
case_table(11293) ->
    {11293,11341};
case_table(11294) ->
    {11294,11342};
case_table(11295) ->
    {11295,11343};
case_table(11296) ->
    {11296,11344};
case_table(11297) ->
    {11297,11345};
case_table(11298) ->
    {11298,11346};
case_table(11299) ->
    {11299,11347};
case_table(11300) ->
    {11300,11348};
case_table(11301) ->
    {11301,11349};
case_table(11302) ->
    {11302,11350};
case_table(11303) ->
    {11303,11351};
case_table(11304) ->
    {11304,11352};
case_table(11305) ->
    {11305,11353};
case_table(11306) ->
    {11306,11354};
case_table(11307) ->
    {11307,11355};
case_table(11308) ->
    {11308,11356};
case_table(11309) ->
    {11309,11357};
case_table(11310) ->
    {11310,11358};
case_table(11312) ->
    {11264,11312};
case_table(11313) ->
    {11265,11313};
case_table(11314) ->
    {11266,11314};
case_table(11315) ->
    {11267,11315};
case_table(11316) ->
    {11268,11316};
case_table(11317) ->
    {11269,11317};
case_table(11318) ->
    {11270,11318};
case_table(11319) ->
    {11271,11319};
case_table(11320) ->
    {11272,11320};
case_table(11321) ->
    {11273,11321};
case_table(11322) ->
    {11274,11322};
case_table(11323) ->
    {11275,11323};
case_table(11324) ->
    {11276,11324};
case_table(11325) ->
    {11277,11325};
case_table(11326) ->
    {11278,11326};
case_table(11327) ->
    {11279,11327};
case_table(11328) ->
    {11280,11328};
case_table(11329) ->
    {11281,11329};
case_table(11330) ->
    {11282,11330};
case_table(11331) ->
    {11283,11331};
case_table(11332) ->
    {11284,11332};
case_table(11333) ->
    {11285,11333};
case_table(11334) ->
    {11286,11334};
case_table(11335) ->
    {11287,11335};
case_table(11336) ->
    {11288,11336};
case_table(11337) ->
    {11289,11337};
case_table(11338) ->
    {11290,11338};
case_table(11339) ->
    {11291,11339};
case_table(11340) ->
    {11292,11340};
case_table(11341) ->
    {11293,11341};
case_table(11342) ->
    {11294,11342};
case_table(11343) ->
    {11295,11343};
case_table(11344) ->
    {11296,11344};
case_table(11345) ->
    {11297,11345};
case_table(11346) ->
    {11298,11346};
case_table(11347) ->
    {11299,11347};
case_table(11348) ->
    {11300,11348};
case_table(11349) ->
    {11301,11349};
case_table(11350) ->
    {11302,11350};
case_table(11351) ->
    {11303,11351};
case_table(11352) ->
    {11304,11352};
case_table(11353) ->
    {11305,11353};
case_table(11354) ->
    {11306,11354};
case_table(11355) ->
    {11307,11355};
case_table(11356) ->
    {11308,11356};
case_table(11357) ->
    {11309,11357};
case_table(11358) ->
    {11310,11358};
case_table(11360) ->
    {11360,11361};
case_table(11361) ->
    {11360,11361};
case_table(11362) ->
    {11362,619};
case_table(11363) ->
    {11363,7549};
case_table(11364) ->
    {11364,637};
case_table(11365) ->
    {570,11365};
case_table(11366) ->
    {574,11366};
case_table(11367) ->
    {11367,11368};
case_table(11368) ->
    {11367,11368};
case_table(11369) ->
    {11369,11370};
case_table(11370) ->
    {11369,11370};
case_table(11371) ->
    {11371,11372};
case_table(11372) ->
    {11371,11372};
case_table(11373) ->
    {11373,593};
case_table(11374) ->
    {11374,625};
case_table(11375) ->
    {11375,592};
case_table(11376) ->
    {11376,594};
case_table(11378) ->
    {11378,11379};
case_table(11379) ->
    {11378,11379};
case_table(11381) ->
    {11381,11382};
case_table(11382) ->
    {11381,11382};
case_table(11390) ->
    {11390,575};
case_table(11391) ->
    {11391,576};
case_table(11392) ->
    {11392,11393};
case_table(11393) ->
    {11392,11393};
case_table(11394) ->
    {11394,11395};
case_table(11395) ->
    {11394,11395};
case_table(11396) ->
    {11396,11397};
case_table(11397) ->
    {11396,11397};
case_table(11398) ->
    {11398,11399};
case_table(11399) ->
    {11398,11399};
case_table(11400) ->
    {11400,11401};
case_table(11401) ->
    {11400,11401};
case_table(11402) ->
    {11402,11403};
case_table(11403) ->
    {11402,11403};
case_table(11404) ->
    {11404,11405};
case_table(11405) ->
    {11404,11405};
case_table(11406) ->
    {11406,11407};
case_table(11407) ->
    {11406,11407};
case_table(11408) ->
    {11408,11409};
case_table(11409) ->
    {11408,11409};
case_table(11410) ->
    {11410,11411};
case_table(11411) ->
    {11410,11411};
case_table(11412) ->
    {11412,11413};
case_table(11413) ->
    {11412,11413};
case_table(11414) ->
    {11414,11415};
case_table(11415) ->
    {11414,11415};
case_table(11416) ->
    {11416,11417};
case_table(11417) ->
    {11416,11417};
case_table(11418) ->
    {11418,11419};
case_table(11419) ->
    {11418,11419};
case_table(11420) ->
    {11420,11421};
case_table(11421) ->
    {11420,11421};
case_table(11422) ->
    {11422,11423};
case_table(11423) ->
    {11422,11423};
case_table(11424) ->
    {11424,11425};
case_table(11425) ->
    {11424,11425};
case_table(11426) ->
    {11426,11427};
case_table(11427) ->
    {11426,11427};
case_table(11428) ->
    {11428,11429};
case_table(11429) ->
    {11428,11429};
case_table(11430) ->
    {11430,11431};
case_table(11431) ->
    {11430,11431};
case_table(11432) ->
    {11432,11433};
case_table(11433) ->
    {11432,11433};
case_table(11434) ->
    {11434,11435};
case_table(11435) ->
    {11434,11435};
case_table(11436) ->
    {11436,11437};
case_table(11437) ->
    {11436,11437};
case_table(11438) ->
    {11438,11439};
case_table(11439) ->
    {11438,11439};
case_table(11440) ->
    {11440,11441};
case_table(11441) ->
    {11440,11441};
case_table(11442) ->
    {11442,11443};
case_table(11443) ->
    {11442,11443};
case_table(11444) ->
    {11444,11445};
case_table(11445) ->
    {11444,11445};
case_table(11446) ->
    {11446,11447};
case_table(11447) ->
    {11446,11447};
case_table(11448) ->
    {11448,11449};
case_table(11449) ->
    {11448,11449};
case_table(11450) ->
    {11450,11451};
case_table(11451) ->
    {11450,11451};
case_table(11452) ->
    {11452,11453};
case_table(11453) ->
    {11452,11453};
case_table(11454) ->
    {11454,11455};
case_table(11455) ->
    {11454,11455};
case_table(11456) ->
    {11456,11457};
case_table(11457) ->
    {11456,11457};
case_table(11458) ->
    {11458,11459};
case_table(11459) ->
    {11458,11459};
case_table(11460) ->
    {11460,11461};
case_table(11461) ->
    {11460,11461};
case_table(11462) ->
    {11462,11463};
case_table(11463) ->
    {11462,11463};
case_table(11464) ->
    {11464,11465};
case_table(11465) ->
    {11464,11465};
case_table(11466) ->
    {11466,11467};
case_table(11467) ->
    {11466,11467};
case_table(11468) ->
    {11468,11469};
case_table(11469) ->
    {11468,11469};
case_table(11470) ->
    {11470,11471};
case_table(11471) ->
    {11470,11471};
case_table(11472) ->
    {11472,11473};
case_table(11473) ->
    {11472,11473};
case_table(11474) ->
    {11474,11475};
case_table(11475) ->
    {11474,11475};
case_table(11476) ->
    {11476,11477};
case_table(11477) ->
    {11476,11477};
case_table(11478) ->
    {11478,11479};
case_table(11479) ->
    {11478,11479};
case_table(11480) ->
    {11480,11481};
case_table(11481) ->
    {11480,11481};
case_table(11482) ->
    {11482,11483};
case_table(11483) ->
    {11482,11483};
case_table(11484) ->
    {11484,11485};
case_table(11485) ->
    {11484,11485};
case_table(11486) ->
    {11486,11487};
case_table(11487) ->
    {11486,11487};
case_table(11488) ->
    {11488,11489};
case_table(11489) ->
    {11488,11489};
case_table(11490) ->
    {11490,11491};
case_table(11491) ->
    {11490,11491};
case_table(11499) ->
    {11499,11500};
case_table(11500) ->
    {11499,11500};
case_table(11501) ->
    {11501,11502};
case_table(11502) ->
    {11501,11502};
case_table(11506) ->
    {11506,11507};
case_table(11507) ->
    {11506,11507};
case_table(11520) ->
    {4256,11520};
case_table(11521) ->
    {4257,11521};
case_table(11522) ->
    {4258,11522};
case_table(11523) ->
    {4259,11523};
case_table(11524) ->
    {4260,11524};
case_table(11525) ->
    {4261,11525};
case_table(11526) ->
    {4262,11526};
case_table(11527) ->
    {4263,11527};
case_table(11528) ->
    {4264,11528};
case_table(11529) ->
    {4265,11529};
case_table(11530) ->
    {4266,11530};
case_table(11531) ->
    {4267,11531};
case_table(11532) ->
    {4268,11532};
case_table(11533) ->
    {4269,11533};
case_table(11534) ->
    {4270,11534};
case_table(11535) ->
    {4271,11535};
case_table(11536) ->
    {4272,11536};
case_table(11537) ->
    {4273,11537};
case_table(11538) ->
    {4274,11538};
case_table(11539) ->
    {4275,11539};
case_table(11540) ->
    {4276,11540};
case_table(11541) ->
    {4277,11541};
case_table(11542) ->
    {4278,11542};
case_table(11543) ->
    {4279,11543};
case_table(11544) ->
    {4280,11544};
case_table(11545) ->
    {4281,11545};
case_table(11546) ->
    {4282,11546};
case_table(11547) ->
    {4283,11547};
case_table(11548) ->
    {4284,11548};
case_table(11549) ->
    {4285,11549};
case_table(11550) ->
    {4286,11550};
case_table(11551) ->
    {4287,11551};
case_table(11552) ->
    {4288,11552};
case_table(11553) ->
    {4289,11553};
case_table(11554) ->
    {4290,11554};
case_table(11555) ->
    {4291,11555};
case_table(11556) ->
    {4292,11556};
case_table(11557) ->
    {4293,11557};
case_table(11559) ->
    {4295,11559};
case_table(11565) ->
    {4301,11565};
case_table(42560) ->
    {42560,42561};
case_table(42561) ->
    {42560,42561};
case_table(42562) ->
    {42562,42563};
case_table(42563) ->
    {42562,42563};
case_table(42564) ->
    {42564,42565};
case_table(42565) ->
    {42564,42565};
case_table(42566) ->
    {42566,42567};
case_table(42567) ->
    {42566,42567};
case_table(42568) ->
    {42568,42569};
case_table(42569) ->
    {42568,42569};
case_table(42570) ->
    {42570,42571};
case_table(42571) ->
    {42570,42571};
case_table(42572) ->
    {42572,42573};
case_table(42573) ->
    {42572,42573};
case_table(42574) ->
    {42574,42575};
case_table(42575) ->
    {42574,42575};
case_table(42576) ->
    {42576,42577};
case_table(42577) ->
    {42576,42577};
case_table(42578) ->
    {42578,42579};
case_table(42579) ->
    {42578,42579};
case_table(42580) ->
    {42580,42581};
case_table(42581) ->
    {42580,42581};
case_table(42582) ->
    {42582,42583};
case_table(42583) ->
    {42582,42583};
case_table(42584) ->
    {42584,42585};
case_table(42585) ->
    {42584,42585};
case_table(42586) ->
    {42586,42587};
case_table(42587) ->
    {42586,42587};
case_table(42588) ->
    {42588,42589};
case_table(42589) ->
    {42588,42589};
case_table(42590) ->
    {42590,42591};
case_table(42591) ->
    {42590,42591};
case_table(42592) ->
    {42592,42593};
case_table(42593) ->
    {42592,42593};
case_table(42594) ->
    {42594,42595};
case_table(42595) ->
    {42594,42595};
case_table(42596) ->
    {42596,42597};
case_table(42597) ->
    {42596,42597};
case_table(42598) ->
    {42598,42599};
case_table(42599) ->
    {42598,42599};
case_table(42600) ->
    {42600,42601};
case_table(42601) ->
    {42600,42601};
case_table(42602) ->
    {42602,42603};
case_table(42603) ->
    {42602,42603};
case_table(42604) ->
    {42604,42605};
case_table(42605) ->
    {42604,42605};
case_table(42624) ->
    {42624,42625};
case_table(42625) ->
    {42624,42625};
case_table(42626) ->
    {42626,42627};
case_table(42627) ->
    {42626,42627};
case_table(42628) ->
    {42628,42629};
case_table(42629) ->
    {42628,42629};
case_table(42630) ->
    {42630,42631};
case_table(42631) ->
    {42630,42631};
case_table(42632) ->
    {42632,42633};
case_table(42633) ->
    {42632,42633};
case_table(42634) ->
    {42634,42635};
case_table(42635) ->
    {42634,42635};
case_table(42636) ->
    {42636,42637};
case_table(42637) ->
    {42636,42637};
case_table(42638) ->
    {42638,42639};
case_table(42639) ->
    {42638,42639};
case_table(42640) ->
    {42640,42641};
case_table(42641) ->
    {42640,42641};
case_table(42642) ->
    {42642,42643};
case_table(42643) ->
    {42642,42643};
case_table(42644) ->
    {42644,42645};
case_table(42645) ->
    {42644,42645};
case_table(42646) ->
    {42646,42647};
case_table(42647) ->
    {42646,42647};
case_table(42648) ->
    {42648,42649};
case_table(42649) ->
    {42648,42649};
case_table(42650) ->
    {42650,42651};
case_table(42651) ->
    {42650,42651};
case_table(42786) ->
    {42786,42787};
case_table(42787) ->
    {42786,42787};
case_table(42788) ->
    {42788,42789};
case_table(42789) ->
    {42788,42789};
case_table(42790) ->
    {42790,42791};
case_table(42791) ->
    {42790,42791};
case_table(42792) ->
    {42792,42793};
case_table(42793) ->
    {42792,42793};
case_table(42794) ->
    {42794,42795};
case_table(42795) ->
    {42794,42795};
case_table(42796) ->
    {42796,42797};
case_table(42797) ->
    {42796,42797};
case_table(42798) ->
    {42798,42799};
case_table(42799) ->
    {42798,42799};
case_table(42802) ->
    {42802,42803};
case_table(42803) ->
    {42802,42803};
case_table(42804) ->
    {42804,42805};
case_table(42805) ->
    {42804,42805};
case_table(42806) ->
    {42806,42807};
case_table(42807) ->
    {42806,42807};
case_table(42808) ->
    {42808,42809};
case_table(42809) ->
    {42808,42809};
case_table(42810) ->
    {42810,42811};
case_table(42811) ->
    {42810,42811};
case_table(42812) ->
    {42812,42813};
case_table(42813) ->
    {42812,42813};
case_table(42814) ->
    {42814,42815};
case_table(42815) ->
    {42814,42815};
case_table(42816) ->
    {42816,42817};
case_table(42817) ->
    {42816,42817};
case_table(42818) ->
    {42818,42819};
case_table(42819) ->
    {42818,42819};
case_table(42820) ->
    {42820,42821};
case_table(42821) ->
    {42820,42821};
case_table(42822) ->
    {42822,42823};
case_table(42823) ->
    {42822,42823};
case_table(42824) ->
    {42824,42825};
case_table(42825) ->
    {42824,42825};
case_table(42826) ->
    {42826,42827};
case_table(42827) ->
    {42826,42827};
case_table(42828) ->
    {42828,42829};
case_table(42829) ->
    {42828,42829};
case_table(42830) ->
    {42830,42831};
case_table(42831) ->
    {42830,42831};
case_table(42832) ->
    {42832,42833};
case_table(42833) ->
    {42832,42833};
case_table(42834) ->
    {42834,42835};
case_table(42835) ->
    {42834,42835};
case_table(42836) ->
    {42836,42837};
case_table(42837) ->
    {42836,42837};
case_table(42838) ->
    {42838,42839};
case_table(42839) ->
    {42838,42839};
case_table(42840) ->
    {42840,42841};
case_table(42841) ->
    {42840,42841};
case_table(42842) ->
    {42842,42843};
case_table(42843) ->
    {42842,42843};
case_table(42844) ->
    {42844,42845};
case_table(42845) ->
    {42844,42845};
case_table(42846) ->
    {42846,42847};
case_table(42847) ->
    {42846,42847};
case_table(42848) ->
    {42848,42849};
case_table(42849) ->
    {42848,42849};
case_table(42850) ->
    {42850,42851};
case_table(42851) ->
    {42850,42851};
case_table(42852) ->
    {42852,42853};
case_table(42853) ->
    {42852,42853};
case_table(42854) ->
    {42854,42855};
case_table(42855) ->
    {42854,42855};
case_table(42856) ->
    {42856,42857};
case_table(42857) ->
    {42856,42857};
case_table(42858) ->
    {42858,42859};
case_table(42859) ->
    {42858,42859};
case_table(42860) ->
    {42860,42861};
case_table(42861) ->
    {42860,42861};
case_table(42862) ->
    {42862,42863};
case_table(42863) ->
    {42862,42863};
case_table(42873) ->
    {42873,42874};
case_table(42874) ->
    {42873,42874};
case_table(42875) ->
    {42875,42876};
case_table(42876) ->
    {42875,42876};
case_table(42877) ->
    {42877,7545};
case_table(42878) ->
    {42878,42879};
case_table(42879) ->
    {42878,42879};
case_table(42880) ->
    {42880,42881};
case_table(42881) ->
    {42880,42881};
case_table(42882) ->
    {42882,42883};
case_table(42883) ->
    {42882,42883};
case_table(42884) ->
    {42884,42885};
case_table(42885) ->
    {42884,42885};
case_table(42886) ->
    {42886,42887};
case_table(42887) ->
    {42886,42887};
case_table(42891) ->
    {42891,42892};
case_table(42892) ->
    {42891,42892};
case_table(42893) ->
    {42893,613};
case_table(42896) ->
    {42896,42897};
case_table(42897) ->
    {42896,42897};
case_table(42898) ->
    {42898,42899};
case_table(42899) ->
    {42898,42899};
case_table(42900) ->
    {42948,42900};
case_table(42902) ->
    {42902,42903};
case_table(42903) ->
    {42902,42903};
case_table(42904) ->
    {42904,42905};
case_table(42905) ->
    {42904,42905};
case_table(42906) ->
    {42906,42907};
case_table(42907) ->
    {42906,42907};
case_table(42908) ->
    {42908,42909};
case_table(42909) ->
    {42908,42909};
case_table(42910) ->
    {42910,42911};
case_table(42911) ->
    {42910,42911};
case_table(42912) ->
    {42912,42913};
case_table(42913) ->
    {42912,42913};
case_table(42914) ->
    {42914,42915};
case_table(42915) ->
    {42914,42915};
case_table(42916) ->
    {42916,42917};
case_table(42917) ->
    {42916,42917};
case_table(42918) ->
    {42918,42919};
case_table(42919) ->
    {42918,42919};
case_table(42920) ->
    {42920,42921};
case_table(42921) ->
    {42920,42921};
case_table(42922) ->
    {42922,614};
case_table(42923) ->
    {42923,604};
case_table(42924) ->
    {42924,609};
case_table(42925) ->
    {42925,620};
case_table(42926) ->
    {42926,618};
case_table(42928) ->
    {42928,670};
case_table(42929) ->
    {42929,647};
case_table(42930) ->
    {42930,669};
case_table(42931) ->
    {42931,43859};
case_table(42932) ->
    {42932,42933};
case_table(42933) ->
    {42932,42933};
case_table(42934) ->
    {42934,42935};
case_table(42935) ->
    {42934,42935};
case_table(42936) ->
    {42936,42937};
case_table(42937) ->
    {42936,42937};
case_table(42938) ->
    {42938,42939};
case_table(42939) ->
    {42938,42939};
case_table(42940) ->
    {42940,42941};
case_table(42941) ->
    {42940,42941};
case_table(42942) ->
    {42942,42943};
case_table(42943) ->
    {42942,42943};
case_table(42946) ->
    {42946,42947};
case_table(42947) ->
    {42946,42947};
case_table(42948) ->
    {42948,42900};
case_table(42949) ->
    {42949,642};
case_table(42950) ->
    {42950,7566};
case_table(43859) ->
    {42931,43859};
case_table(43888) ->
    {5024,43888,5024,5024};
case_table(43889) ->
    {5025,43889,5025,5025};
case_table(43890) ->
    {5026,43890,5026,5026};
case_table(43891) ->
    {5027,43891,5027,5027};
case_table(43892) ->
    {5028,43892,5028,5028};
case_table(43893) ->
    {5029,43893,5029,5029};
case_table(43894) ->
    {5030,43894,5030,5030};
case_table(43895) ->
    {5031,43895,5031,5031};
case_table(43896) ->
    {5032,43896,5032,5032};
case_table(43897) ->
    {5033,43897,5033,5033};
case_table(43898) ->
    {5034,43898,5034,5034};
case_table(43899) ->
    {5035,43899,5035,5035};
case_table(43900) ->
    {5036,43900,5036,5036};
case_table(43901) ->
    {5037,43901,5037,5037};
case_table(43902) ->
    {5038,43902,5038,5038};
case_table(43903) ->
    {5039,43903,5039,5039};
case_table(43904) ->
    {5040,43904,5040,5040};
case_table(43905) ->
    {5041,43905,5041,5041};
case_table(43906) ->
    {5042,43906,5042,5042};
case_table(43907) ->
    {5043,43907,5043,5043};
case_table(43908) ->
    {5044,43908,5044,5044};
case_table(43909) ->
    {5045,43909,5045,5045};
case_table(43910) ->
    {5046,43910,5046,5046};
case_table(43911) ->
    {5047,43911,5047,5047};
case_table(43912) ->
    {5048,43912,5048,5048};
case_table(43913) ->
    {5049,43913,5049,5049};
case_table(43914) ->
    {5050,43914,5050,5050};
case_table(43915) ->
    {5051,43915,5051,5051};
case_table(43916) ->
    {5052,43916,5052,5052};
case_table(43917) ->
    {5053,43917,5053,5053};
case_table(43918) ->
    {5054,43918,5054,5054};
case_table(43919) ->
    {5055,43919,5055,5055};
case_table(43920) ->
    {5056,43920,5056,5056};
case_table(43921) ->
    {5057,43921,5057,5057};
case_table(43922) ->
    {5058,43922,5058,5058};
case_table(43923) ->
    {5059,43923,5059,5059};
case_table(43924) ->
    {5060,43924,5060,5060};
case_table(43925) ->
    {5061,43925,5061,5061};
case_table(43926) ->
    {5062,43926,5062,5062};
case_table(43927) ->
    {5063,43927,5063,5063};
case_table(43928) ->
    {5064,43928,5064,5064};
case_table(43929) ->
    {5065,43929,5065,5065};
case_table(43930) ->
    {5066,43930,5066,5066};
case_table(43931) ->
    {5067,43931,5067,5067};
case_table(43932) ->
    {5068,43932,5068,5068};
case_table(43933) ->
    {5069,43933,5069,5069};
case_table(43934) ->
    {5070,43934,5070,5070};
case_table(43935) ->
    {5071,43935,5071,5071};
case_table(43936) ->
    {5072,43936,5072,5072};
case_table(43937) ->
    {5073,43937,5073,5073};
case_table(43938) ->
    {5074,43938,5074,5074};
case_table(43939) ->
    {5075,43939,5075,5075};
case_table(43940) ->
    {5076,43940,5076,5076};
case_table(43941) ->
    {5077,43941,5077,5077};
case_table(43942) ->
    {5078,43942,5078,5078};
case_table(43943) ->
    {5079,43943,5079,5079};
case_table(43944) ->
    {5080,43944,5080,5080};
case_table(43945) ->
    {5081,43945,5081,5081};
case_table(43946) ->
    {5082,43946,5082,5082};
case_table(43947) ->
    {5083,43947,5083,5083};
case_table(43948) ->
    {5084,43948,5084,5084};
case_table(43949) ->
    {5085,43949,5085,5085};
case_table(43950) ->
    {5086,43950,5086,5086};
case_table(43951) ->
    {5087,43951,5087,5087};
case_table(43952) ->
    {5088,43952,5088,5088};
case_table(43953) ->
    {5089,43953,5089,5089};
case_table(43954) ->
    {5090,43954,5090,5090};
case_table(43955) ->
    {5091,43955,5091,5091};
case_table(43956) ->
    {5092,43956,5092,5092};
case_table(43957) ->
    {5093,43957,5093,5093};
case_table(43958) ->
    {5094,43958,5094,5094};
case_table(43959) ->
    {5095,43959,5095,5095};
case_table(43960) ->
    {5096,43960,5096,5096};
case_table(43961) ->
    {5097,43961,5097,5097};
case_table(43962) ->
    {5098,43962,5098,5098};
case_table(43963) ->
    {5099,43963,5099,5099};
case_table(43964) ->
    {5100,43964,5100,5100};
case_table(43965) ->
    {5101,43965,5101,5101};
case_table(43966) ->
    {5102,43966,5102,5102};
case_table(43967) ->
    {5103,43967,5103,5103};
case_table(64256) ->
    {[70, 70],64256,[70, 102],[102, 102]};
case_table(64257) ->
    {[70, 73],64257,[70, 105],[102, 105]};
case_table(64258) ->
    {[70, 76],64258,[70, 108],[102, 108]};
case_table(64259) ->
    {[70, 70, 73],64259,[70, 102, 105],[102, 102, 105]};
case_table(64260) ->
    {[70, 70, 76],64260,[70, 102, 108],[102, 102, 108]};
case_table(64261) ->
    {[83, 84],64261,[83, 116],[115, 116]};
case_table(64262) ->
    {[83, 84],64262,[83, 116],[115, 116]};
case_table(64275) ->
    {[1348, 1350],64275,[1348, 1398],[1396, 1398]};
case_table(64276) ->
    {[1348, 1333],64276,[1348, 1381],[1396, 1381]};
case_table(64277) ->
    {[1348, 1339],64277,[1348, 1387],[1396, 1387]};
case_table(64278) ->
    {[1358, 1350],64278,[1358, 1398],[1406, 1398]};
case_table(64279) ->
    {[1348, 1341],64279,[1348, 1389],[1396, 1389]};
case_table(65313) ->
    {65313,65345};
case_table(65314) ->
    {65314,65346};
case_table(65315) ->
    {65315,65347};
case_table(65316) ->
    {65316,65348};
case_table(65317) ->
    {65317,65349};
case_table(65318) ->
    {65318,65350};
case_table(65319) ->
    {65319,65351};
case_table(65320) ->
    {65320,65352};
case_table(65321) ->
    {65321,65353};
case_table(65322) ->
    {65322,65354};
case_table(65323) ->
    {65323,65355};
case_table(65324) ->
    {65324,65356};
case_table(65325) ->
    {65325,65357};
case_table(65326) ->
    {65326,65358};
case_table(65327) ->
    {65327,65359};
case_table(65328) ->
    {65328,65360};
case_table(65329) ->
    {65329,65361};
case_table(65330) ->
    {65330,65362};
case_table(65331) ->
    {65331,65363};
case_table(65332) ->
    {65332,65364};
case_table(65333) ->
    {65333,65365};
case_table(65334) ->
    {65334,65366};
case_table(65335) ->
    {65335,65367};
case_table(65336) ->
    {65336,65368};
case_table(65337) ->
    {65337,65369};
case_table(65338) ->
    {65338,65370};
case_table(65345) ->
    {65313,65345};
case_table(65346) ->
    {65314,65346};
case_table(65347) ->
    {65315,65347};
case_table(65348) ->
    {65316,65348};
case_table(65349) ->
    {65317,65349};
case_table(65350) ->
    {65318,65350};
case_table(65351) ->
    {65319,65351};
case_table(65352) ->
    {65320,65352};
case_table(65353) ->
    {65321,65353};
case_table(65354) ->
    {65322,65354};
case_table(65355) ->
    {65323,65355};
case_table(65356) ->
    {65324,65356};
case_table(65357) ->
    {65325,65357};
case_table(65358) ->
    {65326,65358};
case_table(65359) ->
    {65327,65359};
case_table(65360) ->
    {65328,65360};
case_table(65361) ->
    {65329,65361};
case_table(65362) ->
    {65330,65362};
case_table(65363) ->
    {65331,65363};
case_table(65364) ->
    {65332,65364};
case_table(65365) ->
    {65333,65365};
case_table(65366) ->
    {65334,65366};
case_table(65367) ->
    {65335,65367};
case_table(65368) ->
    {65336,65368};
case_table(65369) ->
    {65337,65369};
case_table(65370) ->
    {65338,65370};
case_table(66560) ->
    {66560,66600};
case_table(66561) ->
    {66561,66601};
case_table(66562) ->
    {66562,66602};
case_table(66563) ->
    {66563,66603};
case_table(66564) ->
    {66564,66604};
case_table(66565) ->
    {66565,66605};
case_table(66566) ->
    {66566,66606};
case_table(66567) ->
    {66567,66607};
case_table(66568) ->
    {66568,66608};
case_table(66569) ->
    {66569,66609};
case_table(66570) ->
    {66570,66610};
case_table(66571) ->
    {66571,66611};
case_table(66572) ->
    {66572,66612};
case_table(66573) ->
    {66573,66613};
case_table(66574) ->
    {66574,66614};
case_table(66575) ->
    {66575,66615};
case_table(66576) ->
    {66576,66616};
case_table(66577) ->
    {66577,66617};
case_table(66578) ->
    {66578,66618};
case_table(66579) ->
    {66579,66619};
case_table(66580) ->
    {66580,66620};
case_table(66581) ->
    {66581,66621};
case_table(66582) ->
    {66582,66622};
case_table(66583) ->
    {66583,66623};
case_table(66584) ->
    {66584,66624};
case_table(66585) ->
    {66585,66625};
case_table(66586) ->
    {66586,66626};
case_table(66587) ->
    {66587,66627};
case_table(66588) ->
    {66588,66628};
case_table(66589) ->
    {66589,66629};
case_table(66590) ->
    {66590,66630};
case_table(66591) ->
    {66591,66631};
case_table(66592) ->
    {66592,66632};
case_table(66593) ->
    {66593,66633};
case_table(66594) ->
    {66594,66634};
case_table(66595) ->
    {66595,66635};
case_table(66596) ->
    {66596,66636};
case_table(66597) ->
    {66597,66637};
case_table(66598) ->
    {66598,66638};
case_table(66599) ->
    {66599,66639};
case_table(66600) ->
    {66560,66600};
case_table(66601) ->
    {66561,66601};
case_table(66602) ->
    {66562,66602};
case_table(66603) ->
    {66563,66603};
case_table(66604) ->
    {66564,66604};
case_table(66605) ->
    {66565,66605};
case_table(66606) ->
    {66566,66606};
case_table(66607) ->
    {66567,66607};
case_table(66608) ->
    {66568,66608};
case_table(66609) ->
    {66569,66609};
case_table(66610) ->
    {66570,66610};
case_table(66611) ->
    {66571,66611};
case_table(66612) ->
    {66572,66612};
case_table(66613) ->
    {66573,66613};
case_table(66614) ->
    {66574,66614};
case_table(66615) ->
    {66575,66615};
case_table(66616) ->
    {66576,66616};
case_table(66617) ->
    {66577,66617};
case_table(66618) ->
    {66578,66618};
case_table(66619) ->
    {66579,66619};
case_table(66620) ->
    {66580,66620};
case_table(66621) ->
    {66581,66621};
case_table(66622) ->
    {66582,66622};
case_table(66623) ->
    {66583,66623};
case_table(66624) ->
    {66584,66624};
case_table(66625) ->
    {66585,66625};
case_table(66626) ->
    {66586,66626};
case_table(66627) ->
    {66587,66627};
case_table(66628) ->
    {66588,66628};
case_table(66629) ->
    {66589,66629};
case_table(66630) ->
    {66590,66630};
case_table(66631) ->
    {66591,66631};
case_table(66632) ->
    {66592,66632};
case_table(66633) ->
    {66593,66633};
case_table(66634) ->
    {66594,66634};
case_table(66635) ->
    {66595,66635};
case_table(66636) ->
    {66596,66636};
case_table(66637) ->
    {66597,66637};
case_table(66638) ->
    {66598,66638};
case_table(66639) ->
    {66599,66639};
case_table(66736) ->
    {66736,66776};
case_table(66737) ->
    {66737,66777};
case_table(66738) ->
    {66738,66778};
case_table(66739) ->
    {66739,66779};
case_table(66740) ->
    {66740,66780};
case_table(66741) ->
    {66741,66781};
case_table(66742) ->
    {66742,66782};
case_table(66743) ->
    {66743,66783};
case_table(66744) ->
    {66744,66784};
case_table(66745) ->
    {66745,66785};
case_table(66746) ->
    {66746,66786};
case_table(66747) ->
    {66747,66787};
case_table(66748) ->
    {66748,66788};
case_table(66749) ->
    {66749,66789};
case_table(66750) ->
    {66750,66790};
case_table(66751) ->
    {66751,66791};
case_table(66752) ->
    {66752,66792};
case_table(66753) ->
    {66753,66793};
case_table(66754) ->
    {66754,66794};
case_table(66755) ->
    {66755,66795};
case_table(66756) ->
    {66756,66796};
case_table(66757) ->
    {66757,66797};
case_table(66758) ->
    {66758,66798};
case_table(66759) ->
    {66759,66799};
case_table(66760) ->
    {66760,66800};
case_table(66761) ->
    {66761,66801};
case_table(66762) ->
    {66762,66802};
case_table(66763) ->
    {66763,66803};
case_table(66764) ->
    {66764,66804};
case_table(66765) ->
    {66765,66805};
case_table(66766) ->
    {66766,66806};
case_table(66767) ->
    {66767,66807};
case_table(66768) ->
    {66768,66808};
case_table(66769) ->
    {66769,66809};
case_table(66770) ->
    {66770,66810};
case_table(66771) ->
    {66771,66811};
case_table(66776) ->
    {66736,66776};
case_table(66777) ->
    {66737,66777};
case_table(66778) ->
    {66738,66778};
case_table(66779) ->
    {66739,66779};
case_table(66780) ->
    {66740,66780};
case_table(66781) ->
    {66741,66781};
case_table(66782) ->
    {66742,66782};
case_table(66783) ->
    {66743,66783};
case_table(66784) ->
    {66744,66784};
case_table(66785) ->
    {66745,66785};
case_table(66786) ->
    {66746,66786};
case_table(66787) ->
    {66747,66787};
case_table(66788) ->
    {66748,66788};
case_table(66789) ->
    {66749,66789};
case_table(66790) ->
    {66750,66790};
case_table(66791) ->
    {66751,66791};
case_table(66792) ->
    {66752,66792};
case_table(66793) ->
    {66753,66793};
case_table(66794) ->
    {66754,66794};
case_table(66795) ->
    {66755,66795};
case_table(66796) ->
    {66756,66796};
case_table(66797) ->
    {66757,66797};
case_table(66798) ->
    {66758,66798};
case_table(66799) ->
    {66759,66799};
case_table(66800) ->
    {66760,66800};
case_table(66801) ->
    {66761,66801};
case_table(66802) ->
    {66762,66802};
case_table(66803) ->
    {66763,66803};
case_table(66804) ->
    {66764,66804};
case_table(66805) ->
    {66765,66805};
case_table(66806) ->
    {66766,66806};
case_table(66807) ->
    {66767,66807};
case_table(66808) ->
    {66768,66808};
case_table(66809) ->
    {66769,66809};
case_table(66810) ->
    {66770,66810};
case_table(66811) ->
    {66771,66811};
case_table(68736) ->
    {68736,68800};
case_table(68737) ->
    {68737,68801};
case_table(68738) ->
    {68738,68802};
case_table(68739) ->
    {68739,68803};
case_table(68740) ->
    {68740,68804};
case_table(68741) ->
    {68741,68805};
case_table(68742) ->
    {68742,68806};
case_table(68743) ->
    {68743,68807};
case_table(68744) ->
    {68744,68808};
case_table(68745) ->
    {68745,68809};
case_table(68746) ->
    {68746,68810};
case_table(68747) ->
    {68747,68811};
case_table(68748) ->
    {68748,68812};
case_table(68749) ->
    {68749,68813};
case_table(68750) ->
    {68750,68814};
case_table(68751) ->
    {68751,68815};
case_table(68752) ->
    {68752,68816};
case_table(68753) ->
    {68753,68817};
case_table(68754) ->
    {68754,68818};
case_table(68755) ->
    {68755,68819};
case_table(68756) ->
    {68756,68820};
case_table(68757) ->
    {68757,68821};
case_table(68758) ->
    {68758,68822};
case_table(68759) ->
    {68759,68823};
case_table(68760) ->
    {68760,68824};
case_table(68761) ->
    {68761,68825};
case_table(68762) ->
    {68762,68826};
case_table(68763) ->
    {68763,68827};
case_table(68764) ->
    {68764,68828};
case_table(68765) ->
    {68765,68829};
case_table(68766) ->
    {68766,68830};
case_table(68767) ->
    {68767,68831};
case_table(68768) ->
    {68768,68832};
case_table(68769) ->
    {68769,68833};
case_table(68770) ->
    {68770,68834};
case_table(68771) ->
    {68771,68835};
case_table(68772) ->
    {68772,68836};
case_table(68773) ->
    {68773,68837};
case_table(68774) ->
    {68774,68838};
case_table(68775) ->
    {68775,68839};
case_table(68776) ->
    {68776,68840};
case_table(68777) ->
    {68777,68841};
case_table(68778) ->
    {68778,68842};
case_table(68779) ->
    {68779,68843};
case_table(68780) ->
    {68780,68844};
case_table(68781) ->
    {68781,68845};
case_table(68782) ->
    {68782,68846};
case_table(68783) ->
    {68783,68847};
case_table(68784) ->
    {68784,68848};
case_table(68785) ->
    {68785,68849};
case_table(68786) ->
    {68786,68850};
case_table(68800) ->
    {68736,68800};
case_table(68801) ->
    {68737,68801};
case_table(68802) ->
    {68738,68802};
case_table(68803) ->
    {68739,68803};
case_table(68804) ->
    {68740,68804};
case_table(68805) ->
    {68741,68805};
case_table(68806) ->
    {68742,68806};
case_table(68807) ->
    {68743,68807};
case_table(68808) ->
    {68744,68808};
case_table(68809) ->
    {68745,68809};
case_table(68810) ->
    {68746,68810};
case_table(68811) ->
    {68747,68811};
case_table(68812) ->
    {68748,68812};
case_table(68813) ->
    {68749,68813};
case_table(68814) ->
    {68750,68814};
case_table(68815) ->
    {68751,68815};
case_table(68816) ->
    {68752,68816};
case_table(68817) ->
    {68753,68817};
case_table(68818) ->
    {68754,68818};
case_table(68819) ->
    {68755,68819};
case_table(68820) ->
    {68756,68820};
case_table(68821) ->
    {68757,68821};
case_table(68822) ->
    {68758,68822};
case_table(68823) ->
    {68759,68823};
case_table(68824) ->
    {68760,68824};
case_table(68825) ->
    {68761,68825};
case_table(68826) ->
    {68762,68826};
case_table(68827) ->
    {68763,68827};
case_table(68828) ->
    {68764,68828};
case_table(68829) ->
    {68765,68829};
case_table(68830) ->
    {68766,68830};
case_table(68831) ->
    {68767,68831};
case_table(68832) ->
    {68768,68832};
case_table(68833) ->
    {68769,68833};
case_table(68834) ->
    {68770,68834};
case_table(68835) ->
    {68771,68835};
case_table(68836) ->
    {68772,68836};
case_table(68837) ->
    {68773,68837};
case_table(68838) ->
    {68774,68838};
case_table(68839) ->
    {68775,68839};
case_table(68840) ->
    {68776,68840};
case_table(68841) ->
    {68777,68841};
case_table(68842) ->
    {68778,68842};
case_table(68843) ->
    {68779,68843};
case_table(68844) ->
    {68780,68844};
case_table(68845) ->
    {68781,68845};
case_table(68846) ->
    {68782,68846};
case_table(68847) ->
    {68783,68847};
case_table(68848) ->
    {68784,68848};
case_table(68849) ->
    {68785,68849};
case_table(68850) ->
    {68786,68850};
case_table(71840) ->
    {71840,71872};
case_table(71841) ->
    {71841,71873};
case_table(71842) ->
    {71842,71874};
case_table(71843) ->
    {71843,71875};
case_table(71844) ->
    {71844,71876};
case_table(71845) ->
    {71845,71877};
case_table(71846) ->
    {71846,71878};
case_table(71847) ->
    {71847,71879};
case_table(71848) ->
    {71848,71880};
case_table(71849) ->
    {71849,71881};
case_table(71850) ->
    {71850,71882};
case_table(71851) ->
    {71851,71883};
case_table(71852) ->
    {71852,71884};
case_table(71853) ->
    {71853,71885};
case_table(71854) ->
    {71854,71886};
case_table(71855) ->
    {71855,71887};
case_table(71856) ->
    {71856,71888};
case_table(71857) ->
    {71857,71889};
case_table(71858) ->
    {71858,71890};
case_table(71859) ->
    {71859,71891};
case_table(71860) ->
    {71860,71892};
case_table(71861) ->
    {71861,71893};
case_table(71862) ->
    {71862,71894};
case_table(71863) ->
    {71863,71895};
case_table(71864) ->
    {71864,71896};
case_table(71865) ->
    {71865,71897};
case_table(71866) ->
    {71866,71898};
case_table(71867) ->
    {71867,71899};
case_table(71868) ->
    {71868,71900};
case_table(71869) ->
    {71869,71901};
case_table(71870) ->
    {71870,71902};
case_table(71871) ->
    {71871,71903};
case_table(71872) ->
    {71840,71872};
case_table(71873) ->
    {71841,71873};
case_table(71874) ->
    {71842,71874};
case_table(71875) ->
    {71843,71875};
case_table(71876) ->
    {71844,71876};
case_table(71877) ->
    {71845,71877};
case_table(71878) ->
    {71846,71878};
case_table(71879) ->
    {71847,71879};
case_table(71880) ->
    {71848,71880};
case_table(71881) ->
    {71849,71881};
case_table(71882) ->
    {71850,71882};
case_table(71883) ->
    {71851,71883};
case_table(71884) ->
    {71852,71884};
case_table(71885) ->
    {71853,71885};
case_table(71886) ->
    {71854,71886};
case_table(71887) ->
    {71855,71887};
case_table(71888) ->
    {71856,71888};
case_table(71889) ->
    {71857,71889};
case_table(71890) ->
    {71858,71890};
case_table(71891) ->
    {71859,71891};
case_table(71892) ->
    {71860,71892};
case_table(71893) ->
    {71861,71893};
case_table(71894) ->
    {71862,71894};
case_table(71895) ->
    {71863,71895};
case_table(71896) ->
    {71864,71896};
case_table(71897) ->
    {71865,71897};
case_table(71898) ->
    {71866,71898};
case_table(71899) ->
    {71867,71899};
case_table(71900) ->
    {71868,71900};
case_table(71901) ->
    {71869,71901};
case_table(71902) ->
    {71870,71902};
case_table(71903) ->
    {71871,71903};
case_table(93760) ->
    {93760,93792};
case_table(93761) ->
    {93761,93793};
case_table(93762) ->
    {93762,93794};
case_table(93763) ->
    {93763,93795};
case_table(93764) ->
    {93764,93796};
case_table(93765) ->
    {93765,93797};
case_table(93766) ->
    {93766,93798};
case_table(93767) ->
    {93767,93799};
case_table(93768) ->
    {93768,93800};
case_table(93769) ->
    {93769,93801};
case_table(93770) ->
    {93770,93802};
case_table(93771) ->
    {93771,93803};
case_table(93772) ->
    {93772,93804};
case_table(93773) ->
    {93773,93805};
case_table(93774) ->
    {93774,93806};
case_table(93775) ->
    {93775,93807};
case_table(93776) ->
    {93776,93808};
case_table(93777) ->
    {93777,93809};
case_table(93778) ->
    {93778,93810};
case_table(93779) ->
    {93779,93811};
case_table(93780) ->
    {93780,93812};
case_table(93781) ->
    {93781,93813};
case_table(93782) ->
    {93782,93814};
case_table(93783) ->
    {93783,93815};
case_table(93784) ->
    {93784,93816};
case_table(93785) ->
    {93785,93817};
case_table(93786) ->
    {93786,93818};
case_table(93787) ->
    {93787,93819};
case_table(93788) ->
    {93788,93820};
case_table(93789) ->
    {93789,93821};
case_table(93790) ->
    {93790,93822};
case_table(93791) ->
    {93791,93823};
case_table(93792) ->
    {93760,93792};
case_table(93793) ->
    {93761,93793};
case_table(93794) ->
    {93762,93794};
case_table(93795) ->
    {93763,93795};
case_table(93796) ->
    {93764,93796};
case_table(93797) ->
    {93765,93797};
case_table(93798) ->
    {93766,93798};
case_table(93799) ->
    {93767,93799};
case_table(93800) ->
    {93768,93800};
case_table(93801) ->
    {93769,93801};
case_table(93802) ->
    {93770,93802};
case_table(93803) ->
    {93771,93803};
case_table(93804) ->
    {93772,93804};
case_table(93805) ->
    {93773,93805};
case_table(93806) ->
    {93774,93806};
case_table(93807) ->
    {93775,93807};
case_table(93808) ->
    {93776,93808};
case_table(93809) ->
    {93777,93809};
case_table(93810) ->
    {93778,93810};
case_table(93811) ->
    {93779,93811};
case_table(93812) ->
    {93780,93812};
case_table(93813) ->
    {93781,93813};
case_table(93814) ->
    {93782,93814};
case_table(93815) ->
    {93783,93815};
case_table(93816) ->
    {93784,93816};
case_table(93817) ->
    {93785,93817};
case_table(93818) ->
    {93786,93818};
case_table(93819) ->
    {93787,93819};
case_table(93820) ->
    {93788,93820};
case_table(93821) ->
    {93789,93821};
case_table(93822) ->
    {93790,93822};
case_table(93823) ->
    {93791,93823};
case_table(125184) ->
    {125184,125218};
case_table(125185) ->
    {125185,125219};
case_table(125186) ->
    {125186,125220};
case_table(125187) ->
    {125187,125221};
case_table(125188) ->
    {125188,125222};
case_table(125189) ->
    {125189,125223};
case_table(125190) ->
    {125190,125224};
case_table(125191) ->
    {125191,125225};
case_table(125192) ->
    {125192,125226};
case_table(125193) ->
    {125193,125227};
case_table(125194) ->
    {125194,125228};
case_table(125195) ->
    {125195,125229};
case_table(125196) ->
    {125196,125230};
case_table(125197) ->
    {125197,125231};
case_table(125198) ->
    {125198,125232};
case_table(125199) ->
    {125199,125233};
case_table(125200) ->
    {125200,125234};
case_table(125201) ->
    {125201,125235};
case_table(125202) ->
    {125202,125236};
case_table(125203) ->
    {125203,125237};
case_table(125204) ->
    {125204,125238};
case_table(125205) ->
    {125205,125239};
case_table(125206) ->
    {125206,125240};
case_table(125207) ->
    {125207,125241};
case_table(125208) ->
    {125208,125242};
case_table(125209) ->
    {125209,125243};
case_table(125210) ->
    {125210,125244};
case_table(125211) ->
    {125211,125245};
case_table(125212) ->
    {125212,125246};
case_table(125213) ->
    {125213,125247};
case_table(125214) ->
    {125214,125248};
case_table(125215) ->
    {125215,125249};
case_table(125216) ->
    {125216,125250};
case_table(125217) ->
    {125217,125251};
case_table(125218) ->
    {125184,125218};
case_table(125219) ->
    {125185,125219};
case_table(125220) ->
    {125186,125220};
case_table(125221) ->
    {125187,125221};
case_table(125222) ->
    {125188,125222};
case_table(125223) ->
    {125189,125223};
case_table(125224) ->
    {125190,125224};
case_table(125225) ->
    {125191,125225};
case_table(125226) ->
    {125192,125226};
case_table(125227) ->
    {125193,125227};
case_table(125228) ->
    {125194,125228};
case_table(125229) ->
    {125195,125229};
case_table(125230) ->
    {125196,125230};
case_table(125231) ->
    {125197,125231};
case_table(125232) ->
    {125198,125232};
case_table(125233) ->
    {125199,125233};
case_table(125234) ->
    {125200,125234};
case_table(125235) ->
    {125201,125235};
case_table(125236) ->
    {125202,125236};
case_table(125237) ->
    {125203,125237};
case_table(125238) ->
    {125204,125238};
case_table(125239) ->
    {125205,125239};
case_table(125240) ->
    {125206,125240};
case_table(125241) ->
    {125207,125241};
case_table(125242) ->
    {125208,125242};
case_table(125243) ->
    {125209,125243};
case_table(125244) ->
    {125210,125244};
case_table(125245) ->
    {125211,125245};
case_table(125246) ->
    {125212,125246};
case_table(125247) ->
    {125213,125247};
case_table(125248) ->
    {125214,125248};
case_table(125249) ->
    {125215,125249};
case_table(125250) ->
    {125216,125250};
case_table(125251) ->
    {125217,125251};
case_table(CP) ->
    {CP,CP}.

unicode_table(160) ->
    {0,[],{noBreak,[{0,32}]}};
unicode_table(168) ->
    {0,[],{compat,[{0,32}, {230,776}]}};
unicode_table(170) ->
    {0,[],{super,[{0,97}]}};
unicode_table(175) ->
    {0,[],{compat,[{0,32}, {230,772}]}};
unicode_table(178) ->
    {0,[],{super,[{0,50}]}};
unicode_table(179) ->
    {0,[],{super,[{0,51}]}};
unicode_table(180) ->
    {0,[],{compat,[{0,32}, {230,769}]}};
unicode_table(181) ->
    {0,[],{compat,[{0,956}]}};
unicode_table(184) ->
    {0,[],{compat,[{0,32}, {202,807}]}};
unicode_table(185) ->
    {0,[],{super,[{0,49}]}};
unicode_table(186) ->
    {0,[],{super,[{0,111}]}};
unicode_table(188) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,52}]}};
unicode_table(189) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,50}]}};
unicode_table(190) ->
    {0,[],{fraction,[{0,51}, {0,8260}, {0,52}]}};
unicode_table(192) ->
    {0,[{0,65}, {230,768}],[]};
unicode_table(193) ->
    {0,[{0,65}, {230,769}],[]};
unicode_table(194) ->
    {0,[{0,65}, {230,770}],[]};
unicode_table(195) ->
    {0,[{0,65}, {230,771}],[]};
unicode_table(196) ->
    {0,[{0,65}, {230,776}],[]};
unicode_table(197) ->
    {0,[{0,65}, {230,778}],[]};
unicode_table(199) ->
    {0,[{0,67}, {202,807}],[]};
unicode_table(200) ->
    {0,[{0,69}, {230,768}],[]};
unicode_table(201) ->
    {0,[{0,69}, {230,769}],[]};
unicode_table(202) ->
    {0,[{0,69}, {230,770}],[]};
unicode_table(203) ->
    {0,[{0,69}, {230,776}],[]};
unicode_table(204) ->
    {0,[{0,73}, {230,768}],[]};
unicode_table(205) ->
    {0,[{0,73}, {230,769}],[]};
unicode_table(206) ->
    {0,[{0,73}, {230,770}],[]};
unicode_table(207) ->
    {0,[{0,73}, {230,776}],[]};
unicode_table(209) ->
    {0,[{0,78}, {230,771}],[]};
unicode_table(210) ->
    {0,[{0,79}, {230,768}],[]};
unicode_table(211) ->
    {0,[{0,79}, {230,769}],[]};
unicode_table(212) ->
    {0,[{0,79}, {230,770}],[]};
unicode_table(213) ->
    {0,[{0,79}, {230,771}],[]};
unicode_table(214) ->
    {0,[{0,79}, {230,776}],[]};
unicode_table(217) ->
    {0,[{0,85}, {230,768}],[]};
unicode_table(218) ->
    {0,[{0,85}, {230,769}],[]};
unicode_table(219) ->
    {0,[{0,85}, {230,770}],[]};
unicode_table(220) ->
    {0,[{0,85}, {230,776}],[]};
unicode_table(221) ->
    {0,[{0,89}, {230,769}],[]};
unicode_table(224) ->
    {0,[{0,97}, {230,768}],[]};
unicode_table(225) ->
    {0,[{0,97}, {230,769}],[]};
unicode_table(226) ->
    {0,[{0,97}, {230,770}],[]};
unicode_table(227) ->
    {0,[{0,97}, {230,771}],[]};
unicode_table(228) ->
    {0,[{0,97}, {230,776}],[]};
unicode_table(229) ->
    {0,[{0,97}, {230,778}],[]};
unicode_table(231) ->
    {0,[{0,99}, {202,807}],[]};
unicode_table(232) ->
    {0,[{0,101}, {230,768}],[]};
unicode_table(233) ->
    {0,[{0,101}, {230,769}],[]};
unicode_table(234) ->
    {0,[{0,101}, {230,770}],[]};
unicode_table(235) ->
    {0,[{0,101}, {230,776}],[]};
unicode_table(236) ->
    {0,[{0,105}, {230,768}],[]};
unicode_table(237) ->
    {0,[{0,105}, {230,769}],[]};
unicode_table(238) ->
    {0,[{0,105}, {230,770}],[]};
unicode_table(239) ->
    {0,[{0,105}, {230,776}],[]};
unicode_table(241) ->
    {0,[{0,110}, {230,771}],[]};
unicode_table(242) ->
    {0,[{0,111}, {230,768}],[]};
unicode_table(243) ->
    {0,[{0,111}, {230,769}],[]};
unicode_table(244) ->
    {0,[{0,111}, {230,770}],[]};
unicode_table(245) ->
    {0,[{0,111}, {230,771}],[]};
unicode_table(246) ->
    {0,[{0,111}, {230,776}],[]};
unicode_table(249) ->
    {0,[{0,117}, {230,768}],[]};
unicode_table(250) ->
    {0,[{0,117}, {230,769}],[]};
unicode_table(251) ->
    {0,[{0,117}, {230,770}],[]};
unicode_table(252) ->
    {0,[{0,117}, {230,776}],[]};
unicode_table(253) ->
    {0,[{0,121}, {230,769}],[]};
unicode_table(255) ->
    {0,[{0,121}, {230,776}],[]};
unicode_table(256) ->
    {0,[{0,65}, {230,772}],[]};
unicode_table(257) ->
    {0,[{0,97}, {230,772}],[]};
unicode_table(258) ->
    {0,[{0,65}, {230,774}],[]};
unicode_table(259) ->
    {0,[{0,97}, {230,774}],[]};
unicode_table(260) ->
    {0,[{0,65}, {202,808}],[]};
unicode_table(261) ->
    {0,[{0,97}, {202,808}],[]};
unicode_table(262) ->
    {0,[{0,67}, {230,769}],[]};
unicode_table(263) ->
    {0,[{0,99}, {230,769}],[]};
unicode_table(264) ->
    {0,[{0,67}, {230,770}],[]};
unicode_table(265) ->
    {0,[{0,99}, {230,770}],[]};
unicode_table(266) ->
    {0,[{0,67}, {230,775}],[]};
unicode_table(267) ->
    {0,[{0,99}, {230,775}],[]};
unicode_table(268) ->
    {0,[{0,67}, {230,780}],[]};
unicode_table(269) ->
    {0,[{0,99}, {230,780}],[]};
unicode_table(270) ->
    {0,[{0,68}, {230,780}],[]};
unicode_table(271) ->
    {0,[{0,100}, {230,780}],[]};
unicode_table(274) ->
    {0,[{0,69}, {230,772}],[]};
unicode_table(275) ->
    {0,[{0,101}, {230,772}],[]};
unicode_table(276) ->
    {0,[{0,69}, {230,774}],[]};
unicode_table(277) ->
    {0,[{0,101}, {230,774}],[]};
unicode_table(278) ->
    {0,[{0,69}, {230,775}],[]};
unicode_table(279) ->
    {0,[{0,101}, {230,775}],[]};
unicode_table(280) ->
    {0,[{0,69}, {202,808}],[]};
unicode_table(281) ->
    {0,[{0,101}, {202,808}],[]};
unicode_table(282) ->
    {0,[{0,69}, {230,780}],[]};
unicode_table(283) ->
    {0,[{0,101}, {230,780}],[]};
unicode_table(284) ->
    {0,[{0,71}, {230,770}],[]};
unicode_table(285) ->
    {0,[{0,103}, {230,770}],[]};
unicode_table(286) ->
    {0,[{0,71}, {230,774}],[]};
unicode_table(287) ->
    {0,[{0,103}, {230,774}],[]};
unicode_table(288) ->
    {0,[{0,71}, {230,775}],[]};
unicode_table(289) ->
    {0,[{0,103}, {230,775}],[]};
unicode_table(290) ->
    {0,[{0,71}, {202,807}],[]};
unicode_table(291) ->
    {0,[{0,103}, {202,807}],[]};
unicode_table(292) ->
    {0,[{0,72}, {230,770}],[]};
unicode_table(293) ->
    {0,[{0,104}, {230,770}],[]};
unicode_table(296) ->
    {0,[{0,73}, {230,771}],[]};
unicode_table(297) ->
    {0,[{0,105}, {230,771}],[]};
unicode_table(298) ->
    {0,[{0,73}, {230,772}],[]};
unicode_table(299) ->
    {0,[{0,105}, {230,772}],[]};
unicode_table(300) ->
    {0,[{0,73}, {230,774}],[]};
unicode_table(301) ->
    {0,[{0,105}, {230,774}],[]};
unicode_table(302) ->
    {0,[{0,73}, {202,808}],[]};
unicode_table(303) ->
    {0,[{0,105}, {202,808}],[]};
unicode_table(304) ->
    {0,[{0,73}, {230,775}],[]};
unicode_table(306) ->
    {0,[],{compat,[{0,73}, {0,74}]}};
unicode_table(307) ->
    {0,[],{compat,[{0,105}, {0,106}]}};
unicode_table(308) ->
    {0,[{0,74}, {230,770}],[]};
unicode_table(309) ->
    {0,[{0,106}, {230,770}],[]};
unicode_table(310) ->
    {0,[{0,75}, {202,807}],[]};
unicode_table(311) ->
    {0,[{0,107}, {202,807}],[]};
unicode_table(313) ->
    {0,[{0,76}, {230,769}],[]};
unicode_table(314) ->
    {0,[{0,108}, {230,769}],[]};
unicode_table(315) ->
    {0,[{0,76}, {202,807}],[]};
unicode_table(316) ->
    {0,[{0,108}, {202,807}],[]};
unicode_table(317) ->
    {0,[{0,76}, {230,780}],[]};
unicode_table(318) ->
    {0,[{0,108}, {230,780}],[]};
unicode_table(319) ->
    {0,[],{compat,[{0,76}, {0,183}]}};
unicode_table(320) ->
    {0,[],{compat,[{0,108}, {0,183}]}};
unicode_table(323) ->
    {0,[{0,78}, {230,769}],[]};
unicode_table(324) ->
    {0,[{0,110}, {230,769}],[]};
unicode_table(325) ->
    {0,[{0,78}, {202,807}],[]};
unicode_table(326) ->
    {0,[{0,110}, {202,807}],[]};
unicode_table(327) ->
    {0,[{0,78}, {230,780}],[]};
unicode_table(328) ->
    {0,[{0,110}, {230,780}],[]};
unicode_table(329) ->
    {0,[],{compat,[{0,700}, {0,110}]}};
unicode_table(332) ->
    {0,[{0,79}, {230,772}],[]};
unicode_table(333) ->
    {0,[{0,111}, {230,772}],[]};
unicode_table(334) ->
    {0,[{0,79}, {230,774}],[]};
unicode_table(335) ->
    {0,[{0,111}, {230,774}],[]};
unicode_table(336) ->
    {0,[{0,79}, {230,779}],[]};
unicode_table(337) ->
    {0,[{0,111}, {230,779}],[]};
unicode_table(340) ->
    {0,[{0,82}, {230,769}],[]};
unicode_table(341) ->
    {0,[{0,114}, {230,769}],[]};
unicode_table(342) ->
    {0,[{0,82}, {202,807}],[]};
unicode_table(343) ->
    {0,[{0,114}, {202,807}],[]};
unicode_table(344) ->
    {0,[{0,82}, {230,780}],[]};
unicode_table(345) ->
    {0,[{0,114}, {230,780}],[]};
unicode_table(346) ->
    {0,[{0,83}, {230,769}],[]};
unicode_table(347) ->
    {0,[{0,115}, {230,769}],[]};
unicode_table(348) ->
    {0,[{0,83}, {230,770}],[]};
unicode_table(349) ->
    {0,[{0,115}, {230,770}],[]};
unicode_table(350) ->
    {0,[{0,83}, {202,807}],[]};
unicode_table(351) ->
    {0,[{0,115}, {202,807}],[]};
unicode_table(352) ->
    {0,[{0,83}, {230,780}],[]};
unicode_table(353) ->
    {0,[{0,115}, {230,780}],[]};
unicode_table(354) ->
    {0,[{0,84}, {202,807}],[]};
unicode_table(355) ->
    {0,[{0,116}, {202,807}],[]};
unicode_table(356) ->
    {0,[{0,84}, {230,780}],[]};
unicode_table(357) ->
    {0,[{0,116}, {230,780}],[]};
unicode_table(360) ->
    {0,[{0,85}, {230,771}],[]};
unicode_table(361) ->
    {0,[{0,117}, {230,771}],[]};
unicode_table(362) ->
    {0,[{0,85}, {230,772}],[]};
unicode_table(363) ->
    {0,[{0,117}, {230,772}],[]};
unicode_table(364) ->
    {0,[{0,85}, {230,774}],[]};
unicode_table(365) ->
    {0,[{0,117}, {230,774}],[]};
unicode_table(366) ->
    {0,[{0,85}, {230,778}],[]};
unicode_table(367) ->
    {0,[{0,117}, {230,778}],[]};
unicode_table(368) ->
    {0,[{0,85}, {230,779}],[]};
unicode_table(369) ->
    {0,[{0,117}, {230,779}],[]};
unicode_table(370) ->
    {0,[{0,85}, {202,808}],[]};
unicode_table(371) ->
    {0,[{0,117}, {202,808}],[]};
unicode_table(372) ->
    {0,[{0,87}, {230,770}],[]};
unicode_table(373) ->
    {0,[{0,119}, {230,770}],[]};
unicode_table(374) ->
    {0,[{0,89}, {230,770}],[]};
unicode_table(375) ->
    {0,[{0,121}, {230,770}],[]};
unicode_table(376) ->
    {0,[{0,89}, {230,776}],[]};
unicode_table(377) ->
    {0,[{0,90}, {230,769}],[]};
unicode_table(378) ->
    {0,[{0,122}, {230,769}],[]};
unicode_table(379) ->
    {0,[{0,90}, {230,775}],[]};
unicode_table(380) ->
    {0,[{0,122}, {230,775}],[]};
unicode_table(381) ->
    {0,[{0,90}, {230,780}],[]};
unicode_table(382) ->
    {0,[{0,122}, {230,780}],[]};
unicode_table(383) ->
    {0,[],{compat,[{0,115}]}};
unicode_table(416) ->
    {0,[{0,79}, {216,795}],[]};
unicode_table(417) ->
    {0,[{0,111}, {216,795}],[]};
unicode_table(431) ->
    {0,[{0,85}, {216,795}],[]};
unicode_table(432) ->
    {0,[{0,117}, {216,795}],[]};
unicode_table(452) ->
    {0,[],{compat,[{0,68}, {0,90}, {230,780}]}};
unicode_table(453) ->
    {0,[],{compat,[{0,68}, {0,122}, {230,780}]}};
unicode_table(454) ->
    {0,[],{compat,[{0,100}, {0,122}, {230,780}]}};
unicode_table(455) ->
    {0,[],{compat,[{0,76}, {0,74}]}};
unicode_table(456) ->
    {0,[],{compat,[{0,76}, {0,106}]}};
unicode_table(457) ->
    {0,[],{compat,[{0,108}, {0,106}]}};
unicode_table(458) ->
    {0,[],{compat,[{0,78}, {0,74}]}};
unicode_table(459) ->
    {0,[],{compat,[{0,78}, {0,106}]}};
unicode_table(460) ->
    {0,[],{compat,[{0,110}, {0,106}]}};
unicode_table(461) ->
    {0,[{0,65}, {230,780}],[]};
unicode_table(462) ->
    {0,[{0,97}, {230,780}],[]};
unicode_table(463) ->
    {0,[{0,73}, {230,780}],[]};
unicode_table(464) ->
    {0,[{0,105}, {230,780}],[]};
unicode_table(465) ->
    {0,[{0,79}, {230,780}],[]};
unicode_table(466) ->
    {0,[{0,111}, {230,780}],[]};
unicode_table(467) ->
    {0,[{0,85}, {230,780}],[]};
unicode_table(468) ->
    {0,[{0,117}, {230,780}],[]};
unicode_table(469) ->
    {0,[{0,85}, {230,776}, {230,772}],[]};
unicode_table(470) ->
    {0,[{0,117}, {230,776}, {230,772}],[]};
unicode_table(471) ->
    {0,[{0,85}, {230,776}, {230,769}],[]};
unicode_table(472) ->
    {0,[{0,117}, {230,776}, {230,769}],[]};
unicode_table(473) ->
    {0,[{0,85}, {230,776}, {230,780}],[]};
unicode_table(474) ->
    {0,[{0,117}, {230,776}, {230,780}],[]};
unicode_table(475) ->
    {0,[{0,85}, {230,776}, {230,768}],[]};
unicode_table(476) ->
    {0,[{0,117}, {230,776}, {230,768}],[]};
unicode_table(478) ->
    {0,[{0,65}, {230,776}, {230,772}],[]};
unicode_table(479) ->
    {0,[{0,97}, {230,776}, {230,772}],[]};
unicode_table(480) ->
    {0,[{0,65}, {230,775}, {230,772}],[]};
unicode_table(481) ->
    {0,[{0,97}, {230,775}, {230,772}],[]};
unicode_table(482) ->
    {0,[{0,198}, {230,772}],[]};
unicode_table(483) ->
    {0,[{0,230}, {230,772}],[]};
unicode_table(486) ->
    {0,[{0,71}, {230,780}],[]};
unicode_table(487) ->
    {0,[{0,103}, {230,780}],[]};
unicode_table(488) ->
    {0,[{0,75}, {230,780}],[]};
unicode_table(489) ->
    {0,[{0,107}, {230,780}],[]};
unicode_table(490) ->
    {0,[{0,79}, {202,808}],[]};
unicode_table(491) ->
    {0,[{0,111}, {202,808}],[]};
unicode_table(492) ->
    {0,[{0,79}, {202,808}, {230,772}],[]};
unicode_table(493) ->
    {0,[{0,111}, {202,808}, {230,772}],[]};
unicode_table(494) ->
    {0,[{0,439}, {230,780}],[]};
unicode_table(495) ->
    {0,[{0,658}, {230,780}],[]};
unicode_table(496) ->
    {0,[{0,106}, {230,780}],[]};
unicode_table(497) ->
    {0,[],{compat,[{0,68}, {0,90}]}};
unicode_table(498) ->
    {0,[],{compat,[{0,68}, {0,122}]}};
unicode_table(499) ->
    {0,[],{compat,[{0,100}, {0,122}]}};
unicode_table(500) ->
    {0,[{0,71}, {230,769}],[]};
unicode_table(501) ->
    {0,[{0,103}, {230,769}],[]};
unicode_table(504) ->
    {0,[{0,78}, {230,768}],[]};
unicode_table(505) ->
    {0,[{0,110}, {230,768}],[]};
unicode_table(506) ->
    {0,[{0,65}, {230,778}, {230,769}],[]};
unicode_table(507) ->
    {0,[{0,97}, {230,778}, {230,769}],[]};
unicode_table(508) ->
    {0,[{0,198}, {230,769}],[]};
unicode_table(509) ->
    {0,[{0,230}, {230,769}],[]};
unicode_table(510) ->
    {0,[{0,216}, {230,769}],[]};
unicode_table(511) ->
    {0,[{0,248}, {230,769}],[]};
unicode_table(512) ->
    {0,[{0,65}, {230,783}],[]};
unicode_table(513) ->
    {0,[{0,97}, {230,783}],[]};
unicode_table(514) ->
    {0,[{0,65}, {230,785}],[]};
unicode_table(515) ->
    {0,[{0,97}, {230,785}],[]};
unicode_table(516) ->
    {0,[{0,69}, {230,783}],[]};
unicode_table(517) ->
    {0,[{0,101}, {230,783}],[]};
unicode_table(518) ->
    {0,[{0,69}, {230,785}],[]};
unicode_table(519) ->
    {0,[{0,101}, {230,785}],[]};
unicode_table(520) ->
    {0,[{0,73}, {230,783}],[]};
unicode_table(521) ->
    {0,[{0,105}, {230,783}],[]};
unicode_table(522) ->
    {0,[{0,73}, {230,785}],[]};
unicode_table(523) ->
    {0,[{0,105}, {230,785}],[]};
unicode_table(524) ->
    {0,[{0,79}, {230,783}],[]};
unicode_table(525) ->
    {0,[{0,111}, {230,783}],[]};
unicode_table(526) ->
    {0,[{0,79}, {230,785}],[]};
unicode_table(527) ->
    {0,[{0,111}, {230,785}],[]};
unicode_table(528) ->
    {0,[{0,82}, {230,783}],[]};
unicode_table(529) ->
    {0,[{0,114}, {230,783}],[]};
unicode_table(530) ->
    {0,[{0,82}, {230,785}],[]};
unicode_table(531) ->
    {0,[{0,114}, {230,785}],[]};
unicode_table(532) ->
    {0,[{0,85}, {230,783}],[]};
unicode_table(533) ->
    {0,[{0,117}, {230,783}],[]};
unicode_table(534) ->
    {0,[{0,85}, {230,785}],[]};
unicode_table(535) ->
    {0,[{0,117}, {230,785}],[]};
unicode_table(536) ->
    {0,[{0,83}, {220,806}],[]};
unicode_table(537) ->
    {0,[{0,115}, {220,806}],[]};
unicode_table(538) ->
    {0,[{0,84}, {220,806}],[]};
unicode_table(539) ->
    {0,[{0,116}, {220,806}],[]};
unicode_table(542) ->
    {0,[{0,72}, {230,780}],[]};
unicode_table(543) ->
    {0,[{0,104}, {230,780}],[]};
unicode_table(550) ->
    {0,[{0,65}, {230,775}],[]};
unicode_table(551) ->
    {0,[{0,97}, {230,775}],[]};
unicode_table(552) ->
    {0,[{0,69}, {202,807}],[]};
unicode_table(553) ->
    {0,[{0,101}, {202,807}],[]};
unicode_table(554) ->
    {0,[{0,79}, {230,776}, {230,772}],[]};
unicode_table(555) ->
    {0,[{0,111}, {230,776}, {230,772}],[]};
unicode_table(556) ->
    {0,[{0,79}, {230,771}, {230,772}],[]};
unicode_table(557) ->
    {0,[{0,111}, {230,771}, {230,772}],[]};
unicode_table(558) ->
    {0,[{0,79}, {230,775}],[]};
unicode_table(559) ->
    {0,[{0,111}, {230,775}],[]};
unicode_table(560) ->
    {0,[{0,79}, {230,775}, {230,772}],[]};
unicode_table(561) ->
    {0,[{0,111}, {230,775}, {230,772}],[]};
unicode_table(562) ->
    {0,[{0,89}, {230,772}],[]};
unicode_table(563) ->
    {0,[{0,121}, {230,772}],[]};
unicode_table(688) ->
    {0,[],{super,[{0,104}]}};
unicode_table(689) ->
    {0,[],{super,[{0,614}]}};
unicode_table(690) ->
    {0,[],{super,[{0,106}]}};
unicode_table(691) ->
    {0,[],{super,[{0,114}]}};
unicode_table(692) ->
    {0,[],{super,[{0,633}]}};
unicode_table(693) ->
    {0,[],{super,[{0,635}]}};
unicode_table(694) ->
    {0,[],{super,[{0,641}]}};
unicode_table(695) ->
    {0,[],{super,[{0,119}]}};
unicode_table(696) ->
    {0,[],{super,[{0,121}]}};
unicode_table(728) ->
    {0,[],{compat,[{0,32}, {230,774}]}};
unicode_table(729) ->
    {0,[],{compat,[{0,32}, {230,775}]}};
unicode_table(730) ->
    {0,[],{compat,[{0,32}, {230,778}]}};
unicode_table(731) ->
    {0,[],{compat,[{0,32}, {202,808}]}};
unicode_table(732) ->
    {0,[],{compat,[{0,32}, {230,771}]}};
unicode_table(733) ->
    {0,[],{compat,[{0,32}, {230,779}]}};
unicode_table(736) ->
    {0,[],{super,[{0,611}]}};
unicode_table(737) ->
    {0,[],{super,[{0,108}]}};
unicode_table(738) ->
    {0,[],{super,[{0,115}]}};
unicode_table(739) ->
    {0,[],{super,[{0,120}]}};
unicode_table(740) ->
    {0,[],{super,[{0,661}]}};
unicode_table(768) ->
    {230,[],[]};
unicode_table(769) ->
    {230,[],[]};
unicode_table(770) ->
    {230,[],[]};
unicode_table(771) ->
    {230,[],[]};
unicode_table(772) ->
    {230,[],[]};
unicode_table(773) ->
    {230,[],[]};
unicode_table(774) ->
    {230,[],[]};
unicode_table(775) ->
    {230,[],[]};
unicode_table(776) ->
    {230,[],[]};
unicode_table(777) ->
    {230,[],[]};
unicode_table(778) ->
    {230,[],[]};
unicode_table(779) ->
    {230,[],[]};
unicode_table(780) ->
    {230,[],[]};
unicode_table(781) ->
    {230,[],[]};
unicode_table(782) ->
    {230,[],[]};
unicode_table(783) ->
    {230,[],[]};
unicode_table(784) ->
    {230,[],[]};
unicode_table(785) ->
    {230,[],[]};
unicode_table(786) ->
    {230,[],[]};
unicode_table(787) ->
    {230,[],[]};
unicode_table(788) ->
    {230,[],[]};
unicode_table(789) ->
    {232,[],[]};
unicode_table(790) ->
    {220,[],[]};
unicode_table(791) ->
    {220,[],[]};
unicode_table(792) ->
    {220,[],[]};
unicode_table(793) ->
    {220,[],[]};
unicode_table(794) ->
    {232,[],[]};
unicode_table(795) ->
    {216,[],[]};
unicode_table(796) ->
    {220,[],[]};
unicode_table(797) ->
    {220,[],[]};
unicode_table(798) ->
    {220,[],[]};
unicode_table(799) ->
    {220,[],[]};
unicode_table(800) ->
    {220,[],[]};
unicode_table(801) ->
    {202,[],[]};
unicode_table(802) ->
    {202,[],[]};
unicode_table(803) ->
    {220,[],[]};
unicode_table(804) ->
    {220,[],[]};
unicode_table(805) ->
    {220,[],[]};
unicode_table(806) ->
    {220,[],[]};
unicode_table(807) ->
    {202,[],[]};
unicode_table(808) ->
    {202,[],[]};
unicode_table(809) ->
    {220,[],[]};
unicode_table(810) ->
    {220,[],[]};
unicode_table(811) ->
    {220,[],[]};
unicode_table(812) ->
    {220,[],[]};
unicode_table(813) ->
    {220,[],[]};
unicode_table(814) ->
    {220,[],[]};
unicode_table(815) ->
    {220,[],[]};
unicode_table(816) ->
    {220,[],[]};
unicode_table(817) ->
    {220,[],[]};
unicode_table(818) ->
    {220,[],[]};
unicode_table(819) ->
    {220,[],[]};
unicode_table(820) ->
    {1,[],[]};
unicode_table(821) ->
    {1,[],[]};
unicode_table(822) ->
    {1,[],[]};
unicode_table(823) ->
    {1,[],[]};
unicode_table(824) ->
    {1,[],[]};
unicode_table(825) ->
    {220,[],[]};
unicode_table(826) ->
    {220,[],[]};
unicode_table(827) ->
    {220,[],[]};
unicode_table(828) ->
    {220,[],[]};
unicode_table(829) ->
    {230,[],[]};
unicode_table(830) ->
    {230,[],[]};
unicode_table(831) ->
    {230,[],[]};
unicode_table(832) ->
    {230,[{230,768}],[]};
unicode_table(833) ->
    {230,[{230,769}],[]};
unicode_table(834) ->
    {230,[],[]};
unicode_table(835) ->
    {230,[{230,787}],[]};
unicode_table(836) ->
    {230,[{230,776}, {230,769}],[]};
unicode_table(837) ->
    {240,[],[]};
unicode_table(838) ->
    {230,[],[]};
unicode_table(839) ->
    {220,[],[]};
unicode_table(840) ->
    {220,[],[]};
unicode_table(841) ->
    {220,[],[]};
unicode_table(842) ->
    {230,[],[]};
unicode_table(843) ->
    {230,[],[]};
unicode_table(844) ->
    {230,[],[]};
unicode_table(845) ->
    {220,[],[]};
unicode_table(846) ->
    {220,[],[]};
unicode_table(848) ->
    {230,[],[]};
unicode_table(849) ->
    {230,[],[]};
unicode_table(850) ->
    {230,[],[]};
unicode_table(851) ->
    {220,[],[]};
unicode_table(852) ->
    {220,[],[]};
unicode_table(853) ->
    {220,[],[]};
unicode_table(854) ->
    {220,[],[]};
unicode_table(855) ->
    {230,[],[]};
unicode_table(856) ->
    {232,[],[]};
unicode_table(857) ->
    {220,[],[]};
unicode_table(858) ->
    {220,[],[]};
unicode_table(859) ->
    {230,[],[]};
unicode_table(860) ->
    {233,[],[]};
unicode_table(861) ->
    {234,[],[]};
unicode_table(862) ->
    {234,[],[]};
unicode_table(863) ->
    {233,[],[]};
unicode_table(864) ->
    {234,[],[]};
unicode_table(865) ->
    {234,[],[]};
unicode_table(866) ->
    {233,[],[]};
unicode_table(867) ->
    {230,[],[]};
unicode_table(868) ->
    {230,[],[]};
unicode_table(869) ->
    {230,[],[]};
unicode_table(870) ->
    {230,[],[]};
unicode_table(871) ->
    {230,[],[]};
unicode_table(872) ->
    {230,[],[]};
unicode_table(873) ->
    {230,[],[]};
unicode_table(874) ->
    {230,[],[]};
unicode_table(875) ->
    {230,[],[]};
unicode_table(876) ->
    {230,[],[]};
unicode_table(877) ->
    {230,[],[]};
unicode_table(878) ->
    {230,[],[]};
unicode_table(879) ->
    {230,[],[]};
unicode_table(884) ->
    {0,[{0,697}],[]};
unicode_table(890) ->
    {0,[],{compat,[{0,32}, {240,837}]}};
unicode_table(894) ->
    {0,[{0,59}],[]};
unicode_table(900) ->
    {0,[],{compat,[{0,32}, {230,769}]}};
unicode_table(901) ->
    {0,[{0,168}, {230,769}],{compat,[{0,32}, {230,776}, {230,769}]}};
unicode_table(902) ->
    {0,[{0,913}, {230,769}],[]};
unicode_table(903) ->
    {0,[{0,183}],[]};
unicode_table(904) ->
    {0,[{0,917}, {230,769}],[]};
unicode_table(905) ->
    {0,[{0,919}, {230,769}],[]};
unicode_table(906) ->
    {0,[{0,921}, {230,769}],[]};
unicode_table(908) ->
    {0,[{0,927}, {230,769}],[]};
unicode_table(910) ->
    {0,[{0,933}, {230,769}],[]};
unicode_table(911) ->
    {0,[{0,937}, {230,769}],[]};
unicode_table(912) ->
    {0,[{0,953}, {230,776}, {230,769}],[]};
unicode_table(938) ->
    {0,[{0,921}, {230,776}],[]};
unicode_table(939) ->
    {0,[{0,933}, {230,776}],[]};
unicode_table(940) ->
    {0,[{0,945}, {230,769}],[]};
unicode_table(941) ->
    {0,[{0,949}, {230,769}],[]};
unicode_table(942) ->
    {0,[{0,951}, {230,769}],[]};
unicode_table(943) ->
    {0,[{0,953}, {230,769}],[]};
unicode_table(944) ->
    {0,[{0,965}, {230,776}, {230,769}],[]};
unicode_table(970) ->
    {0,[{0,953}, {230,776}],[]};
unicode_table(971) ->
    {0,[{0,965}, {230,776}],[]};
unicode_table(972) ->
    {0,[{0,959}, {230,769}],[]};
unicode_table(973) ->
    {0,[{0,965}, {230,769}],[]};
unicode_table(974) ->
    {0,[{0,969}, {230,769}],[]};
unicode_table(976) ->
    {0,[],{compat,[{0,946}]}};
unicode_table(977) ->
    {0,[],{compat,[{0,952}]}};
unicode_table(978) ->
    {0,[],{compat,[{0,933}]}};
unicode_table(979) ->
    {0,[{0,978}, {230,769}],{compat,[{0,933}, {230,769}]}};
unicode_table(980) ->
    {0,[{0,978}, {230,776}],{compat,[{0,933}, {230,776}]}};
unicode_table(981) ->
    {0,[],{compat,[{0,966}]}};
unicode_table(982) ->
    {0,[],{compat,[{0,960}]}};
unicode_table(1008) ->
    {0,[],{compat,[{0,954}]}};
unicode_table(1009) ->
    {0,[],{compat,[{0,961}]}};
unicode_table(1010) ->
    {0,[],{compat,[{0,962}]}};
unicode_table(1012) ->
    {0,[],{compat,[{0,920}]}};
unicode_table(1013) ->
    {0,[],{compat,[{0,949}]}};
unicode_table(1017) ->
    {0,[],{compat,[{0,931}]}};
unicode_table(1024) ->
    {0,[{0,1045}, {230,768}],[]};
unicode_table(1025) ->
    {0,[{0,1045}, {230,776}],[]};
unicode_table(1027) ->
    {0,[{0,1043}, {230,769}],[]};
unicode_table(1031) ->
    {0,[{0,1030}, {230,776}],[]};
unicode_table(1036) ->
    {0,[{0,1050}, {230,769}],[]};
unicode_table(1037) ->
    {0,[{0,1048}, {230,768}],[]};
unicode_table(1038) ->
    {0,[{0,1059}, {230,774}],[]};
unicode_table(1049) ->
    {0,[{0,1048}, {230,774}],[]};
unicode_table(1081) ->
    {0,[{0,1080}, {230,774}],[]};
unicode_table(1104) ->
    {0,[{0,1077}, {230,768}],[]};
unicode_table(1105) ->
    {0,[{0,1077}, {230,776}],[]};
unicode_table(1107) ->
    {0,[{0,1075}, {230,769}],[]};
unicode_table(1111) ->
    {0,[{0,1110}, {230,776}],[]};
unicode_table(1116) ->
    {0,[{0,1082}, {230,769}],[]};
unicode_table(1117) ->
    {0,[{0,1080}, {230,768}],[]};
unicode_table(1118) ->
    {0,[{0,1091}, {230,774}],[]};
unicode_table(1142) ->
    {0,[{0,1140}, {230,783}],[]};
unicode_table(1143) ->
    {0,[{0,1141}, {230,783}],[]};
unicode_table(1155) ->
    {230,[],[]};
unicode_table(1156) ->
    {230,[],[]};
unicode_table(1157) ->
    {230,[],[]};
unicode_table(1158) ->
    {230,[],[]};
unicode_table(1159) ->
    {230,[],[]};
unicode_table(1217) ->
    {0,[{0,1046}, {230,774}],[]};
unicode_table(1218) ->
    {0,[{0,1078}, {230,774}],[]};
unicode_table(1232) ->
    {0,[{0,1040}, {230,774}],[]};
unicode_table(1233) ->
    {0,[{0,1072}, {230,774}],[]};
unicode_table(1234) ->
    {0,[{0,1040}, {230,776}],[]};
unicode_table(1235) ->
    {0,[{0,1072}, {230,776}],[]};
unicode_table(1238) ->
    {0,[{0,1045}, {230,774}],[]};
unicode_table(1239) ->
    {0,[{0,1077}, {230,774}],[]};
unicode_table(1242) ->
    {0,[{0,1240}, {230,776}],[]};
unicode_table(1243) ->
    {0,[{0,1241}, {230,776}],[]};
unicode_table(1244) ->
    {0,[{0,1046}, {230,776}],[]};
unicode_table(1245) ->
    {0,[{0,1078}, {230,776}],[]};
unicode_table(1246) ->
    {0,[{0,1047}, {230,776}],[]};
unicode_table(1247) ->
    {0,[{0,1079}, {230,776}],[]};
unicode_table(1250) ->
    {0,[{0,1048}, {230,772}],[]};
unicode_table(1251) ->
    {0,[{0,1080}, {230,772}],[]};
unicode_table(1252) ->
    {0,[{0,1048}, {230,776}],[]};
unicode_table(1253) ->
    {0,[{0,1080}, {230,776}],[]};
unicode_table(1254) ->
    {0,[{0,1054}, {230,776}],[]};
unicode_table(1255) ->
    {0,[{0,1086}, {230,776}],[]};
unicode_table(1258) ->
    {0,[{0,1256}, {230,776}],[]};
unicode_table(1259) ->
    {0,[{0,1257}, {230,776}],[]};
unicode_table(1260) ->
    {0,[{0,1069}, {230,776}],[]};
unicode_table(1261) ->
    {0,[{0,1101}, {230,776}],[]};
unicode_table(1262) ->
    {0,[{0,1059}, {230,772}],[]};
unicode_table(1263) ->
    {0,[{0,1091}, {230,772}],[]};
unicode_table(1264) ->
    {0,[{0,1059}, {230,776}],[]};
unicode_table(1265) ->
    {0,[{0,1091}, {230,776}],[]};
unicode_table(1266) ->
    {0,[{0,1059}, {230,779}],[]};
unicode_table(1267) ->
    {0,[{0,1091}, {230,779}],[]};
unicode_table(1268) ->
    {0,[{0,1063}, {230,776}],[]};
unicode_table(1269) ->
    {0,[{0,1095}, {230,776}],[]};
unicode_table(1272) ->
    {0,[{0,1067}, {230,776}],[]};
unicode_table(1273) ->
    {0,[{0,1099}, {230,776}],[]};
unicode_table(1415) ->
    {0,[],{compat,[{0,1381}, {0,1410}]}};
unicode_table(1425) ->
    {220,[],[]};
unicode_table(1426) ->
    {230,[],[]};
unicode_table(1427) ->
    {230,[],[]};
unicode_table(1428) ->
    {230,[],[]};
unicode_table(1429) ->
    {230,[],[]};
unicode_table(1430) ->
    {220,[],[]};
unicode_table(1431) ->
    {230,[],[]};
unicode_table(1432) ->
    {230,[],[]};
unicode_table(1433) ->
    {230,[],[]};
unicode_table(1434) ->
    {222,[],[]};
unicode_table(1435) ->
    {220,[],[]};
unicode_table(1436) ->
    {230,[],[]};
unicode_table(1437) ->
    {230,[],[]};
unicode_table(1438) ->
    {230,[],[]};
unicode_table(1439) ->
    {230,[],[]};
unicode_table(1440) ->
    {230,[],[]};
unicode_table(1441) ->
    {230,[],[]};
unicode_table(1442) ->
    {220,[],[]};
unicode_table(1443) ->
    {220,[],[]};
unicode_table(1444) ->
    {220,[],[]};
unicode_table(1445) ->
    {220,[],[]};
unicode_table(1446) ->
    {220,[],[]};
unicode_table(1447) ->
    {220,[],[]};
unicode_table(1448) ->
    {230,[],[]};
unicode_table(1449) ->
    {230,[],[]};
unicode_table(1450) ->
    {220,[],[]};
unicode_table(1451) ->
    {230,[],[]};
unicode_table(1452) ->
    {230,[],[]};
unicode_table(1453) ->
    {222,[],[]};
unicode_table(1454) ->
    {228,[],[]};
unicode_table(1455) ->
    {230,[],[]};
unicode_table(1456) ->
    {10,[],[]};
unicode_table(1457) ->
    {11,[],[]};
unicode_table(1458) ->
    {12,[],[]};
unicode_table(1459) ->
    {13,[],[]};
unicode_table(1460) ->
    {14,[],[]};
unicode_table(1461) ->
    {15,[],[]};
unicode_table(1462) ->
    {16,[],[]};
unicode_table(1463) ->
    {17,[],[]};
unicode_table(1464) ->
    {18,[],[]};
unicode_table(1465) ->
    {19,[],[]};
unicode_table(1466) ->
    {19,[],[]};
unicode_table(1467) ->
    {20,[],[]};
unicode_table(1468) ->
    {21,[],[]};
unicode_table(1469) ->
    {22,[],[]};
unicode_table(1471) ->
    {23,[],[]};
unicode_table(1473) ->
    {24,[],[]};
unicode_table(1474) ->
    {25,[],[]};
unicode_table(1476) ->
    {230,[],[]};
unicode_table(1477) ->
    {220,[],[]};
unicode_table(1479) ->
    {18,[],[]};
unicode_table(1552) ->
    {230,[],[]};
unicode_table(1553) ->
    {230,[],[]};
unicode_table(1554) ->
    {230,[],[]};
unicode_table(1555) ->
    {230,[],[]};
unicode_table(1556) ->
    {230,[],[]};
unicode_table(1557) ->
    {230,[],[]};
unicode_table(1558) ->
    {230,[],[]};
unicode_table(1559) ->
    {230,[],[]};
unicode_table(1560) ->
    {30,[],[]};
unicode_table(1561) ->
    {31,[],[]};
unicode_table(1562) ->
    {32,[],[]};
unicode_table(1570) ->
    {0,[{0,1575}, {230,1619}],[]};
unicode_table(1571) ->
    {0,[{0,1575}, {230,1620}],[]};
unicode_table(1572) ->
    {0,[{0,1608}, {230,1620}],[]};
unicode_table(1573) ->
    {0,[{0,1575}, {220,1621}],[]};
unicode_table(1574) ->
    {0,[{0,1610}, {230,1620}],[]};
unicode_table(1611) ->
    {27,[],[]};
unicode_table(1612) ->
    {28,[],[]};
unicode_table(1613) ->
    {29,[],[]};
unicode_table(1614) ->
    {30,[],[]};
unicode_table(1615) ->
    {31,[],[]};
unicode_table(1616) ->
    {32,[],[]};
unicode_table(1617) ->
    {33,[],[]};
unicode_table(1618) ->
    {34,[],[]};
unicode_table(1619) ->
    {230,[],[]};
unicode_table(1620) ->
    {230,[],[]};
unicode_table(1621) ->
    {220,[],[]};
unicode_table(1622) ->
    {220,[],[]};
unicode_table(1623) ->
    {230,[],[]};
unicode_table(1624) ->
    {230,[],[]};
unicode_table(1625) ->
    {230,[],[]};
unicode_table(1626) ->
    {230,[],[]};
unicode_table(1627) ->
    {230,[],[]};
unicode_table(1628) ->
    {220,[],[]};
unicode_table(1629) ->
    {230,[],[]};
unicode_table(1630) ->
    {230,[],[]};
unicode_table(1631) ->
    {220,[],[]};
unicode_table(1648) ->
    {35,[],[]};
unicode_table(1653) ->
    {0,[],{compat,[{0,1575}, {0,1652}]}};
unicode_table(1654) ->
    {0,[],{compat,[{0,1608}, {0,1652}]}};
unicode_table(1655) ->
    {0,[],{compat,[{0,1735}, {0,1652}]}};
unicode_table(1656) ->
    {0,[],{compat,[{0,1610}, {0,1652}]}};
unicode_table(1728) ->
    {0,[{0,1749}, {230,1620}],[]};
unicode_table(1730) ->
    {0,[{0,1729}, {230,1620}],[]};
unicode_table(1747) ->
    {0,[{0,1746}, {230,1620}],[]};
unicode_table(1750) ->
    {230,[],[]};
unicode_table(1751) ->
    {230,[],[]};
unicode_table(1752) ->
    {230,[],[]};
unicode_table(1753) ->
    {230,[],[]};
unicode_table(1754) ->
    {230,[],[]};
unicode_table(1755) ->
    {230,[],[]};
unicode_table(1756) ->
    {230,[],[]};
unicode_table(1759) ->
    {230,[],[]};
unicode_table(1760) ->
    {230,[],[]};
unicode_table(1761) ->
    {230,[],[]};
unicode_table(1762) ->
    {230,[],[]};
unicode_table(1763) ->
    {220,[],[]};
unicode_table(1764) ->
    {230,[],[]};
unicode_table(1767) ->
    {230,[],[]};
unicode_table(1768) ->
    {230,[],[]};
unicode_table(1770) ->
    {220,[],[]};
unicode_table(1771) ->
    {230,[],[]};
unicode_table(1772) ->
    {230,[],[]};
unicode_table(1773) ->
    {220,[],[]};
unicode_table(1809) ->
    {36,[],[]};
unicode_table(1840) ->
    {230,[],[]};
unicode_table(1841) ->
    {220,[],[]};
unicode_table(1842) ->
    {230,[],[]};
unicode_table(1843) ->
    {230,[],[]};
unicode_table(1844) ->
    {220,[],[]};
unicode_table(1845) ->
    {230,[],[]};
unicode_table(1846) ->
    {230,[],[]};
unicode_table(1847) ->
    {220,[],[]};
unicode_table(1848) ->
    {220,[],[]};
unicode_table(1849) ->
    {220,[],[]};
unicode_table(1850) ->
    {230,[],[]};
unicode_table(1851) ->
    {220,[],[]};
unicode_table(1852) ->
    {220,[],[]};
unicode_table(1853) ->
    {230,[],[]};
unicode_table(1854) ->
    {220,[],[]};
unicode_table(1855) ->
    {230,[],[]};
unicode_table(1856) ->
    {230,[],[]};
unicode_table(1857) ->
    {230,[],[]};
unicode_table(1858) ->
    {220,[],[]};
unicode_table(1859) ->
    {230,[],[]};
unicode_table(1860) ->
    {220,[],[]};
unicode_table(1861) ->
    {230,[],[]};
unicode_table(1862) ->
    {220,[],[]};
unicode_table(1863) ->
    {230,[],[]};
unicode_table(1864) ->
    {220,[],[]};
unicode_table(1865) ->
    {230,[],[]};
unicode_table(1866) ->
    {230,[],[]};
unicode_table(2027) ->
    {230,[],[]};
unicode_table(2028) ->
    {230,[],[]};
unicode_table(2029) ->
    {230,[],[]};
unicode_table(2030) ->
    {230,[],[]};
unicode_table(2031) ->
    {230,[],[]};
unicode_table(2032) ->
    {230,[],[]};
unicode_table(2033) ->
    {230,[],[]};
unicode_table(2034) ->
    {220,[],[]};
unicode_table(2035) ->
    {230,[],[]};
unicode_table(2045) ->
    {220,[],[]};
unicode_table(2070) ->
    {230,[],[]};
unicode_table(2071) ->
    {230,[],[]};
unicode_table(2072) ->
    {230,[],[]};
unicode_table(2073) ->
    {230,[],[]};
unicode_table(2075) ->
    {230,[],[]};
unicode_table(2076) ->
    {230,[],[]};
unicode_table(2077) ->
    {230,[],[]};
unicode_table(2078) ->
    {230,[],[]};
unicode_table(2079) ->
    {230,[],[]};
unicode_table(2080) ->
    {230,[],[]};
unicode_table(2081) ->
    {230,[],[]};
unicode_table(2082) ->
    {230,[],[]};
unicode_table(2083) ->
    {230,[],[]};
unicode_table(2085) ->
    {230,[],[]};
unicode_table(2086) ->
    {230,[],[]};
unicode_table(2087) ->
    {230,[],[]};
unicode_table(2089) ->
    {230,[],[]};
unicode_table(2090) ->
    {230,[],[]};
unicode_table(2091) ->
    {230,[],[]};
unicode_table(2092) ->
    {230,[],[]};
unicode_table(2093) ->
    {230,[],[]};
unicode_table(2137) ->
    {220,[],[]};
unicode_table(2138) ->
    {220,[],[]};
unicode_table(2139) ->
    {220,[],[]};
unicode_table(2259) ->
    {220,[],[]};
unicode_table(2260) ->
    {230,[],[]};
unicode_table(2261) ->
    {230,[],[]};
unicode_table(2262) ->
    {230,[],[]};
unicode_table(2263) ->
    {230,[],[]};
unicode_table(2264) ->
    {230,[],[]};
unicode_table(2265) ->
    {230,[],[]};
unicode_table(2266) ->
    {230,[],[]};
unicode_table(2267) ->
    {230,[],[]};
unicode_table(2268) ->
    {230,[],[]};
unicode_table(2269) ->
    {230,[],[]};
unicode_table(2270) ->
    {230,[],[]};
unicode_table(2271) ->
    {230,[],[]};
unicode_table(2272) ->
    {230,[],[]};
unicode_table(2273) ->
    {230,[],[]};
unicode_table(2275) ->
    {220,[],[]};
unicode_table(2276) ->
    {230,[],[]};
unicode_table(2277) ->
    {230,[],[]};
unicode_table(2278) ->
    {220,[],[]};
unicode_table(2279) ->
    {230,[],[]};
unicode_table(2280) ->
    {230,[],[]};
unicode_table(2281) ->
    {220,[],[]};
unicode_table(2282) ->
    {230,[],[]};
unicode_table(2283) ->
    {230,[],[]};
unicode_table(2284) ->
    {230,[],[]};
unicode_table(2285) ->
    {220,[],[]};
unicode_table(2286) ->
    {220,[],[]};
unicode_table(2287) ->
    {220,[],[]};
unicode_table(2288) ->
    {27,[],[]};
unicode_table(2289) ->
    {28,[],[]};
unicode_table(2290) ->
    {29,[],[]};
unicode_table(2291) ->
    {230,[],[]};
unicode_table(2292) ->
    {230,[],[]};
unicode_table(2293) ->
    {230,[],[]};
unicode_table(2294) ->
    {220,[],[]};
unicode_table(2295) ->
    {230,[],[]};
unicode_table(2296) ->
    {230,[],[]};
unicode_table(2297) ->
    {220,[],[]};
unicode_table(2298) ->
    {220,[],[]};
unicode_table(2299) ->
    {230,[],[]};
unicode_table(2300) ->
    {230,[],[]};
unicode_table(2301) ->
    {230,[],[]};
unicode_table(2302) ->
    {230,[],[]};
unicode_table(2303) ->
    {230,[],[]};
unicode_table(2345) ->
    {0,[{0,2344}, {7,2364}],[]};
unicode_table(2353) ->
    {0,[{0,2352}, {7,2364}],[]};
unicode_table(2356) ->
    {0,[{0,2355}, {7,2364}],[]};
unicode_table(2364) ->
    {7,[],[]};
unicode_table(2381) ->
    {9,[],[]};
unicode_table(2385) ->
    {230,[],[]};
unicode_table(2386) ->
    {220,[],[]};
unicode_table(2387) ->
    {230,[],[]};
unicode_table(2388) ->
    {230,[],[]};
unicode_table(2392) ->
    {0,[{0,2325}, {7,2364}],[]};
unicode_table(2393) ->
    {0,[{0,2326}, {7,2364}],[]};
unicode_table(2394) ->
    {0,[{0,2327}, {7,2364}],[]};
unicode_table(2395) ->
    {0,[{0,2332}, {7,2364}],[]};
unicode_table(2396) ->
    {0,[{0,2337}, {7,2364}],[]};
unicode_table(2397) ->
    {0,[{0,2338}, {7,2364}],[]};
unicode_table(2398) ->
    {0,[{0,2347}, {7,2364}],[]};
unicode_table(2399) ->
    {0,[{0,2351}, {7,2364}],[]};
unicode_table(2492) ->
    {7,[],[]};
unicode_table(2507) ->
    {0,[{0,2503}, {0,2494}],[]};
unicode_table(2508) ->
    {0,[{0,2503}, {0,2519}],[]};
unicode_table(2509) ->
    {9,[],[]};
unicode_table(2524) ->
    {0,[{0,2465}, {7,2492}],[]};
unicode_table(2525) ->
    {0,[{0,2466}, {7,2492}],[]};
unicode_table(2527) ->
    {0,[{0,2479}, {7,2492}],[]};
unicode_table(2558) ->
    {230,[],[]};
unicode_table(2611) ->
    {0,[{0,2610}, {7,2620}],[]};
unicode_table(2614) ->
    {0,[{0,2616}, {7,2620}],[]};
unicode_table(2620) ->
    {7,[],[]};
unicode_table(2637) ->
    {9,[],[]};
unicode_table(2649) ->
    {0,[{0,2582}, {7,2620}],[]};
unicode_table(2650) ->
    {0,[{0,2583}, {7,2620}],[]};
unicode_table(2651) ->
    {0,[{0,2588}, {7,2620}],[]};
unicode_table(2654) ->
    {0,[{0,2603}, {7,2620}],[]};
unicode_table(2748) ->
    {7,[],[]};
unicode_table(2765) ->
    {9,[],[]};
unicode_table(2876) ->
    {7,[],[]};
unicode_table(2888) ->
    {0,[{0,2887}, {0,2902}],[]};
unicode_table(2891) ->
    {0,[{0,2887}, {0,2878}],[]};
unicode_table(2892) ->
    {0,[{0,2887}, {0,2903}],[]};
unicode_table(2893) ->
    {9,[],[]};
unicode_table(2908) ->
    {0,[{0,2849}, {7,2876}],[]};
unicode_table(2909) ->
    {0,[{0,2850}, {7,2876}],[]};
unicode_table(2964) ->
    {0,[{0,2962}, {0,3031}],[]};
unicode_table(3018) ->
    {0,[{0,3014}, {0,3006}],[]};
unicode_table(3019) ->
    {0,[{0,3015}, {0,3006}],[]};
unicode_table(3020) ->
    {0,[{0,3014}, {0,3031}],[]};
unicode_table(3021) ->
    {9,[],[]};
unicode_table(3144) ->
    {0,[{0,3142}, {91,3158}],[]};
unicode_table(3149) ->
    {9,[],[]};
unicode_table(3157) ->
    {84,[],[]};
unicode_table(3158) ->
    {91,[],[]};
unicode_table(3260) ->
    {7,[],[]};
unicode_table(3264) ->
    {0,[{0,3263}, {0,3285}],[]};
unicode_table(3271) ->
    {0,[{0,3270}, {0,3285}],[]};
unicode_table(3272) ->
    {0,[{0,3270}, {0,3286}],[]};
unicode_table(3274) ->
    {0,[{0,3270}, {0,3266}],[]};
unicode_table(3275) ->
    {0,[{0,3270}, {0,3266}, {0,3285}],[]};
unicode_table(3277) ->
    {9,[],[]};
unicode_table(3387) ->
    {9,[],[]};
unicode_table(3388) ->
    {9,[],[]};
unicode_table(3402) ->
    {0,[{0,3398}, {0,3390}],[]};
unicode_table(3403) ->
    {0,[{0,3399}, {0,3390}],[]};
unicode_table(3404) ->
    {0,[{0,3398}, {0,3415}],[]};
unicode_table(3405) ->
    {9,[],[]};
unicode_table(3530) ->
    {9,[],[]};
unicode_table(3546) ->
    {0,[{0,3545}, {9,3530}],[]};
unicode_table(3548) ->
    {0,[{0,3545}, {0,3535}],[]};
unicode_table(3549) ->
    {0,[{0,3545}, {0,3535}, {9,3530}],[]};
unicode_table(3550) ->
    {0,[{0,3545}, {0,3551}],[]};
unicode_table(3635) ->
    {0,[],{compat,[{0,3661}, {0,3634}]}};
unicode_table(3640) ->
    {103,[],[]};
unicode_table(3641) ->
    {103,[],[]};
unicode_table(3642) ->
    {9,[],[]};
unicode_table(3656) ->
    {107,[],[]};
unicode_table(3657) ->
    {107,[],[]};
unicode_table(3658) ->
    {107,[],[]};
unicode_table(3659) ->
    {107,[],[]};
unicode_table(3763) ->
    {0,[],{compat,[{0,3789}, {0,3762}]}};
unicode_table(3768) ->
    {118,[],[]};
unicode_table(3769) ->
    {118,[],[]};
unicode_table(3770) ->
    {9,[],[]};
unicode_table(3784) ->
    {122,[],[]};
unicode_table(3785) ->
    {122,[],[]};
unicode_table(3786) ->
    {122,[],[]};
unicode_table(3787) ->
    {122,[],[]};
unicode_table(3804) ->
    {0,[],{compat,[{0,3755}, {0,3737}]}};
unicode_table(3805) ->
    {0,[],{compat,[{0,3755}, {0,3745}]}};
unicode_table(3852) ->
    {0,[],{noBreak,[{0,3851}]}};
unicode_table(3864) ->
    {220,[],[]};
unicode_table(3865) ->
    {220,[],[]};
unicode_table(3893) ->
    {220,[],[]};
unicode_table(3895) ->
    {220,[],[]};
unicode_table(3897) ->
    {216,[],[]};
unicode_table(3907) ->
    {0,[{0,3906}, {0,4023}],[]};
unicode_table(3917) ->
    {0,[{0,3916}, {0,4023}],[]};
unicode_table(3922) ->
    {0,[{0,3921}, {0,4023}],[]};
unicode_table(3927) ->
    {0,[{0,3926}, {0,4023}],[]};
unicode_table(3932) ->
    {0,[{0,3931}, {0,4023}],[]};
unicode_table(3945) ->
    {0,[{0,3904}, {0,4021}],[]};
unicode_table(3953) ->
    {129,[],[]};
unicode_table(3954) ->
    {130,[],[]};
unicode_table(3955) ->
    {0,[{129,3953}, {130,3954}],[]};
unicode_table(3956) ->
    {132,[],[]};
unicode_table(3957) ->
    {0,[{129,3953}, {132,3956}],[]};
unicode_table(3958) ->
    {0,[{0,4018}, {130,3968}],[]};
unicode_table(3959) ->
    {0,[],{compat,[{0,4018}, {129,3953}, {130,3968}]}};
unicode_table(3960) ->
    {0,[{0,4019}, {130,3968}],[]};
unicode_table(3961) ->
    {0,[],{compat,[{0,4019}, {129,3953}, {130,3968}]}};
unicode_table(3962) ->
    {130,[],[]};
unicode_table(3963) ->
    {130,[],[]};
unicode_table(3964) ->
    {130,[],[]};
unicode_table(3965) ->
    {130,[],[]};
unicode_table(3968) ->
    {130,[],[]};
unicode_table(3969) ->
    {0,[{129,3953}, {130,3968}],[]};
unicode_table(3970) ->
    {230,[],[]};
unicode_table(3971) ->
    {230,[],[]};
unicode_table(3972) ->
    {9,[],[]};
unicode_table(3974) ->
    {230,[],[]};
unicode_table(3975) ->
    {230,[],[]};
unicode_table(3987) ->
    {0,[{0,3986}, {0,4023}],[]};
unicode_table(3997) ->
    {0,[{0,3996}, {0,4023}],[]};
unicode_table(4002) ->
    {0,[{0,4001}, {0,4023}],[]};
unicode_table(4007) ->
    {0,[{0,4006}, {0,4023}],[]};
unicode_table(4012) ->
    {0,[{0,4011}, {0,4023}],[]};
unicode_table(4025) ->
    {0,[{0,3984}, {0,4021}],[]};
unicode_table(4038) ->
    {220,[],[]};
unicode_table(4134) ->
    {0,[{0,4133}, {0,4142}],[]};
unicode_table(4151) ->
    {7,[],[]};
unicode_table(4153) ->
    {9,[],[]};
unicode_table(4154) ->
    {9,[],[]};
unicode_table(4237) ->
    {220,[],[]};
unicode_table(4348) ->
    {0,[],{super,[{0,4316}]}};
unicode_table(4957) ->
    {230,[],[]};
unicode_table(4958) ->
    {230,[],[]};
unicode_table(4959) ->
    {230,[],[]};
unicode_table(5908) ->
    {9,[],[]};
unicode_table(5940) ->
    {9,[],[]};
unicode_table(6098) ->
    {9,[],[]};
unicode_table(6109) ->
    {230,[],[]};
unicode_table(6313) ->
    {228,[],[]};
unicode_table(6457) ->
    {222,[],[]};
unicode_table(6458) ->
    {230,[],[]};
unicode_table(6459) ->
    {220,[],[]};
unicode_table(6679) ->
    {230,[],[]};
unicode_table(6680) ->
    {220,[],[]};
unicode_table(6752) ->
    {9,[],[]};
unicode_table(6773) ->
    {230,[],[]};
unicode_table(6774) ->
    {230,[],[]};
unicode_table(6775) ->
    {230,[],[]};
unicode_table(6776) ->
    {230,[],[]};
unicode_table(6777) ->
    {230,[],[]};
unicode_table(6778) ->
    {230,[],[]};
unicode_table(6779) ->
    {230,[],[]};
unicode_table(6780) ->
    {230,[],[]};
unicode_table(6783) ->
    {220,[],[]};
unicode_table(6832) ->
    {230,[],[]};
unicode_table(6833) ->
    {230,[],[]};
unicode_table(6834) ->
    {230,[],[]};
unicode_table(6835) ->
    {230,[],[]};
unicode_table(6836) ->
    {230,[],[]};
unicode_table(6837) ->
    {220,[],[]};
unicode_table(6838) ->
    {220,[],[]};
unicode_table(6839) ->
    {220,[],[]};
unicode_table(6840) ->
    {220,[],[]};
unicode_table(6841) ->
    {220,[],[]};
unicode_table(6842) ->
    {220,[],[]};
unicode_table(6843) ->
    {230,[],[]};
unicode_table(6844) ->
    {230,[],[]};
unicode_table(6845) ->
    {220,[],[]};
unicode_table(6918) ->
    {0,[{0,6917}, {0,6965}],[]};
unicode_table(6920) ->
    {0,[{0,6919}, {0,6965}],[]};
unicode_table(6922) ->
    {0,[{0,6921}, {0,6965}],[]};
unicode_table(6924) ->
    {0,[{0,6923}, {0,6965}],[]};
unicode_table(6926) ->
    {0,[{0,6925}, {0,6965}],[]};
unicode_table(6930) ->
    {0,[{0,6929}, {0,6965}],[]};
unicode_table(6964) ->
    {7,[],[]};
unicode_table(6971) ->
    {0,[{0,6970}, {0,6965}],[]};
unicode_table(6973) ->
    {0,[{0,6972}, {0,6965}],[]};
unicode_table(6976) ->
    {0,[{0,6974}, {0,6965}],[]};
unicode_table(6977) ->
    {0,[{0,6975}, {0,6965}],[]};
unicode_table(6979) ->
    {0,[{0,6978}, {0,6965}],[]};
unicode_table(6980) ->
    {9,[],[]};
unicode_table(7019) ->
    {230,[],[]};
unicode_table(7020) ->
    {220,[],[]};
unicode_table(7021) ->
    {230,[],[]};
unicode_table(7022) ->
    {230,[],[]};
unicode_table(7023) ->
    {230,[],[]};
unicode_table(7024) ->
    {230,[],[]};
unicode_table(7025) ->
    {230,[],[]};
unicode_table(7026) ->
    {230,[],[]};
unicode_table(7027) ->
    {230,[],[]};
unicode_table(7082) ->
    {9,[],[]};
unicode_table(7083) ->
    {9,[],[]};
unicode_table(7142) ->
    {7,[],[]};
unicode_table(7154) ->
    {9,[],[]};
unicode_table(7155) ->
    {9,[],[]};
unicode_table(7223) ->
    {7,[],[]};
unicode_table(7376) ->
    {230,[],[]};
unicode_table(7377) ->
    {230,[],[]};
unicode_table(7378) ->
    {230,[],[]};
unicode_table(7380) ->
    {1,[],[]};
unicode_table(7381) ->
    {220,[],[]};
unicode_table(7382) ->
    {220,[],[]};
unicode_table(7383) ->
    {220,[],[]};
unicode_table(7384) ->
    {220,[],[]};
unicode_table(7385) ->
    {220,[],[]};
unicode_table(7386) ->
    {230,[],[]};
unicode_table(7387) ->
    {230,[],[]};
unicode_table(7388) ->
    {220,[],[]};
unicode_table(7389) ->
    {220,[],[]};
unicode_table(7390) ->
    {220,[],[]};
unicode_table(7391) ->
    {220,[],[]};
unicode_table(7392) ->
    {230,[],[]};
unicode_table(7394) ->
    {1,[],[]};
unicode_table(7395) ->
    {1,[],[]};
unicode_table(7396) ->
    {1,[],[]};
unicode_table(7397) ->
    {1,[],[]};
unicode_table(7398) ->
    {1,[],[]};
unicode_table(7399) ->
    {1,[],[]};
unicode_table(7400) ->
    {1,[],[]};
unicode_table(7405) ->
    {220,[],[]};
unicode_table(7412) ->
    {230,[],[]};
unicode_table(7416) ->
    {230,[],[]};
unicode_table(7417) ->
    {230,[],[]};
unicode_table(7468) ->
    {0,[],{super,[{0,65}]}};
unicode_table(7469) ->
    {0,[],{super,[{0,198}]}};
unicode_table(7470) ->
    {0,[],{super,[{0,66}]}};
unicode_table(7472) ->
    {0,[],{super,[{0,68}]}};
unicode_table(7473) ->
    {0,[],{super,[{0,69}]}};
unicode_table(7474) ->
    {0,[],{super,[{0,398}]}};
unicode_table(7475) ->
    {0,[],{super,[{0,71}]}};
unicode_table(7476) ->
    {0,[],{super,[{0,72}]}};
unicode_table(7477) ->
    {0,[],{super,[{0,73}]}};
unicode_table(7478) ->
    {0,[],{super,[{0,74}]}};
unicode_table(7479) ->
    {0,[],{super,[{0,75}]}};
unicode_table(7480) ->
    {0,[],{super,[{0,76}]}};
unicode_table(7481) ->
    {0,[],{super,[{0,77}]}};
unicode_table(7482) ->
    {0,[],{super,[{0,78}]}};
unicode_table(7484) ->
    {0,[],{super,[{0,79}]}};
unicode_table(7485) ->
    {0,[],{super,[{0,546}]}};
unicode_table(7486) ->
    {0,[],{super,[{0,80}]}};
unicode_table(7487) ->
    {0,[],{super,[{0,82}]}};
unicode_table(7488) ->
    {0,[],{super,[{0,84}]}};
unicode_table(7489) ->
    {0,[],{super,[{0,85}]}};
unicode_table(7490) ->
    {0,[],{super,[{0,87}]}};
unicode_table(7491) ->
    {0,[],{super,[{0,97}]}};
unicode_table(7492) ->
    {0,[],{super,[{0,592}]}};
unicode_table(7493) ->
    {0,[],{super,[{0,593}]}};
unicode_table(7494) ->
    {0,[],{super,[{0,7426}]}};
unicode_table(7495) ->
    {0,[],{super,[{0,98}]}};
unicode_table(7496) ->
    {0,[],{super,[{0,100}]}};
unicode_table(7497) ->
    {0,[],{super,[{0,101}]}};
unicode_table(7498) ->
    {0,[],{super,[{0,601}]}};
unicode_table(7499) ->
    {0,[],{super,[{0,603}]}};
unicode_table(7500) ->
    {0,[],{super,[{0,604}]}};
unicode_table(7501) ->
    {0,[],{super,[{0,103}]}};
unicode_table(7503) ->
    {0,[],{super,[{0,107}]}};
unicode_table(7504) ->
    {0,[],{super,[{0,109}]}};
unicode_table(7505) ->
    {0,[],{super,[{0,331}]}};
unicode_table(7506) ->
    {0,[],{super,[{0,111}]}};
unicode_table(7507) ->
    {0,[],{super,[{0,596}]}};
unicode_table(7508) ->
    {0,[],{super,[{0,7446}]}};
unicode_table(7509) ->
    {0,[],{super,[{0,7447}]}};
unicode_table(7510) ->
    {0,[],{super,[{0,112}]}};
unicode_table(7511) ->
    {0,[],{super,[{0,116}]}};
unicode_table(7512) ->
    {0,[],{super,[{0,117}]}};
unicode_table(7513) ->
    {0,[],{super,[{0,7453}]}};
unicode_table(7514) ->
    {0,[],{super,[{0,623}]}};
unicode_table(7515) ->
    {0,[],{super,[{0,118}]}};
unicode_table(7516) ->
    {0,[],{super,[{0,7461}]}};
unicode_table(7517) ->
    {0,[],{super,[{0,946}]}};
unicode_table(7518) ->
    {0,[],{super,[{0,947}]}};
unicode_table(7519) ->
    {0,[],{super,[{0,948}]}};
unicode_table(7520) ->
    {0,[],{super,[{0,966}]}};
unicode_table(7521) ->
    {0,[],{super,[{0,967}]}};
unicode_table(7522) ->
    {0,[],{sub,[{0,105}]}};
unicode_table(7523) ->
    {0,[],{sub,[{0,114}]}};
unicode_table(7524) ->
    {0,[],{sub,[{0,117}]}};
unicode_table(7525) ->
    {0,[],{sub,[{0,118}]}};
unicode_table(7526) ->
    {0,[],{sub,[{0,946}]}};
unicode_table(7527) ->
    {0,[],{sub,[{0,947}]}};
unicode_table(7528) ->
    {0,[],{sub,[{0,961}]}};
unicode_table(7529) ->
    {0,[],{sub,[{0,966}]}};
unicode_table(7530) ->
    {0,[],{sub,[{0,967}]}};
unicode_table(7544) ->
    {0,[],{super,[{0,1085}]}};
unicode_table(7579) ->
    {0,[],{super,[{0,594}]}};
unicode_table(7580) ->
    {0,[],{super,[{0,99}]}};
unicode_table(7581) ->
    {0,[],{super,[{0,597}]}};
unicode_table(7582) ->
    {0,[],{super,[{0,240}]}};
unicode_table(7583) ->
    {0,[],{super,[{0,604}]}};
unicode_table(7584) ->
    {0,[],{super,[{0,102}]}};
unicode_table(7585) ->
    {0,[],{super,[{0,607}]}};
unicode_table(7586) ->
    {0,[],{super,[{0,609}]}};
unicode_table(7587) ->
    {0,[],{super,[{0,613}]}};
unicode_table(7588) ->
    {0,[],{super,[{0,616}]}};
unicode_table(7589) ->
    {0,[],{super,[{0,617}]}};
unicode_table(7590) ->
    {0,[],{super,[{0,618}]}};
unicode_table(7591) ->
    {0,[],{super,[{0,7547}]}};
unicode_table(7592) ->
    {0,[],{super,[{0,669}]}};
unicode_table(7593) ->
    {0,[],{super,[{0,621}]}};
unicode_table(7594) ->
    {0,[],{super,[{0,7557}]}};
unicode_table(7595) ->
    {0,[],{super,[{0,671}]}};
unicode_table(7596) ->
    {0,[],{super,[{0,625}]}};
unicode_table(7597) ->
    {0,[],{super,[{0,624}]}};
unicode_table(7598) ->
    {0,[],{super,[{0,626}]}};
unicode_table(7599) ->
    {0,[],{super,[{0,627}]}};
unicode_table(7600) ->
    {0,[],{super,[{0,628}]}};
unicode_table(7601) ->
    {0,[],{super,[{0,629}]}};
unicode_table(7602) ->
    {0,[],{super,[{0,632}]}};
unicode_table(7603) ->
    {0,[],{super,[{0,642}]}};
unicode_table(7604) ->
    {0,[],{super,[{0,643}]}};
unicode_table(7605) ->
    {0,[],{super,[{0,427}]}};
unicode_table(7606) ->
    {0,[],{super,[{0,649}]}};
unicode_table(7607) ->
    {0,[],{super,[{0,650}]}};
unicode_table(7608) ->
    {0,[],{super,[{0,7452}]}};
unicode_table(7609) ->
    {0,[],{super,[{0,651}]}};
unicode_table(7610) ->
    {0,[],{super,[{0,652}]}};
unicode_table(7611) ->
    {0,[],{super,[{0,122}]}};
unicode_table(7612) ->
    {0,[],{super,[{0,656}]}};
unicode_table(7613) ->
    {0,[],{super,[{0,657}]}};
unicode_table(7614) ->
    {0,[],{super,[{0,658}]}};
unicode_table(7615) ->
    {0,[],{super,[{0,952}]}};
unicode_table(7616) ->
    {230,[],[]};
unicode_table(7617) ->
    {230,[],[]};
unicode_table(7618) ->
    {220,[],[]};
unicode_table(7619) ->
    {230,[],[]};
unicode_table(7620) ->
    {230,[],[]};
unicode_table(7621) ->
    {230,[],[]};
unicode_table(7622) ->
    {230,[],[]};
unicode_table(7623) ->
    {230,[],[]};
unicode_table(7624) ->
    {230,[],[]};
unicode_table(7625) ->
    {230,[],[]};
unicode_table(7626) ->
    {220,[],[]};
unicode_table(7627) ->
    {230,[],[]};
unicode_table(7628) ->
    {230,[],[]};
unicode_table(7629) ->
    {234,[],[]};
unicode_table(7630) ->
    {214,[],[]};
unicode_table(7631) ->
    {220,[],[]};
unicode_table(7632) ->
    {202,[],[]};
unicode_table(7633) ->
    {230,[],[]};
unicode_table(7634) ->
    {230,[],[]};
unicode_table(7635) ->
    {230,[],[]};
unicode_table(7636) ->
    {230,[],[]};
unicode_table(7637) ->
    {230,[],[]};
unicode_table(7638) ->
    {230,[],[]};
unicode_table(7639) ->
    {230,[],[]};
unicode_table(7640) ->
    {230,[],[]};
unicode_table(7641) ->
    {230,[],[]};
unicode_table(7642) ->
    {230,[],[]};
unicode_table(7643) ->
    {230,[],[]};
unicode_table(7644) ->
    {230,[],[]};
unicode_table(7645) ->
    {230,[],[]};
unicode_table(7646) ->
    {230,[],[]};
unicode_table(7647) ->
    {230,[],[]};
unicode_table(7648) ->
    {230,[],[]};
unicode_table(7649) ->
    {230,[],[]};
unicode_table(7650) ->
    {230,[],[]};
unicode_table(7651) ->
    {230,[],[]};
unicode_table(7652) ->
    {230,[],[]};
unicode_table(7653) ->
    {230,[],[]};
unicode_table(7654) ->
    {230,[],[]};
unicode_table(7655) ->
    {230,[],[]};
unicode_table(7656) ->
    {230,[],[]};
unicode_table(7657) ->
    {230,[],[]};
unicode_table(7658) ->
    {230,[],[]};
unicode_table(7659) ->
    {230,[],[]};
unicode_table(7660) ->
    {230,[],[]};
unicode_table(7661) ->
    {230,[],[]};
unicode_table(7662) ->
    {230,[],[]};
unicode_table(7663) ->
    {230,[],[]};
unicode_table(7664) ->
    {230,[],[]};
unicode_table(7665) ->
    {230,[],[]};
unicode_table(7666) ->
    {230,[],[]};
unicode_table(7667) ->
    {230,[],[]};
unicode_table(7668) ->
    {230,[],[]};
unicode_table(7669) ->
    {230,[],[]};
unicode_table(7670) ->
    {232,[],[]};
unicode_table(7671) ->
    {228,[],[]};
unicode_table(7672) ->
    {228,[],[]};
unicode_table(7673) ->
    {220,[],[]};
unicode_table(7675) ->
    {230,[],[]};
unicode_table(7676) ->
    {233,[],[]};
unicode_table(7677) ->
    {220,[],[]};
unicode_table(7678) ->
    {230,[],[]};
unicode_table(7679) ->
    {220,[],[]};
unicode_table(7680) ->
    {0,[{0,65}, {220,805}],[]};
unicode_table(7681) ->
    {0,[{0,97}, {220,805}],[]};
unicode_table(7682) ->
    {0,[{0,66}, {230,775}],[]};
unicode_table(7683) ->
    {0,[{0,98}, {230,775}],[]};
unicode_table(7684) ->
    {0,[{0,66}, {220,803}],[]};
unicode_table(7685) ->
    {0,[{0,98}, {220,803}],[]};
unicode_table(7686) ->
    {0,[{0,66}, {220,817}],[]};
unicode_table(7687) ->
    {0,[{0,98}, {220,817}],[]};
unicode_table(7688) ->
    {0,[{0,67}, {202,807}, {230,769}],[]};
unicode_table(7689) ->
    {0,[{0,99}, {202,807}, {230,769}],[]};
unicode_table(7690) ->
    {0,[{0,68}, {230,775}],[]};
unicode_table(7691) ->
    {0,[{0,100}, {230,775}],[]};
unicode_table(7692) ->
    {0,[{0,68}, {220,803}],[]};
unicode_table(7693) ->
    {0,[{0,100}, {220,803}],[]};
unicode_table(7694) ->
    {0,[{0,68}, {220,817}],[]};
unicode_table(7695) ->
    {0,[{0,100}, {220,817}],[]};
unicode_table(7696) ->
    {0,[{0,68}, {202,807}],[]};
unicode_table(7697) ->
    {0,[{0,100}, {202,807}],[]};
unicode_table(7698) ->
    {0,[{0,68}, {220,813}],[]};
unicode_table(7699) ->
    {0,[{0,100}, {220,813}],[]};
unicode_table(7700) ->
    {0,[{0,69}, {230,772}, {230,768}],[]};
unicode_table(7701) ->
    {0,[{0,101}, {230,772}, {230,768}],[]};
unicode_table(7702) ->
    {0,[{0,69}, {230,772}, {230,769}],[]};
unicode_table(7703) ->
    {0,[{0,101}, {230,772}, {230,769}],[]};
unicode_table(7704) ->
    {0,[{0,69}, {220,813}],[]};
unicode_table(7705) ->
    {0,[{0,101}, {220,813}],[]};
unicode_table(7706) ->
    {0,[{0,69}, {220,816}],[]};
unicode_table(7707) ->
    {0,[{0,101}, {220,816}],[]};
unicode_table(7708) ->
    {0,[{0,69}, {202,807}, {230,774}],[]};
unicode_table(7709) ->
    {0,[{0,101}, {202,807}, {230,774}],[]};
unicode_table(7710) ->
    {0,[{0,70}, {230,775}],[]};
unicode_table(7711) ->
    {0,[{0,102}, {230,775}],[]};
unicode_table(7712) ->
    {0,[{0,71}, {230,772}],[]};
unicode_table(7713) ->
    {0,[{0,103}, {230,772}],[]};
unicode_table(7714) ->
    {0,[{0,72}, {230,775}],[]};
unicode_table(7715) ->
    {0,[{0,104}, {230,775}],[]};
unicode_table(7716) ->
    {0,[{0,72}, {220,803}],[]};
unicode_table(7717) ->
    {0,[{0,104}, {220,803}],[]};
unicode_table(7718) ->
    {0,[{0,72}, {230,776}],[]};
unicode_table(7719) ->
    {0,[{0,104}, {230,776}],[]};
unicode_table(7720) ->
    {0,[{0,72}, {202,807}],[]};
unicode_table(7721) ->
    {0,[{0,104}, {202,807}],[]};
unicode_table(7722) ->
    {0,[{0,72}, {220,814}],[]};
unicode_table(7723) ->
    {0,[{0,104}, {220,814}],[]};
unicode_table(7724) ->
    {0,[{0,73}, {220,816}],[]};
unicode_table(7725) ->
    {0,[{0,105}, {220,816}],[]};
unicode_table(7726) ->
    {0,[{0,73}, {230,776}, {230,769}],[]};
unicode_table(7727) ->
    {0,[{0,105}, {230,776}, {230,769}],[]};
unicode_table(7728) ->
    {0,[{0,75}, {230,769}],[]};
unicode_table(7729) ->
    {0,[{0,107}, {230,769}],[]};
unicode_table(7730) ->
    {0,[{0,75}, {220,803}],[]};
unicode_table(7731) ->
    {0,[{0,107}, {220,803}],[]};
unicode_table(7732) ->
    {0,[{0,75}, {220,817}],[]};
unicode_table(7733) ->
    {0,[{0,107}, {220,817}],[]};
unicode_table(7734) ->
    {0,[{0,76}, {220,803}],[]};
unicode_table(7735) ->
    {0,[{0,108}, {220,803}],[]};
unicode_table(7736) ->
    {0,[{0,76}, {220,803}, {230,772}],[]};
unicode_table(7737) ->
    {0,[{0,108}, {220,803}, {230,772}],[]};
unicode_table(7738) ->
    {0,[{0,76}, {220,817}],[]};
unicode_table(7739) ->
    {0,[{0,108}, {220,817}],[]};
unicode_table(7740) ->
    {0,[{0,76}, {220,813}],[]};
unicode_table(7741) ->
    {0,[{0,108}, {220,813}],[]};
unicode_table(7742) ->
    {0,[{0,77}, {230,769}],[]};
unicode_table(7743) ->
    {0,[{0,109}, {230,769}],[]};
unicode_table(7744) ->
    {0,[{0,77}, {230,775}],[]};
unicode_table(7745) ->
    {0,[{0,109}, {230,775}],[]};
unicode_table(7746) ->
    {0,[{0,77}, {220,803}],[]};
unicode_table(7747) ->
    {0,[{0,109}, {220,803}],[]};
unicode_table(7748) ->
    {0,[{0,78}, {230,775}],[]};
unicode_table(7749) ->
    {0,[{0,110}, {230,775}],[]};
unicode_table(7750) ->
    {0,[{0,78}, {220,803}],[]};
unicode_table(7751) ->
    {0,[{0,110}, {220,803}],[]};
unicode_table(7752) ->
    {0,[{0,78}, {220,817}],[]};
unicode_table(7753) ->
    {0,[{0,110}, {220,817}],[]};
unicode_table(7754) ->
    {0,[{0,78}, {220,813}],[]};
unicode_table(7755) ->
    {0,[{0,110}, {220,813}],[]};
unicode_table(7756) ->
    {0,[{0,79}, {230,771}, {230,769}],[]};
unicode_table(7757) ->
    {0,[{0,111}, {230,771}, {230,769}],[]};
unicode_table(7758) ->
    {0,[{0,79}, {230,771}, {230,776}],[]};
unicode_table(7759) ->
    {0,[{0,111}, {230,771}, {230,776}],[]};
unicode_table(7760) ->
    {0,[{0,79}, {230,772}, {230,768}],[]};
unicode_table(7761) ->
    {0,[{0,111}, {230,772}, {230,768}],[]};
unicode_table(7762) ->
    {0,[{0,79}, {230,772}, {230,769}],[]};
unicode_table(7763) ->
    {0,[{0,111}, {230,772}, {230,769}],[]};
unicode_table(7764) ->
    {0,[{0,80}, {230,769}],[]};
unicode_table(7765) ->
    {0,[{0,112}, {230,769}],[]};
unicode_table(7766) ->
    {0,[{0,80}, {230,775}],[]};
unicode_table(7767) ->
    {0,[{0,112}, {230,775}],[]};
unicode_table(7768) ->
    {0,[{0,82}, {230,775}],[]};
unicode_table(7769) ->
    {0,[{0,114}, {230,775}],[]};
unicode_table(7770) ->
    {0,[{0,82}, {220,803}],[]};
unicode_table(7771) ->
    {0,[{0,114}, {220,803}],[]};
unicode_table(7772) ->
    {0,[{0,82}, {220,803}, {230,772}],[]};
unicode_table(7773) ->
    {0,[{0,114}, {220,803}, {230,772}],[]};
unicode_table(7774) ->
    {0,[{0,82}, {220,817}],[]};
unicode_table(7775) ->
    {0,[{0,114}, {220,817}],[]};
unicode_table(7776) ->
    {0,[{0,83}, {230,775}],[]};
unicode_table(7777) ->
    {0,[{0,115}, {230,775}],[]};
unicode_table(7778) ->
    {0,[{0,83}, {220,803}],[]};
unicode_table(7779) ->
    {0,[{0,115}, {220,803}],[]};
unicode_table(7780) ->
    {0,[{0,83}, {230,769}, {230,775}],[]};
unicode_table(7781) ->
    {0,[{0,115}, {230,769}, {230,775}],[]};
unicode_table(7782) ->
    {0,[{0,83}, {230,780}, {230,775}],[]};
unicode_table(7783) ->
    {0,[{0,115}, {230,780}, {230,775}],[]};
unicode_table(7784) ->
    {0,[{0,83}, {220,803}, {230,775}],[]};
unicode_table(7785) ->
    {0,[{0,115}, {220,803}, {230,775}],[]};
unicode_table(7786) ->
    {0,[{0,84}, {230,775}],[]};
unicode_table(7787) ->
    {0,[{0,116}, {230,775}],[]};
unicode_table(7788) ->
    {0,[{0,84}, {220,803}],[]};
unicode_table(7789) ->
    {0,[{0,116}, {220,803}],[]};
unicode_table(7790) ->
    {0,[{0,84}, {220,817}],[]};
unicode_table(7791) ->
    {0,[{0,116}, {220,817}],[]};
unicode_table(7792) ->
    {0,[{0,84}, {220,813}],[]};
unicode_table(7793) ->
    {0,[{0,116}, {220,813}],[]};
unicode_table(7794) ->
    {0,[{0,85}, {220,804}],[]};
unicode_table(7795) ->
    {0,[{0,117}, {220,804}],[]};
unicode_table(7796) ->
    {0,[{0,85}, {220,816}],[]};
unicode_table(7797) ->
    {0,[{0,117}, {220,816}],[]};
unicode_table(7798) ->
    {0,[{0,85}, {220,813}],[]};
unicode_table(7799) ->
    {0,[{0,117}, {220,813}],[]};
unicode_table(7800) ->
    {0,[{0,85}, {230,771}, {230,769}],[]};
unicode_table(7801) ->
    {0,[{0,117}, {230,771}, {230,769}],[]};
unicode_table(7802) ->
    {0,[{0,85}, {230,772}, {230,776}],[]};
unicode_table(7803) ->
    {0,[{0,117}, {230,772}, {230,776}],[]};
unicode_table(7804) ->
    {0,[{0,86}, {230,771}],[]};
unicode_table(7805) ->
    {0,[{0,118}, {230,771}],[]};
unicode_table(7806) ->
    {0,[{0,86}, {220,803}],[]};
unicode_table(7807) ->
    {0,[{0,118}, {220,803}],[]};
unicode_table(7808) ->
    {0,[{0,87}, {230,768}],[]};
unicode_table(7809) ->
    {0,[{0,119}, {230,768}],[]};
unicode_table(7810) ->
    {0,[{0,87}, {230,769}],[]};
unicode_table(7811) ->
    {0,[{0,119}, {230,769}],[]};
unicode_table(7812) ->
    {0,[{0,87}, {230,776}],[]};
unicode_table(7813) ->
    {0,[{0,119}, {230,776}],[]};
unicode_table(7814) ->
    {0,[{0,87}, {230,775}],[]};
unicode_table(7815) ->
    {0,[{0,119}, {230,775}],[]};
unicode_table(7816) ->
    {0,[{0,87}, {220,803}],[]};
unicode_table(7817) ->
    {0,[{0,119}, {220,803}],[]};
unicode_table(7818) ->
    {0,[{0,88}, {230,775}],[]};
unicode_table(7819) ->
    {0,[{0,120}, {230,775}],[]};
unicode_table(7820) ->
    {0,[{0,88}, {230,776}],[]};
unicode_table(7821) ->
    {0,[{0,120}, {230,776}],[]};
unicode_table(7822) ->
    {0,[{0,89}, {230,775}],[]};
unicode_table(7823) ->
    {0,[{0,121}, {230,775}],[]};
unicode_table(7824) ->
    {0,[{0,90}, {230,770}],[]};
unicode_table(7825) ->
    {0,[{0,122}, {230,770}],[]};
unicode_table(7826) ->
    {0,[{0,90}, {220,803}],[]};
unicode_table(7827) ->
    {0,[{0,122}, {220,803}],[]};
unicode_table(7828) ->
    {0,[{0,90}, {220,817}],[]};
unicode_table(7829) ->
    {0,[{0,122}, {220,817}],[]};
unicode_table(7830) ->
    {0,[{0,104}, {220,817}],[]};
unicode_table(7831) ->
    {0,[{0,116}, {230,776}],[]};
unicode_table(7832) ->
    {0,[{0,119}, {230,778}],[]};
unicode_table(7833) ->
    {0,[{0,121}, {230,778}],[]};
unicode_table(7834) ->
    {0,[],{compat,[{0,97}, {0,702}]}};
unicode_table(7835) ->
    {0,[{0,383}, {230,775}],{compat,[{0,115}, {230,775}]}};
unicode_table(7840) ->
    {0,[{0,65}, {220,803}],[]};
unicode_table(7841) ->
    {0,[{0,97}, {220,803}],[]};
unicode_table(7842) ->
    {0,[{0,65}, {230,777}],[]};
unicode_table(7843) ->
    {0,[{0,97}, {230,777}],[]};
unicode_table(7844) ->
    {0,[{0,65}, {230,770}, {230,769}],[]};
unicode_table(7845) ->
    {0,[{0,97}, {230,770}, {230,769}],[]};
unicode_table(7846) ->
    {0,[{0,65}, {230,770}, {230,768}],[]};
unicode_table(7847) ->
    {0,[{0,97}, {230,770}, {230,768}],[]};
unicode_table(7848) ->
    {0,[{0,65}, {230,770}, {230,777}],[]};
unicode_table(7849) ->
    {0,[{0,97}, {230,770}, {230,777}],[]};
unicode_table(7850) ->
    {0,[{0,65}, {230,770}, {230,771}],[]};
unicode_table(7851) ->
    {0,[{0,97}, {230,770}, {230,771}],[]};
unicode_table(7852) ->
    {0,[{0,65}, {220,803}, {230,770}],[]};
unicode_table(7853) ->
    {0,[{0,97}, {220,803}, {230,770}],[]};
unicode_table(7854) ->
    {0,[{0,65}, {230,774}, {230,769}],[]};
unicode_table(7855) ->
    {0,[{0,97}, {230,774}, {230,769}],[]};
unicode_table(7856) ->
    {0,[{0,65}, {230,774}, {230,768}],[]};
unicode_table(7857) ->
    {0,[{0,97}, {230,774}, {230,768}],[]};
unicode_table(7858) ->
    {0,[{0,65}, {230,774}, {230,777}],[]};
unicode_table(7859) ->
    {0,[{0,97}, {230,774}, {230,777}],[]};
unicode_table(7860) ->
    {0,[{0,65}, {230,774}, {230,771}],[]};
unicode_table(7861) ->
    {0,[{0,97}, {230,774}, {230,771}],[]};
unicode_table(7862) ->
    {0,[{0,65}, {220,803}, {230,774}],[]};
unicode_table(7863) ->
    {0,[{0,97}, {220,803}, {230,774}],[]};
unicode_table(7864) ->
    {0,[{0,69}, {220,803}],[]};
unicode_table(7865) ->
    {0,[{0,101}, {220,803}],[]};
unicode_table(7866) ->
    {0,[{0,69}, {230,777}],[]};
unicode_table(7867) ->
    {0,[{0,101}, {230,777}],[]};
unicode_table(7868) ->
    {0,[{0,69}, {230,771}],[]};
unicode_table(7869) ->
    {0,[{0,101}, {230,771}],[]};
unicode_table(7870) ->
    {0,[{0,69}, {230,770}, {230,769}],[]};
unicode_table(7871) ->
    {0,[{0,101}, {230,770}, {230,769}],[]};
unicode_table(7872) ->
    {0,[{0,69}, {230,770}, {230,768}],[]};
unicode_table(7873) ->
    {0,[{0,101}, {230,770}, {230,768}],[]};
unicode_table(7874) ->
    {0,[{0,69}, {230,770}, {230,777}],[]};
unicode_table(7875) ->
    {0,[{0,101}, {230,770}, {230,777}],[]};
unicode_table(7876) ->
    {0,[{0,69}, {230,770}, {230,771}],[]};
unicode_table(7877) ->
    {0,[{0,101}, {230,770}, {230,771}],[]};
unicode_table(7878) ->
    {0,[{0,69}, {220,803}, {230,770}],[]};
unicode_table(7879) ->
    {0,[{0,101}, {220,803}, {230,770}],[]};
unicode_table(7880) ->
    {0,[{0,73}, {230,777}],[]};
unicode_table(7881) ->
    {0,[{0,105}, {230,777}],[]};
unicode_table(7882) ->
    {0,[{0,73}, {220,803}],[]};
unicode_table(7883) ->
    {0,[{0,105}, {220,803}],[]};
unicode_table(7884) ->
    {0,[{0,79}, {220,803}],[]};
unicode_table(7885) ->
    {0,[{0,111}, {220,803}],[]};
unicode_table(7886) ->
    {0,[{0,79}, {230,777}],[]};
unicode_table(7887) ->
    {0,[{0,111}, {230,777}],[]};
unicode_table(7888) ->
    {0,[{0,79}, {230,770}, {230,769}],[]};
unicode_table(7889) ->
    {0,[{0,111}, {230,770}, {230,769}],[]};
unicode_table(7890) ->
    {0,[{0,79}, {230,770}, {230,768}],[]};
unicode_table(7891) ->
    {0,[{0,111}, {230,770}, {230,768}],[]};
unicode_table(7892) ->
    {0,[{0,79}, {230,770}, {230,777}],[]};
unicode_table(7893) ->
    {0,[{0,111}, {230,770}, {230,777}],[]};
unicode_table(7894) ->
    {0,[{0,79}, {230,770}, {230,771}],[]};
unicode_table(7895) ->
    {0,[{0,111}, {230,770}, {230,771}],[]};
unicode_table(7896) ->
    {0,[{0,79}, {220,803}, {230,770}],[]};
unicode_table(7897) ->
    {0,[{0,111}, {220,803}, {230,770}],[]};
unicode_table(7898) ->
    {0,[{0,79}, {216,795}, {230,769}],[]};
unicode_table(7899) ->
    {0,[{0,111}, {216,795}, {230,769}],[]};
unicode_table(7900) ->
    {0,[{0,79}, {216,795}, {230,768}],[]};
unicode_table(7901) ->
    {0,[{0,111}, {216,795}, {230,768}],[]};
unicode_table(7902) ->
    {0,[{0,79}, {216,795}, {230,777}],[]};
unicode_table(7903) ->
    {0,[{0,111}, {216,795}, {230,777}],[]};
unicode_table(7904) ->
    {0,[{0,79}, {216,795}, {230,771}],[]};
unicode_table(7905) ->
    {0,[{0,111}, {216,795}, {230,771}],[]};
unicode_table(7906) ->
    {0,[{0,79}, {216,795}, {220,803}],[]};
unicode_table(7907) ->
    {0,[{0,111}, {216,795}, {220,803}],[]};
unicode_table(7908) ->
    {0,[{0,85}, {220,803}],[]};
unicode_table(7909) ->
    {0,[{0,117}, {220,803}],[]};
unicode_table(7910) ->
    {0,[{0,85}, {230,777}],[]};
unicode_table(7911) ->
    {0,[{0,117}, {230,777}],[]};
unicode_table(7912) ->
    {0,[{0,85}, {216,795}, {230,769}],[]};
unicode_table(7913) ->
    {0,[{0,117}, {216,795}, {230,769}],[]};
unicode_table(7914) ->
    {0,[{0,85}, {216,795}, {230,768}],[]};
unicode_table(7915) ->
    {0,[{0,117}, {216,795}, {230,768}],[]};
unicode_table(7916) ->
    {0,[{0,85}, {216,795}, {230,777}],[]};
unicode_table(7917) ->
    {0,[{0,117}, {216,795}, {230,777}],[]};
unicode_table(7918) ->
    {0,[{0,85}, {216,795}, {230,771}],[]};
unicode_table(7919) ->
    {0,[{0,117}, {216,795}, {230,771}],[]};
unicode_table(7920) ->
    {0,[{0,85}, {216,795}, {220,803}],[]};
unicode_table(7921) ->
    {0,[{0,117}, {216,795}, {220,803}],[]};
unicode_table(7922) ->
    {0,[{0,89}, {230,768}],[]};
unicode_table(7923) ->
    {0,[{0,121}, {230,768}],[]};
unicode_table(7924) ->
    {0,[{0,89}, {220,803}],[]};
unicode_table(7925) ->
    {0,[{0,121}, {220,803}],[]};
unicode_table(7926) ->
    {0,[{0,89}, {230,777}],[]};
unicode_table(7927) ->
    {0,[{0,121}, {230,777}],[]};
unicode_table(7928) ->
    {0,[{0,89}, {230,771}],[]};
unicode_table(7929) ->
    {0,[{0,121}, {230,771}],[]};
unicode_table(7936) ->
    {0,[{0,945}, {230,787}],[]};
unicode_table(7937) ->
    {0,[{0,945}, {230,788}],[]};
unicode_table(7938) ->
    {0,[{0,945}, {230,787}, {230,768}],[]};
unicode_table(7939) ->
    {0,[{0,945}, {230,788}, {230,768}],[]};
unicode_table(7940) ->
    {0,[{0,945}, {230,787}, {230,769}],[]};
unicode_table(7941) ->
    {0,[{0,945}, {230,788}, {230,769}],[]};
unicode_table(7942) ->
    {0,[{0,945}, {230,787}, {230,834}],[]};
unicode_table(7943) ->
    {0,[{0,945}, {230,788}, {230,834}],[]};
unicode_table(7944) ->
    {0,[{0,913}, {230,787}],[]};
unicode_table(7945) ->
    {0,[{0,913}, {230,788}],[]};
unicode_table(7946) ->
    {0,[{0,913}, {230,787}, {230,768}],[]};
unicode_table(7947) ->
    {0,[{0,913}, {230,788}, {230,768}],[]};
unicode_table(7948) ->
    {0,[{0,913}, {230,787}, {230,769}],[]};
unicode_table(7949) ->
    {0,[{0,913}, {230,788}, {230,769}],[]};
unicode_table(7950) ->
    {0,[{0,913}, {230,787}, {230,834}],[]};
unicode_table(7951) ->
    {0,[{0,913}, {230,788}, {230,834}],[]};
unicode_table(7952) ->
    {0,[{0,949}, {230,787}],[]};
unicode_table(7953) ->
    {0,[{0,949}, {230,788}],[]};
unicode_table(7954) ->
    {0,[{0,949}, {230,787}, {230,768}],[]};
unicode_table(7955) ->
    {0,[{0,949}, {230,788}, {230,768}],[]};
unicode_table(7956) ->
    {0,[{0,949}, {230,787}, {230,769}],[]};
unicode_table(7957) ->
    {0,[{0,949}, {230,788}, {230,769}],[]};
unicode_table(7960) ->
    {0,[{0,917}, {230,787}],[]};
unicode_table(7961) ->
    {0,[{0,917}, {230,788}],[]};
unicode_table(7962) ->
    {0,[{0,917}, {230,787}, {230,768}],[]};
unicode_table(7963) ->
    {0,[{0,917}, {230,788}, {230,768}],[]};
unicode_table(7964) ->
    {0,[{0,917}, {230,787}, {230,769}],[]};
unicode_table(7965) ->
    {0,[{0,917}, {230,788}, {230,769}],[]};
unicode_table(7968) ->
    {0,[{0,951}, {230,787}],[]};
unicode_table(7969) ->
    {0,[{0,951}, {230,788}],[]};
unicode_table(7970) ->
    {0,[{0,951}, {230,787}, {230,768}],[]};
unicode_table(7971) ->
    {0,[{0,951}, {230,788}, {230,768}],[]};
unicode_table(7972) ->
    {0,[{0,951}, {230,787}, {230,769}],[]};
unicode_table(7973) ->
    {0,[{0,951}, {230,788}, {230,769}],[]};
unicode_table(7974) ->
    {0,[{0,951}, {230,787}, {230,834}],[]};
unicode_table(7975) ->
    {0,[{0,951}, {230,788}, {230,834}],[]};
unicode_table(7976) ->
    {0,[{0,919}, {230,787}],[]};
unicode_table(7977) ->
    {0,[{0,919}, {230,788}],[]};
unicode_table(7978) ->
    {0,[{0,919}, {230,787}, {230,768}],[]};
unicode_table(7979) ->
    {0,[{0,919}, {230,788}, {230,768}],[]};
unicode_table(7980) ->
    {0,[{0,919}, {230,787}, {230,769}],[]};
unicode_table(7981) ->
    {0,[{0,919}, {230,788}, {230,769}],[]};
unicode_table(7982) ->
    {0,[{0,919}, {230,787}, {230,834}],[]};
unicode_table(7983) ->
    {0,[{0,919}, {230,788}, {230,834}],[]};
unicode_table(7984) ->
    {0,[{0,953}, {230,787}],[]};
unicode_table(7985) ->
    {0,[{0,953}, {230,788}],[]};
unicode_table(7986) ->
    {0,[{0,953}, {230,787}, {230,768}],[]};
unicode_table(7987) ->
    {0,[{0,953}, {230,788}, {230,768}],[]};
unicode_table(7988) ->
    {0,[{0,953}, {230,787}, {230,769}],[]};
unicode_table(7989) ->
    {0,[{0,953}, {230,788}, {230,769}],[]};
unicode_table(7990) ->
    {0,[{0,953}, {230,787}, {230,834}],[]};
unicode_table(7991) ->
    {0,[{0,953}, {230,788}, {230,834}],[]};
unicode_table(7992) ->
    {0,[{0,921}, {230,787}],[]};
unicode_table(7993) ->
    {0,[{0,921}, {230,788}],[]};
unicode_table(7994) ->
    {0,[{0,921}, {230,787}, {230,768}],[]};
unicode_table(7995) ->
    {0,[{0,921}, {230,788}, {230,768}],[]};
unicode_table(7996) ->
    {0,[{0,921}, {230,787}, {230,769}],[]};
unicode_table(7997) ->
    {0,[{0,921}, {230,788}, {230,769}],[]};
unicode_table(7998) ->
    {0,[{0,921}, {230,787}, {230,834}],[]};
unicode_table(7999) ->
    {0,[{0,921}, {230,788}, {230,834}],[]};
unicode_table(8000) ->
    {0,[{0,959}, {230,787}],[]};
unicode_table(8001) ->
    {0,[{0,959}, {230,788}],[]};
unicode_table(8002) ->
    {0,[{0,959}, {230,787}, {230,768}],[]};
unicode_table(8003) ->
    {0,[{0,959}, {230,788}, {230,768}],[]};
unicode_table(8004) ->
    {0,[{0,959}, {230,787}, {230,769}],[]};
unicode_table(8005) ->
    {0,[{0,959}, {230,788}, {230,769}],[]};
unicode_table(8008) ->
    {0,[{0,927}, {230,787}],[]};
unicode_table(8009) ->
    {0,[{0,927}, {230,788}],[]};
unicode_table(8010) ->
    {0,[{0,927}, {230,787}, {230,768}],[]};
unicode_table(8011) ->
    {0,[{0,927}, {230,788}, {230,768}],[]};
unicode_table(8012) ->
    {0,[{0,927}, {230,787}, {230,769}],[]};
unicode_table(8013) ->
    {0,[{0,927}, {230,788}, {230,769}],[]};
unicode_table(8016) ->
    {0,[{0,965}, {230,787}],[]};
unicode_table(8017) ->
    {0,[{0,965}, {230,788}],[]};
unicode_table(8018) ->
    {0,[{0,965}, {230,787}, {230,768}],[]};
unicode_table(8019) ->
    {0,[{0,965}, {230,788}, {230,768}],[]};
unicode_table(8020) ->
    {0,[{0,965}, {230,787}, {230,769}],[]};
unicode_table(8021) ->
    {0,[{0,965}, {230,788}, {230,769}],[]};
unicode_table(8022) ->
    {0,[{0,965}, {230,787}, {230,834}],[]};
unicode_table(8023) ->
    {0,[{0,965}, {230,788}, {230,834}],[]};
unicode_table(8025) ->
    {0,[{0,933}, {230,788}],[]};
unicode_table(8027) ->
    {0,[{0,933}, {230,788}, {230,768}],[]};
unicode_table(8029) ->
    {0,[{0,933}, {230,788}, {230,769}],[]};
unicode_table(8031) ->
    {0,[{0,933}, {230,788}, {230,834}],[]};
unicode_table(8032) ->
    {0,[{0,969}, {230,787}],[]};
unicode_table(8033) ->
    {0,[{0,969}, {230,788}],[]};
unicode_table(8034) ->
    {0,[{0,969}, {230,787}, {230,768}],[]};
unicode_table(8035) ->
    {0,[{0,969}, {230,788}, {230,768}],[]};
unicode_table(8036) ->
    {0,[{0,969}, {230,787}, {230,769}],[]};
unicode_table(8037) ->
    {0,[{0,969}, {230,788}, {230,769}],[]};
unicode_table(8038) ->
    {0,[{0,969}, {230,787}, {230,834}],[]};
unicode_table(8039) ->
    {0,[{0,969}, {230,788}, {230,834}],[]};
unicode_table(8040) ->
    {0,[{0,937}, {230,787}],[]};
unicode_table(8041) ->
    {0,[{0,937}, {230,788}],[]};
unicode_table(8042) ->
    {0,[{0,937}, {230,787}, {230,768}],[]};
unicode_table(8043) ->
    {0,[{0,937}, {230,788}, {230,768}],[]};
unicode_table(8044) ->
    {0,[{0,937}, {230,787}, {230,769}],[]};
unicode_table(8045) ->
    {0,[{0,937}, {230,788}, {230,769}],[]};
unicode_table(8046) ->
    {0,[{0,937}, {230,787}, {230,834}],[]};
unicode_table(8047) ->
    {0,[{0,937}, {230,788}, {230,834}],[]};
unicode_table(8048) ->
    {0,[{0,945}, {230,768}],[]};
unicode_table(8049) ->
    {0,[{0,945}, {230,769}],[]};
unicode_table(8050) ->
    {0,[{0,949}, {230,768}],[]};
unicode_table(8051) ->
    {0,[{0,949}, {230,769}],[]};
unicode_table(8052) ->
    {0,[{0,951}, {230,768}],[]};
unicode_table(8053) ->
    {0,[{0,951}, {230,769}],[]};
unicode_table(8054) ->
    {0,[{0,953}, {230,768}],[]};
unicode_table(8055) ->
    {0,[{0,953}, {230,769}],[]};
unicode_table(8056) ->
    {0,[{0,959}, {230,768}],[]};
unicode_table(8057) ->
    {0,[{0,959}, {230,769}],[]};
unicode_table(8058) ->
    {0,[{0,965}, {230,768}],[]};
unicode_table(8059) ->
    {0,[{0,965}, {230,769}],[]};
unicode_table(8060) ->
    {0,[{0,969}, {230,768}],[]};
unicode_table(8061) ->
    {0,[{0,969}, {230,769}],[]};
unicode_table(8064) ->
    {0,[{0,945}, {230,787}, {240,837}],[]};
unicode_table(8065) ->
    {0,[{0,945}, {230,788}, {240,837}],[]};
unicode_table(8066) ->
    {0,[{0,945}, {230,787}, {230,768}, {240,837}],[]};
unicode_table(8067) ->
    {0,[{0,945}, {230,788}, {230,768}, {240,837}],[]};
unicode_table(8068) ->
    {0,[{0,945}, {230,787}, {230,769}, {240,837}],[]};
unicode_table(8069) ->
    {0,[{0,945}, {230,788}, {230,769}, {240,837}],[]};
unicode_table(8070) ->
    {0,[{0,945}, {230,787}, {230,834}, {240,837}],[]};
unicode_table(8071) ->
    {0,[{0,945}, {230,788}, {230,834}, {240,837}],[]};
unicode_table(8072) ->
    {0,[{0,913}, {230,787}, {240,837}],[]};
unicode_table(8073) ->
    {0,[{0,913}, {230,788}, {240,837}],[]};
unicode_table(8074) ->
    {0,[{0,913}, {230,787}, {230,768}, {240,837}],[]};
unicode_table(8075) ->
    {0,[{0,913}, {230,788}, {230,768}, {240,837}],[]};
unicode_table(8076) ->
    {0,[{0,913}, {230,787}, {230,769}, {240,837}],[]};
unicode_table(8077) ->
    {0,[{0,913}, {230,788}, {230,769}, {240,837}],[]};
unicode_table(8078) ->
    {0,[{0,913}, {230,787}, {230,834}, {240,837}],[]};
unicode_table(8079) ->
    {0,[{0,913}, {230,788}, {230,834}, {240,837}],[]};
unicode_table(8080) ->
    {0,[{0,951}, {230,787}, {240,837}],[]};
unicode_table(8081) ->
    {0,[{0,951}, {230,788}, {240,837}],[]};
unicode_table(8082) ->
    {0,[{0,951}, {230,787}, {230,768}, {240,837}],[]};
unicode_table(8083) ->
    {0,[{0,951}, {230,788}, {230,768}, {240,837}],[]};
unicode_table(8084) ->
    {0,[{0,951}, {230,787}, {230,769}, {240,837}],[]};
unicode_table(8085) ->
    {0,[{0,951}, {230,788}, {230,769}, {240,837}],[]};
unicode_table(8086) ->
    {0,[{0,951}, {230,787}, {230,834}, {240,837}],[]};
unicode_table(8087) ->
    {0,[{0,951}, {230,788}, {230,834}, {240,837}],[]};
unicode_table(8088) ->
    {0,[{0,919}, {230,787}, {240,837}],[]};
unicode_table(8089) ->
    {0,[{0,919}, {230,788}, {240,837}],[]};
unicode_table(8090) ->
    {0,[{0,919}, {230,787}, {230,768}, {240,837}],[]};
unicode_table(8091) ->
    {0,[{0,919}, {230,788}, {230,768}, {240,837}],[]};
unicode_table(8092) ->
    {0,[{0,919}, {230,787}, {230,769}, {240,837}],[]};
unicode_table(8093) ->
    {0,[{0,919}, {230,788}, {230,769}, {240,837}],[]};
unicode_table(8094) ->
    {0,[{0,919}, {230,787}, {230,834}, {240,837}],[]};
unicode_table(8095) ->
    {0,[{0,919}, {230,788}, {230,834}, {240,837}],[]};
unicode_table(8096) ->
    {0,[{0,969}, {230,787}, {240,837}],[]};
unicode_table(8097) ->
    {0,[{0,969}, {230,788}, {240,837}],[]};
unicode_table(8098) ->
    {0,[{0,969}, {230,787}, {230,768}, {240,837}],[]};
unicode_table(8099) ->
    {0,[{0,969}, {230,788}, {230,768}, {240,837}],[]};
unicode_table(8100) ->
    {0,[{0,969}, {230,787}, {230,769}, {240,837}],[]};
unicode_table(8101) ->
    {0,[{0,969}, {230,788}, {230,769}, {240,837}],[]};
unicode_table(8102) ->
    {0,[{0,969}, {230,787}, {230,834}, {240,837}],[]};
unicode_table(8103) ->
    {0,[{0,969}, {230,788}, {230,834}, {240,837}],[]};
unicode_table(8104) ->
    {0,[{0,937}, {230,787}, {240,837}],[]};
unicode_table(8105) ->
    {0,[{0,937}, {230,788}, {240,837}],[]};
unicode_table(8106) ->
    {0,[{0,937}, {230,787}, {230,768}, {240,837}],[]};
unicode_table(8107) ->
    {0,[{0,937}, {230,788}, {230,768}, {240,837}],[]};
unicode_table(8108) ->
    {0,[{0,937}, {230,787}, {230,769}, {240,837}],[]};
unicode_table(8109) ->
    {0,[{0,937}, {230,788}, {230,769}, {240,837}],[]};
unicode_table(8110) ->
    {0,[{0,937}, {230,787}, {230,834}, {240,837}],[]};
unicode_table(8111) ->
    {0,[{0,937}, {230,788}, {230,834}, {240,837}],[]};
unicode_table(8112) ->
    {0,[{0,945}, {230,774}],[]};
unicode_table(8113) ->
    {0,[{0,945}, {230,772}],[]};
unicode_table(8114) ->
    {0,[{0,945}, {230,768}, {240,837}],[]};
unicode_table(8115) ->
    {0,[{0,945}, {240,837}],[]};
unicode_table(8116) ->
    {0,[{0,945}, {230,769}, {240,837}],[]};
unicode_table(8118) ->
    {0,[{0,945}, {230,834}],[]};
unicode_table(8119) ->
    {0,[{0,945}, {230,834}, {240,837}],[]};
unicode_table(8120) ->
    {0,[{0,913}, {230,774}],[]};
unicode_table(8121) ->
    {0,[{0,913}, {230,772}],[]};
unicode_table(8122) ->
    {0,[{0,913}, {230,768}],[]};
unicode_table(8123) ->
    {0,[{0,913}, {230,769}],[]};
unicode_table(8124) ->
    {0,[{0,913}, {240,837}],[]};
unicode_table(8125) ->
    {0,[],{compat,[{0,32}, {230,787}]}};
unicode_table(8126) ->
    {0,[{0,953}],[]};
unicode_table(8127) ->
    {0,[],{compat,[{0,32}, {230,787}]}};
unicode_table(8128) ->
    {0,[],{compat,[{0,32}, {230,834}]}};
unicode_table(8129) ->
    {0,[{0,168}, {230,834}],{compat,[{0,32}, {230,776}, {230,834}]}};
unicode_table(8130) ->
    {0,[{0,951}, {230,768}, {240,837}],[]};
unicode_table(8131) ->
    {0,[{0,951}, {240,837}],[]};
unicode_table(8132) ->
    {0,[{0,951}, {230,769}, {240,837}],[]};
unicode_table(8134) ->
    {0,[{0,951}, {230,834}],[]};
unicode_table(8135) ->
    {0,[{0,951}, {230,834}, {240,837}],[]};
unicode_table(8136) ->
    {0,[{0,917}, {230,768}],[]};
unicode_table(8137) ->
    {0,[{0,917}, {230,769}],[]};
unicode_table(8138) ->
    {0,[{0,919}, {230,768}],[]};
unicode_table(8139) ->
    {0,[{0,919}, {230,769}],[]};
unicode_table(8140) ->
    {0,[{0,919}, {240,837}],[]};
unicode_table(8141) ->
    {0,[{0,8127}, {230,768}],{compat,[{0,32}, {230,787}, {230,768}]}};
unicode_table(8142) ->
    {0,[{0,8127}, {230,769}],{compat,[{0,32}, {230,787}, {230,769}]}};
unicode_table(8143) ->
    {0,[{0,8127}, {230,834}],{compat,[{0,32}, {230,787}, {230,834}]}};
unicode_table(8144) ->
    {0,[{0,953}, {230,774}],[]};
unicode_table(8145) ->
    {0,[{0,953}, {230,772}],[]};
unicode_table(8146) ->
    {0,[{0,953}, {230,776}, {230,768}],[]};
unicode_table(8147) ->
    {0,[{0,953}, {230,776}, {230,769}],[]};
unicode_table(8150) ->
    {0,[{0,953}, {230,834}],[]};
unicode_table(8151) ->
    {0,[{0,953}, {230,776}, {230,834}],[]};
unicode_table(8152) ->
    {0,[{0,921}, {230,774}],[]};
unicode_table(8153) ->
    {0,[{0,921}, {230,772}],[]};
unicode_table(8154) ->
    {0,[{0,921}, {230,768}],[]};
unicode_table(8155) ->
    {0,[{0,921}, {230,769}],[]};
unicode_table(8157) ->
    {0,[{0,8190}, {230,768}],{compat,[{0,32}, {230,788}, {230,768}]}};
unicode_table(8158) ->
    {0,[{0,8190}, {230,769}],{compat,[{0,32}, {230,788}, {230,769}]}};
unicode_table(8159) ->
    {0,[{0,8190}, {230,834}],{compat,[{0,32}, {230,788}, {230,834}]}};
unicode_table(8160) ->
    {0,[{0,965}, {230,774}],[]};
unicode_table(8161) ->
    {0,[{0,965}, {230,772}],[]};
unicode_table(8162) ->
    {0,[{0,965}, {230,776}, {230,768}],[]};
unicode_table(8163) ->
    {0,[{0,965}, {230,776}, {230,769}],[]};
unicode_table(8164) ->
    {0,[{0,961}, {230,787}],[]};
unicode_table(8165) ->
    {0,[{0,961}, {230,788}],[]};
unicode_table(8166) ->
    {0,[{0,965}, {230,834}],[]};
unicode_table(8167) ->
    {0,[{0,965}, {230,776}, {230,834}],[]};
unicode_table(8168) ->
    {0,[{0,933}, {230,774}],[]};
unicode_table(8169) ->
    {0,[{0,933}, {230,772}],[]};
unicode_table(8170) ->
    {0,[{0,933}, {230,768}],[]};
unicode_table(8171) ->
    {0,[{0,933}, {230,769}],[]};
unicode_table(8172) ->
    {0,[{0,929}, {230,788}],[]};
unicode_table(8173) ->
    {0,[{0,168}, {230,768}],{compat,[{0,32}, {230,776}, {230,768}]}};
unicode_table(8174) ->
    {0,[{0,168}, {230,769}],{compat,[{0,32}, {230,776}, {230,769}]}};
unicode_table(8175) ->
    {0,[{0,96}],[]};
unicode_table(8178) ->
    {0,[{0,969}, {230,768}, {240,837}],[]};
unicode_table(8179) ->
    {0,[{0,969}, {240,837}],[]};
unicode_table(8180) ->
    {0,[{0,969}, {230,769}, {240,837}],[]};
unicode_table(8182) ->
    {0,[{0,969}, {230,834}],[]};
unicode_table(8183) ->
    {0,[{0,969}, {230,834}, {240,837}],[]};
unicode_table(8184) ->
    {0,[{0,927}, {230,768}],[]};
unicode_table(8185) ->
    {0,[{0,927}, {230,769}],[]};
unicode_table(8186) ->
    {0,[{0,937}, {230,768}],[]};
unicode_table(8187) ->
    {0,[{0,937}, {230,769}],[]};
unicode_table(8188) ->
    {0,[{0,937}, {240,837}],[]};
unicode_table(8189) ->
    {0,[{0,180}],{compat,[{0,32}, {230,769}]}};
unicode_table(8190) ->
    {0,[],{compat,[{0,32}, {230,788}]}};
unicode_table(8192) ->
    {0,[{0,8194}],{compat,[{0,32}]}};
unicode_table(8193) ->
    {0,[{0,8195}],{compat,[{0,32}]}};
unicode_table(8194) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8195) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8196) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8197) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8198) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8199) ->
    {0,[],{noBreak,[{0,32}]}};
unicode_table(8200) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8201) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8202) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8209) ->
    {0,[],{noBreak,[{0,8208}]}};
unicode_table(8215) ->
    {0,[],{compat,[{0,32}, {220,819}]}};
unicode_table(8228) ->
    {0,[],{compat,[{0,46}]}};
unicode_table(8229) ->
    {0,[],{compat,[{0,46}, {0,46}]}};
unicode_table(8230) ->
    {0,[],{compat,[{0,46}, {0,46}, {0,46}]}};
unicode_table(8239) ->
    {0,[],{noBreak,[{0,32}]}};
unicode_table(8243) ->
    {0,[],{compat,[{0,8242}, {0,8242}]}};
unicode_table(8244) ->
    {0,[],{compat,[{0,8242}, {0,8242}, {0,8242}]}};
unicode_table(8246) ->
    {0,[],{compat,[{0,8245}, {0,8245}]}};
unicode_table(8247) ->
    {0,[],{compat,[{0,8245}, {0,8245}, {0,8245}]}};
unicode_table(8252) ->
    {0,[],{compat,[{0,33}, {0,33}]}};
unicode_table(8254) ->
    {0,[],{compat,[{0,32}, {230,773}]}};
unicode_table(8263) ->
    {0,[],{compat,[{0,63}, {0,63}]}};
unicode_table(8264) ->
    {0,[],{compat,[{0,63}, {0,33}]}};
unicode_table(8265) ->
    {0,[],{compat,[{0,33}, {0,63}]}};
unicode_table(8279) ->
    {0,[],{compat,[{0,8242}, {0,8242}, {0,8242}, {0,8242}]}};
unicode_table(8287) ->
    {0,[],{compat,[{0,32}]}};
unicode_table(8304) ->
    {0,[],{super,[{0,48}]}};
unicode_table(8305) ->
    {0,[],{super,[{0,105}]}};
unicode_table(8308) ->
    {0,[],{super,[{0,52}]}};
unicode_table(8309) ->
    {0,[],{super,[{0,53}]}};
unicode_table(8310) ->
    {0,[],{super,[{0,54}]}};
unicode_table(8311) ->
    {0,[],{super,[{0,55}]}};
unicode_table(8312) ->
    {0,[],{super,[{0,56}]}};
unicode_table(8313) ->
    {0,[],{super,[{0,57}]}};
unicode_table(8314) ->
    {0,[],{super,[{0,43}]}};
unicode_table(8315) ->
    {0,[],{super,[{0,8722}]}};
unicode_table(8316) ->
    {0,[],{super,[{0,61}]}};
unicode_table(8317) ->
    {0,[],{super,[{0,40}]}};
unicode_table(8318) ->
    {0,[],{super,[{0,41}]}};
unicode_table(8319) ->
    {0,[],{super,[{0,110}]}};
unicode_table(8320) ->
    {0,[],{sub,[{0,48}]}};
unicode_table(8321) ->
    {0,[],{sub,[{0,49}]}};
unicode_table(8322) ->
    {0,[],{sub,[{0,50}]}};
unicode_table(8323) ->
    {0,[],{sub,[{0,51}]}};
unicode_table(8324) ->
    {0,[],{sub,[{0,52}]}};
unicode_table(8325) ->
    {0,[],{sub,[{0,53}]}};
unicode_table(8326) ->
    {0,[],{sub,[{0,54}]}};
unicode_table(8327) ->
    {0,[],{sub,[{0,55}]}};
unicode_table(8328) ->
    {0,[],{sub,[{0,56}]}};
unicode_table(8329) ->
    {0,[],{sub,[{0,57}]}};
unicode_table(8330) ->
    {0,[],{sub,[{0,43}]}};
unicode_table(8331) ->
    {0,[],{sub,[{0,8722}]}};
unicode_table(8332) ->
    {0,[],{sub,[{0,61}]}};
unicode_table(8333) ->
    {0,[],{sub,[{0,40}]}};
unicode_table(8334) ->
    {0,[],{sub,[{0,41}]}};
unicode_table(8336) ->
    {0,[],{sub,[{0,97}]}};
unicode_table(8337) ->
    {0,[],{sub,[{0,101}]}};
unicode_table(8338) ->
    {0,[],{sub,[{0,111}]}};
unicode_table(8339) ->
    {0,[],{sub,[{0,120}]}};
unicode_table(8340) ->
    {0,[],{sub,[{0,601}]}};
unicode_table(8341) ->
    {0,[],{sub,[{0,104}]}};
unicode_table(8342) ->
    {0,[],{sub,[{0,107}]}};
unicode_table(8343) ->
    {0,[],{sub,[{0,108}]}};
unicode_table(8344) ->
    {0,[],{sub,[{0,109}]}};
unicode_table(8345) ->
    {0,[],{sub,[{0,110}]}};
unicode_table(8346) ->
    {0,[],{sub,[{0,112}]}};
unicode_table(8347) ->
    {0,[],{sub,[{0,115}]}};
unicode_table(8348) ->
    {0,[],{sub,[{0,116}]}};
unicode_table(8360) ->
    {0,[],{compat,[{0,82}, {0,115}]}};
unicode_table(8400) ->
    {230,[],[]};
unicode_table(8401) ->
    {230,[],[]};
unicode_table(8402) ->
    {1,[],[]};
unicode_table(8403) ->
    {1,[],[]};
unicode_table(8404) ->
    {230,[],[]};
unicode_table(8405) ->
    {230,[],[]};
unicode_table(8406) ->
    {230,[],[]};
unicode_table(8407) ->
    {230,[],[]};
unicode_table(8408) ->
    {1,[],[]};
unicode_table(8409) ->
    {1,[],[]};
unicode_table(8410) ->
    {1,[],[]};
unicode_table(8411) ->
    {230,[],[]};
unicode_table(8412) ->
    {230,[],[]};
unicode_table(8417) ->
    {230,[],[]};
unicode_table(8421) ->
    {1,[],[]};
unicode_table(8422) ->
    {1,[],[]};
unicode_table(8423) ->
    {230,[],[]};
unicode_table(8424) ->
    {220,[],[]};
unicode_table(8425) ->
    {230,[],[]};
unicode_table(8426) ->
    {1,[],[]};
unicode_table(8427) ->
    {1,[],[]};
unicode_table(8428) ->
    {220,[],[]};
unicode_table(8429) ->
    {220,[],[]};
unicode_table(8430) ->
    {220,[],[]};
unicode_table(8431) ->
    {220,[],[]};
unicode_table(8432) ->
    {230,[],[]};
unicode_table(8448) ->
    {0,[],{compat,[{0,97}, {0,47}, {0,99}]}};
unicode_table(8449) ->
    {0,[],{compat,[{0,97}, {0,47}, {0,115}]}};
unicode_table(8450) ->
    {0,[],{font,[{0,67}]}};
unicode_table(8451) ->
    {0,[],{compat,[{0,176}, {0,67}]}};
unicode_table(8453) ->
    {0,[],{compat,[{0,99}, {0,47}, {0,111}]}};
unicode_table(8454) ->
    {0,[],{compat,[{0,99}, {0,47}, {0,117}]}};
unicode_table(8455) ->
    {0,[],{compat,[{0,400}]}};
unicode_table(8457) ->
    {0,[],{compat,[{0,176}, {0,70}]}};
unicode_table(8458) ->
    {0,[],{font,[{0,103}]}};
unicode_table(8459) ->
    {0,[],{font,[{0,72}]}};
unicode_table(8460) ->
    {0,[],{font,[{0,72}]}};
unicode_table(8461) ->
    {0,[],{font,[{0,72}]}};
unicode_table(8462) ->
    {0,[],{font,[{0,104}]}};
unicode_table(8463) ->
    {0,[],{font,[{0,295}]}};
unicode_table(8464) ->
    {0,[],{font,[{0,73}]}};
unicode_table(8465) ->
    {0,[],{font,[{0,73}]}};
unicode_table(8466) ->
    {0,[],{font,[{0,76}]}};
unicode_table(8467) ->
    {0,[],{font,[{0,108}]}};
unicode_table(8469) ->
    {0,[],{font,[{0,78}]}};
unicode_table(8470) ->
    {0,[],{compat,[{0,78}, {0,111}]}};
unicode_table(8473) ->
    {0,[],{font,[{0,80}]}};
unicode_table(8474) ->
    {0,[],{font,[{0,81}]}};
unicode_table(8475) ->
    {0,[],{font,[{0,82}]}};
unicode_table(8476) ->
    {0,[],{font,[{0,82}]}};
unicode_table(8477) ->
    {0,[],{font,[{0,82}]}};
unicode_table(8480) ->
    {0,[],{super,[{0,83}, {0,77}]}};
unicode_table(8481) ->
    {0,[],{compat,[{0,84}, {0,69}, {0,76}]}};
unicode_table(8482) ->
    {0,[],{super,[{0,84}, {0,77}]}};
unicode_table(8484) ->
    {0,[],{font,[{0,90}]}};
unicode_table(8486) ->
    {0,[{0,937}],[]};
unicode_table(8488) ->
    {0,[],{font,[{0,90}]}};
unicode_table(8490) ->
    {0,[{0,75}],[]};
unicode_table(8491) ->
    {0,[{0,65}, {230,778}],[]};
unicode_table(8492) ->
    {0,[],{font,[{0,66}]}};
unicode_table(8493) ->
    {0,[],{font,[{0,67}]}};
unicode_table(8495) ->
    {0,[],{font,[{0,101}]}};
unicode_table(8496) ->
    {0,[],{font,[{0,69}]}};
unicode_table(8497) ->
    {0,[],{font,[{0,70}]}};
unicode_table(8499) ->
    {0,[],{font,[{0,77}]}};
unicode_table(8500) ->
    {0,[],{font,[{0,111}]}};
unicode_table(8501) ->
    {0,[],{compat,[{0,1488}]}};
unicode_table(8502) ->
    {0,[],{compat,[{0,1489}]}};
unicode_table(8503) ->
    {0,[],{compat,[{0,1490}]}};
unicode_table(8504) ->
    {0,[],{compat,[{0,1491}]}};
unicode_table(8505) ->
    {0,[],{font,[{0,105}]}};
unicode_table(8507) ->
    {0,[],{compat,[{0,70}, {0,65}, {0,88}]}};
unicode_table(8508) ->
    {0,[],{font,[{0,960}]}};
unicode_table(8509) ->
    {0,[],{font,[{0,947}]}};
unicode_table(8510) ->
    {0,[],{font,[{0,915}]}};
unicode_table(8511) ->
    {0,[],{font,[{0,928}]}};
unicode_table(8512) ->
    {0,[],{font,[{0,8721}]}};
unicode_table(8517) ->
    {0,[],{font,[{0,68}]}};
unicode_table(8518) ->
    {0,[],{font,[{0,100}]}};
unicode_table(8519) ->
    {0,[],{font,[{0,101}]}};
unicode_table(8520) ->
    {0,[],{font,[{0,105}]}};
unicode_table(8521) ->
    {0,[],{font,[{0,106}]}};
unicode_table(8528) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,55}]}};
unicode_table(8529) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,57}]}};
unicode_table(8530) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,49}, {0,48}]}};
unicode_table(8531) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,51}]}};
unicode_table(8532) ->
    {0,[],{fraction,[{0,50}, {0,8260}, {0,51}]}};
unicode_table(8533) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,53}]}};
unicode_table(8534) ->
    {0,[],{fraction,[{0,50}, {0,8260}, {0,53}]}};
unicode_table(8535) ->
    {0,[],{fraction,[{0,51}, {0,8260}, {0,53}]}};
unicode_table(8536) ->
    {0,[],{fraction,[{0,52}, {0,8260}, {0,53}]}};
unicode_table(8537) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,54}]}};
unicode_table(8538) ->
    {0,[],{fraction,[{0,53}, {0,8260}, {0,54}]}};
unicode_table(8539) ->
    {0,[],{fraction,[{0,49}, {0,8260}, {0,56}]}};
unicode_table(8540) ->
    {0,[],{fraction,[{0,51}, {0,8260}, {0,56}]}};
unicode_table(8541) ->
    {0,[],{fraction,[{0,53}, {0,8260}, {0,56}]}};
unicode_table(8542) ->
    {0,[],{fraction,[{0,55}, {0,8260}, {0,56}]}};
unicode_table(8543) ->
    {0,[],{fraction,[{0,49}, {0,8260}]}};
unicode_table(8544) ->
    {0,[],{compat,[{0,73}]}};
unicode_table(8545) ->
    {0,[],{compat,[{0,73}, {0,73}]}};
unicode_table(8546) ->
    {0,[],{compat,[{0,73}, {0,73}, {0,73}]}};
unicode_table(8547) ->
    {0,[],{compat,[{0,73}, {0,86}]}};
unicode_table(8548) ->
    {0,[],{compat,[{0,86}]}};
unicode_table(8549) ->
    {0,[],{compat,[{0,86}, {0,73}]}};
unicode_table(8550) ->
    {0,[],{compat,[{0,86}, {0,73}, {0,73}]}};
unicode_table(8551) ->
    {0,[],{compat,[{0,86}, {0,73}, {0,73}, {0,73}]}};
unicode_table(8552) ->
    {0,[],{compat,[{0,73}, {0,88}]}};
unicode_table(8553) ->
    {0,[],{compat,[{0,88}]}};
unicode_table(8554) ->
    {0,[],{compat,[{0,88}, {0,73}]}};
unicode_table(8555) ->
    {0,[],{compat,[{0,88}, {0,73}, {0,73}]}};
unicode_table(8556) ->
    {0,[],{compat,[{0,76}]}};
unicode_table(8557) ->
    {0,[],{compat,[{0,67}]}};
unicode_table(8558) ->
    {0,[],{compat,[{0,68}]}};
unicode_table(8559) ->
    {0,[],{compat,[{0,77}]}};
unicode_table(8560) ->
    {0,[],{compat,[{0,105}]}};
unicode_table(8561) ->
    {0,[],{compat,[{0,105}, {0,105}]}};
unicode_table(8562) ->
    {0,[],{compat,[{0,105}, {0,105}, {0,105}]}};
unicode_table(8563) ->
    {0,[],{compat,[{0,105}, {0,118}]}};
unicode_table(8564) ->
    {0,[],{compat,[{0,118}]}};
unicode_table(8565) ->
    {0,[],{compat,[{0,118}, {0,105}]}};
unicode_table(8566) ->
    {0,[],{compat,[{0,118}, {0,105}, {0,105}]}};
unicode_table(8567) ->
    {0,[],{compat,[{0,118}, {0,105}, {0,105}, {0,105}]}};
unicode_table(8568) ->
    {0,[],{compat,[{0,105}, {0,120}]}};
unicode_table(8569) ->
    {0,[],{compat,[{0,120}]}};
unicode_table(8570) ->
    {0,[],{compat,[{0,120}, {0,105}]}};
unicode_table(8571) ->
    {0,[],{compat,[{0,120}, {0,105}, {0,105}]}};
unicode_table(8572) ->
    {0,[],{compat,[{0,108}]}};
unicode_table(8573) ->
    {0,[],{compat,[{0,99}]}};
unicode_table(8574) ->
    {0,[],{compat,[{0,100}]}};
unicode_table(8575) ->
    {0,[],{compat,[{0,109}]}};
unicode_table(8585) ->
    {0,[],{fraction,[{0,48}, {0,8260}, {0,51}]}};
unicode_table(8602) ->
    {0,[{0,8592}, {1,824}],[]};
unicode_table(8603) ->
    {0,[{0,8594}, {1,824}],[]};
unicode_table(8622) ->
    {0,[{0,8596}, {1,824}],[]};
unicode_table(8653) ->
    {0,[{0,8656}, {1,824}],[]};
unicode_table(8654) ->
    {0,[{0,8660}, {1,824}],[]};
unicode_table(8655) ->
    {0,[{0,8658}, {1,824}],[]};
unicode_table(8708) ->
    {0,[{0,8707}, {1,824}],[]};
unicode_table(8713) ->
    {0,[{0,8712}, {1,824}],[]};
unicode_table(8716) ->
    {0,[{0,8715}, {1,824}],[]};
unicode_table(8740) ->
    {0,[{0,8739}, {1,824}],[]};
unicode_table(8742) ->
    {0,[{0,8741}, {1,824}],[]};
unicode_table(8748) ->
    {0,[],{compat,[{0,8747}, {0,8747}]}};
unicode_table(8749) ->
    {0,[],{compat,[{0,8747}, {0,8747}, {0,8747}]}};
unicode_table(8751) ->
    {0,[],{compat,[{0,8750}, {0,8750}]}};
unicode_table(8752) ->
    {0,[],{compat,[{0,8750}, {0,8750}, {0,8750}]}};
unicode_table(8769) ->
    {0,[{0,8764}, {1,824}],[]};
unicode_table(8772) ->
    {0,[{0,8771}, {1,824}],[]};
unicode_table(8775) ->
    {0,[{0,8773}, {1,824}],[]};
unicode_table(8777) ->
    {0,[{0,8776}, {1,824}],[]};
unicode_table(8800) ->
    {0,[{0,61}, {1,824}],[]};
unicode_table(8802) ->
    {0,[{0,8801}, {1,824}],[]};
unicode_table(8813) ->
    {0,[{0,8781}, {1,824}],[]};
unicode_table(8814) ->
    {0,[{0,60}, {1,824}],[]};
unicode_table(8815) ->
    {0,[{0,62}, {1,824}],[]};
unicode_table(8816) ->
    {0,[{0,8804}, {1,824}],[]};
unicode_table(8817) ->
    {0,[{0,8805}, {1,824}],[]};
unicode_table(8820) ->
    {0,[{0,8818}, {1,824}],[]};
unicode_table(8821) ->
    {0,[{0,8819}, {1,824}],[]};
unicode_table(8824) ->
    {0,[{0,8822}, {1,824}],[]};
unicode_table(8825) ->
    {0,[{0,8823}, {1,824}],[]};
unicode_table(8832) ->
    {0,[{0,8826}, {1,824}],[]};
unicode_table(8833) ->
    {0,[{0,8827}, {1,824}],[]};
unicode_table(8836) ->
    {0,[{0,8834}, {1,824}],[]};
unicode_table(8837) ->
    {0,[{0,8835}, {1,824}],[]};
unicode_table(8840) ->
    {0,[{0,8838}, {1,824}],[]};
unicode_table(8841) ->
    {0,[{0,8839}, {1,824}],[]};
unicode_table(8876) ->
    {0,[{0,8866}, {1,824}],[]};
unicode_table(8877) ->
    {0,[{0,8872}, {1,824}],[]};
unicode_table(8878) ->
    {0,[{0,8873}, {1,824}],[]};
unicode_table(8879) ->
    {0,[{0,8875}, {1,824}],[]};
unicode_table(8928) ->
    {0,[{0,8828}, {1,824}],[]};
unicode_table(8929) ->
    {0,[{0,8829}, {1,824}],[]};
unicode_table(8930) ->
    {0,[{0,8849}, {1,824}],[]};
unicode_table(8931) ->
    {0,[{0,8850}, {1,824}],[]};
unicode_table(8938) ->
    {0,[{0,8882}, {1,824}],[]};
unicode_table(8939) ->
    {0,[{0,8883}, {1,824}],[]};
unicode_table(8940) ->
    {0,[{0,8884}, {1,824}],[]};
unicode_table(8941) ->
    {0,[{0,8885}, {1,824}],[]};
unicode_table(9001) ->
    {0,[{0,12296}],[]};
unicode_table(9002) ->
    {0,[{0,12297}],[]};
unicode_table(9312) ->
    {0,[],{circle,[{0,49}]}};
unicode_table(9313) ->
    {0,[],{circle,[{0,50}]}};
unicode_table(9314) ->
    {0,[],{circle,[{0,51}]}};
unicode_table(9315) ->
    {0,[],{circle,[{0,52}]}};
unicode_table(9316) ->
    {0,[],{circle,[{0,53}]}};
unicode_table(9317) ->
    {0,[],{circle,[{0,54}]}};
unicode_table(9318) ->
    {0,[],{circle,[{0,55}]}};
unicode_table(9319) ->
    {0,[],{circle,[{0,56}]}};
unicode_table(9320) ->
    {0,[],{circle,[{0,57}]}};
unicode_table(9321) ->
    {0,[],{circle,[{0,49}, {0,48}]}};
unicode_table(9322) ->
    {0,[],{circle,[{0,49}, {0,49}]}};
unicode_table(9323) ->
    {0,[],{circle,[{0,49}, {0,50}]}};
unicode_table(9324) ->
    {0,[],{circle,[{0,49}, {0,51}]}};
unicode_table(9325) ->
    {0,[],{circle,[{0,49}, {0,52}]}};
unicode_table(9326) ->
    {0,[],{circle,[{0,49}, {0,53}]}};
unicode_table(9327) ->
    {0,[],{circle,[{0,49}, {0,54}]}};
unicode_table(9328) ->
    {0,[],{circle,[{0,49}, {0,55}]}};
unicode_table(9329) ->
    {0,[],{circle,[{0,49}, {0,56}]}};
unicode_table(9330) ->
    {0,[],{circle,[{0,49}, {0,57}]}};
unicode_table(9331) ->
    {0,[],{circle,[{0,50}, {0,48}]}};
unicode_table(9332) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,41}]}};
unicode_table(9333) ->
    {0,[],{compat,[{0,40}, {0,50}, {0,41}]}};
unicode_table(9334) ->
    {0,[],{compat,[{0,40}, {0,51}, {0,41}]}};
unicode_table(9335) ->
    {0,[],{compat,[{0,40}, {0,52}, {0,41}]}};
unicode_table(9336) ->
    {0,[],{compat,[{0,40}, {0,53}, {0,41}]}};
unicode_table(9337) ->
    {0,[],{compat,[{0,40}, {0,54}, {0,41}]}};
unicode_table(9338) ->
    {0,[],{compat,[{0,40}, {0,55}, {0,41}]}};
unicode_table(9339) ->
    {0,[],{compat,[{0,40}, {0,56}, {0,41}]}};
unicode_table(9340) ->
    {0,[],{compat,[{0,40}, {0,57}, {0,41}]}};
unicode_table(9341) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,48}, {0,41}]}};
unicode_table(9342) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,49}, {0,41}]}};
unicode_table(9343) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,50}, {0,41}]}};
unicode_table(9344) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,51}, {0,41}]}};
unicode_table(9345) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,52}, {0,41}]}};
unicode_table(9346) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,53}, {0,41}]}};
unicode_table(9347) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,54}, {0,41}]}};
unicode_table(9348) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,55}, {0,41}]}};
unicode_table(9349) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,56}, {0,41}]}};
unicode_table(9350) ->
    {0,[],{compat,[{0,40}, {0,49}, {0,57}, {0,41}]}};
unicode_table(9351) ->
    {0,[],{compat,[{0,40}, {0,50}, {0,48}, {0,41}]}};
unicode_table(9352) ->
    {0,[],{compat,[{0,49}, {0,46}]}};
unicode_table(9353) ->
    {0,[],{compat,[{0,50}, {0,46}]}};
unicode_table(9354) ->
    {0,[],{compat,[{0,51}, {0,46}]}};
unicode_table(9355) ->
    {0,[],{compat,[{0,52}, {0,46}]}};
unicode_table(9356) ->
    {0,[],{compat,[{0,53}, {0,46}]}};
unicode_table(9357) ->
    {0,[],{compat,[{0,54}, {0,46}]}};
unicode_table(9358) ->
    {0,[],{compat,[{0,55}, {0,46}]}};
unicode_table(9359) ->
    {0,[],{compat,[{0,56}, {0,46}]}};
unicode_table(9360) ->
    {0,[],{compat,[{0,57}, {0,46}]}};
unicode_table(9361) ->
    {0,[],{compat,[{0,49}, {0,48}, {0,46}]}};
unicode_table(9362) ->
    {0,[],{compat,[{0,49}, {0,49}, {0,46}]}};
unicode_table(9363) ->
    {0,[],{compat,[{0,49}, {0,50}, {0,46}]}};
unicode_table(9364) ->
    {0,[],{compat,[{0,49}, {0,51}, {0,46}]}};
unicode_table(9365) ->
    {0,[],{compat,[{0,49}, {0,52}, {0,46}]}};
unicode_table(9366) ->
    {0,[],{compat,[{0,49}, {0,53}, {0,46}]}};
unicode_table(9367) ->
    {0,[],{compat,[{0,49}, {0,54}, {0,46}]}};
unicode_table(9368) ->
    {0,[],{compat,[{0,49}, {0,55}, {0,46}]}};
unicode_table(9369) ->
    {0,[],{compat,[{0,49}, {0,56}, {0,46}]}};
unicode_table(9370) ->
    {0,[],{compat,[{0,49}, {0,57}, {0,46}]}};
unicode_table(9371) ->
    {0,[],{compat,[{0,50}, {0,48}, {0,46}]}};
unicode_table(9372) ->
    {0,[],{compat,[{0,40}, {0,97}, {0,41}]}};
unicode_table(9373) ->
    {0,[],{compat,[{0,40}, {0,98}, {0,41}]}};
unicode_table(9374) ->
    {0,[],{compat,[{0,40}, {0,99}, {0,41}]}};
unicode_table(9375) ->
    {0,[],{compat,[{0,40}, {0,100}, {0,41}]}};
unicode_table(9376) ->
    {0,[],{compat,[{0,40}, {0,101}, {0,41}]}};
unicode_table(9377) ->
    {0,[],{compat,[{0,40}, {0,102}, {0,41}]}};
unicode_table(9378) ->
    {0,[],{compat,[{0,40}, {0,103}, {0,41}]}};
unicode_table(9379) ->
    {0,[],{compat,[{0,40}, {0,104}, {0,41}]}};
unicode_table(9380) ->
    {0,[],{compat,[{0,40}, {0,105}, {0,41}]}};
unicode_table(9381) ->
    {0,[],{compat,[{0,40}, {0,106}, {0,41}]}};
unicode_table(9382) ->
    {0,[],{compat,[{0,40}, {0,107}, {0,41}]}};
unicode_table(9383) ->
    {0,[],{compat,[{0,40}, {0,108}, {0,41}]}};
unicode_table(9384) ->
    {0,[],{compat,[{0,40}, {0,109}, {0,41}]}};
unicode_table(9385) ->
    {0,[],{compat,[{0,40}, {0,110}, {0,41}]}};
unicode_table(9386) ->
    {0,[],{compat,[{0,40}, {0,111}, {0,41}]}};
unicode_table(9387) ->
    {0,[],{compat,[{0,40}, {0,112}, {0,41}]}};
unicode_table(9388) ->
    {0,[],{compat,[{0,40}, {0,113}, {0,41}]}};
unicode_table(9389) ->
    {0,[],{compat,[{0,40}, {0,114}, {0,41}]}};
unicode_table(9390) ->
    {0,[],{compat,[{0,40}, {0,115}, {0,41}]}};
unicode_table(9391) ->
    {0,[],{compat,[{0,40}, {0,116}, {0,41}]}};
unicode_table(9392) ->
    {0,[],{compat,[{0,40}, {0,117}, {0,41}]}};
unicode_table(9393) ->
    {0,[],{compat,[{0,40}, {0,118}, {0,41}]}};
unicode_table(9394) ->
    {0,[],{compat,[{0,40}, {0,119}, {0,41}]}};
unicode_table(9395) ->
    {0,[],{compat,[{0,40}, {0,120}, {0,41}]}};
unicode_table(9396) ->
    {0,[],{compat,[{0,40}, {0,121}, {0,41}]}};
unicode_table(9397) ->
    {0,[],{compat,[{0,40}, {0,122}, {0,41}]}};
unicode_table(9398) ->
    {0,[],{circle,[{0,65}]}};
unicode_table(9399) ->
    {0,[],{circle,[{0,66}]}};
unicode_table(9400) ->
    {0,[],{circle,[{0,67}]}};
unicode_table(9401) ->
    {0,[],{circle,[{0,68}]}};
unicode_table(9402) ->
    {0,[],{circle,[{0,69}]}};
unicode_table(9403) ->
    {0,[],{circle,[{0,70}]}};
unicode_table(9404) ->
    {0,[],{circle,[{0,71}]}};
unicode_table(9405) ->
    {0,[],{circle,[{0,72}]}};
unicode_table(9406) ->
    {0,[],{circle,[{0,73}]}};
unicode_table(9407) ->
    {0,[],{circle,[{0,74}]}};
unicode_table(9408) ->
    {0,[],{circle,[{0,75}]}};
unicode_table(9409) ->
    {0,[],{circle,[{0,76}]}};
unicode_table(9410) ->
    {0,[],{circle,[{0,77}]}};
unicode_table(9411) ->
    {0,[],{circle,[{0,78}]}};
unicode_table(9412) ->
    {0,[],{circle,[{0,79}]}};
unicode_table(9413) ->
    {0,[],{circle,[{0,80}]}};
unicode_table(9414) ->
    {0,[],{circle,[{0,81}]}};
unicode_table(9415) ->
    {0,[],{circle,[{0,82}]}};
unicode_table(9416) ->
    {0,[],{circle,[{0,83}]}};
unicode_table(9417) ->
    {0,[],{circle,[{0,84}]}};
unicode_table(9418) ->
    {0,[],{circle,[{0,85}]}};
unicode_table(9419) ->
    {0,[],{circle,[{0,86}]}};
unicode_table(9420) ->
    {0,[],{circle,[{0,87}]}};
unicode_table(9421) ->
    {0,[],{circle,[{0,88}]}};
unicode_table(9422) ->
    {0,[],{circle,[{0,89}]}};
unicode_table(9423) ->
    {0,[],{circle,[{0,90}]}};
unicode_table(9424) ->
    {0,[],{circle,[{0,97}]}};
unicode_table(9425) ->
    {0,[],{circle,[{0,98}]}};
unicode_table(9426) ->
    {0,[],{circle,[{0,99}]}};
unicode_table(9427) ->
    {0,[],{circle,[{0,100}]}};
unicode_table(9428) ->
    {0,[],{circle,[{0,101}]}};
unicode_table(9429) ->
    {0,[],{circle,[{0,102}]}};
unicode_table(9430) ->
    {0,[],{circle,[{0,103}]}};
unicode_table(9431) ->
    {0,[],{circle,[{0,104}]}};
unicode_table(9432) ->
    {0,[],{circle,[{0,105}]}};
unicode_table(9433) ->
    {0,[],{circle,[{0,106}]}};
unicode_table(9434) ->
    {0,[],{circle,[{0,107}]}};
unicode_table(9435) ->
    {0,[],{circle,[{0,108}]}};
unicode_table(9436) ->
    {0,[],{circle,[{0,109}]}};
unicode_table(9437) ->
    {0,[],{circle,[{0,110}]}};
unicode_table(9438) ->
    {0,[],{circle,[{0,111}]}};
unicode_table(9439) ->
    {0,[],{circle,[{0,112}]}};
unicode_table(9440) ->
    {0,[],{circle,[{0,113}]}};
unicode_table(9441) ->
    {0,[],{circle,[{0,114}]}};
unicode_table(9442) ->
    {0,[],{circle,[{0,115}]}};
unicode_table(9443) ->
    {0,[],{circle,[{0,116}]}};
unicode_table(9444) ->
    {0,[],{circle,[{0,117}]}};
unicode_table(9445) ->
    {0,[],{circle,[{0,118}]}};
unicode_table(9446) ->
    {0,[],{circle,[{0,119}]}};
unicode_table(9447) ->
    {0,[],{circle,[{0,120}]}};
unicode_table(9448) ->
    {0,[],{circle,[{0,121}]}};
unicode_table(9449) ->
    {0,[],{circle,[{0,122}]}};
unicode_table(9450) ->
    {0,[],{circle,[{0,48}]}};
unicode_table(10764) ->
    {0,[],{compat,[{0,8747}, {0,8747}, {0,8747}, {0,8747}]}};
unicode_table(10868) ->
    {0,[],{compat,[{0,58}, {0,58}, {0,61}]}};
unicode_table(10869) ->
    {0,[],{compat,[{0,61}, {0,61}]}};
unicode_table(10870) ->
    {0,[],{compat,[{0,61}, {0,61}, {0,61}]}};
unicode_table(10972) ->
    {0,[{0,10973}, {1,824}],[]};
unicode_table(11388) ->
    {0,[],{sub,[{0,106}]}};
unicode_table(11389) ->
    {0,[],{super,[{0,86}]}};
unicode_table(11503) ->
    {230,[],[]};
unicode_table(11504) ->
    {230,[],[]};
unicode_table(11505) ->
    {230,[],[]};
unicode_table(11631) ->
    {0,[],{super,[{0,11617}]}};
unicode_table(11647) ->
    {9,[],[]};
unicode_table(11744) ->
    {230,[],[]};
unicode_table(11745) ->
    {230,[],[]};
unicode_table(11746) ->
    {230,[],[]};
unicode_table(11747) ->
    {230,[],[]};
unicode_table(11748) ->
    {230,[],[]};
unicode_table(11749) ->
    {230,[],[]};
unicode_table(11750) ->
    {230,[],[]};
unicode_table(11751) ->
    {230,[],[]};
unicode_table(11752) ->
    {230,[],[]};
unicode_table(11753) ->
    {230,[],[]};
unicode_table(11754) ->
    {230,[],[]};
unicode_table(11755) ->
    {230,[],[]};
unicode_table(11756) ->
    {230,[],[]};
unicode_table(11757) ->
    {230,[],[]};
unicode_table(11758) ->
    {230,[],[]};
unicode_table(11759) ->
    {230,[],[]};
unicode_table(11760) ->
    {230,[],[]};
unicode_table(11761) ->
    {230,[],[]};
unicode_table(11762) ->
    {230,[],[]};
unicode_table(11763) ->
    {230,[],[]};
unicode_table(11764) ->
    {230,[],[]};
unicode_table(11765) ->
    {230,[],[]};
unicode_table(11766) ->
    {230,[],[]};
unicode_table(11767) ->
    {230,[],[]};
unicode_table(11768) ->
    {230,[],[]};
unicode_table(11769) ->
    {230,[],[]};
unicode_table(11770) ->
    {230,[],[]};
unicode_table(11771) ->
    {230,[],[]};
unicode_table(11772) ->
    {230,[],[]};
unicode_table(11773) ->
    {230,[],[]};
unicode_table(11774) ->
    {230,[],[]};
unicode_table(11775) ->
    {230,[],[]};
unicode_table(11935) ->
    {0,[],{compat,[{0,27597}]}};
unicode_table(12019) ->
    {0,[],{compat,[{0,40863}]}};
unicode_table(12032) ->
    {0,[],{compat,[{0,19968}]}};
unicode_table(12033) ->
    {0,[],{compat,[{0,20008}]}};
unicode_table(12034) ->
    {0,[],{compat,[{0,20022}]}};
unicode_table(12035) ->
    {0,[],{compat,[{0,20031}]}};
unicode_table(12036) ->
    {0,[],{compat,[{0,20057}]}};
unicode_table(12037) ->
    {0,[],{compat,[{0,20101}]}};
unicode_table(12038) ->
    {0,[],{compat,[{0,20108}]}};
unicode_table(12039) ->
    {0,[],{compat,[{0,20128}]}};
unicode_table(12040) ->
    {0,[],{compat,[{0,20154}]}};
unicode_table(12041) ->
    {0,[],{compat,[{0,20799}]}};
unicode_table(12042) ->
    {0,[],{compat,[{0,20837}]}};
unicode_table(12043) ->
    {0,[],{compat,[{0,20843}]}};
unicode_table(12044) ->
    {0,[],{compat,[{0,20866}]}};
unicode_table(12045) ->
    {0,[],{compat,[{0,20886}]}};
unicode_table(12046) ->
    {0,[],{compat,[{0,20907}]}};
unicode_table(12047) ->
    {0,[],{compat,[{0,20960}]}};
unicode_table(12048) ->
    {0,[],{compat,[{0,20981}]}};
unicode_table(12049) ->
    {0,[],{compat,[{0,20992}]}};
unicode_table(12050) ->
    {0,[],{compat,[{0,21147}]}};
unicode_table(12051) ->
    {0,[],{compat,[{0,21241}]}};
unicode_table(12052) ->
    {0,[],{compat,[{0,21269}]}};
unicode_table(12053) ->
    {0,[],{compat,[{0,21274}]}};
unicode_table(12054) ->
    {0,[],{compat,[{0,21304}]}};
unicode_table(12055) ->
    {0,[],{compat,[{0,21313}]}};
unicode_table(12056) ->
    {0,[],{compat,[{0,21340}]}};
unicode_table(12057) ->
    {0,[],{compat,[{0,21353}]}};
unicode_table(12058) ->
    {0,[],{compat,[{0,21378}]}};
unicode_table(12059) ->
    {0,[],{compat,[{0,21430}]}};
unicode_table(12060) ->
    {0,[],{compat,[{0,21448}]}};
unicode_table(12061) ->
    {0,[],{compat,[{0,21475}]}};
unicode_table(12062) ->
    {0,[],{compat,[{0,22231}]}};
unicode_table(12063) ->
    {0,[],{compat,[{0,22303}]}};
unicode_table(12064) ->
    {0,[],{compat,[{0,22763}]}};
unicode_table(12065) ->
    {0,[],{compat,[{0,22786}]}};
unicode_table(12066) ->
    {0,[],{compat,[{0,22794}]}};
unicode_table(12067) ->
    {0,[],{compat,[{0,22805}]}};
unicode_table(12068) ->
    {0,[],{compat,[{0,22823}]}};
unicode_table(12069) ->
    {0,[],{compat,[{0,22899}]}};
unicode_table(12070) ->
    {0,[],{compat,[{0,23376}]}};
unicode_table(12071) ->
    {0,[],{compat,[{0,23424}]}};
unicode_table(12072) ->
    {0,[],{compat,[{0,23544}]}};
unicode_table(12073) ->
    {0,[],{compat,[{0,23567}]}};
unicode_table(12074) ->
    {0,[],{compat,[{0,23586}]}};
unicode_table(12075) ->
    {0,[],{compat,[{0,23608}]}};
unicode_table(12076) ->
    {0,[],{compat,[{0,23662}]}};
unicode_table(12077) ->
    {0,[],{compat,[{0,23665}]}};
unicode_table(12078) ->
    {0,[],{compat,[{0,24027}]}};
unicode_table(12079) ->
    {0,[],{compat,[{0,24037}]}};
unicode_table(12080) ->
    {0,[],{compat,[{0,24049}]}};
unicode_table(12081) ->
    {0,[],{compat,[{0,24062}]}};
unicode_table(12082) ->
    {0,[],{compat,[{0,24178}]}};
unicode_table(12083) ->
    {0,[],{compat,[{0,24186}]}};
unicode_table(12084) ->
    {0,[],{compat,[{0,24191}]}};
unicode_table(12085) ->
    {0,[],{compat,[{0,24308}]}};
unicode_table(12086) ->
    {0,[],{compat,[{0,24318}]}};
unicode_table(12087) ->
    {0,[],{compat,[{0,24331}]}};
unicode_table(12088) ->
    {0,[],{compat,[{0,24339}]}};
unicode_table(12089) ->
    {0,[],{compat,[{0,24400}]}};
unicode_table(12090) ->
    {0,[],{compat,[{0,24417}]}};
unicode_table(12091) ->
    {0,[],{compat,[{0,24435}]}};
unicode_table(12092) ->
    {0,[],{compat,[{0,24515}]}};
unicode_table(12093) ->
    {0,[],{compat,[{0,25096}]}};
unicode_table(12094) ->
    {0,[],{compat,[{0,25142}]}};
unicode_table(12095) ->
    {0,[],{compat,[{0,25163}]}};
unicode_table(12096) ->
    {0,[],{compat,[{0,25903}]}};
unicode_table(12097) ->
    {0,[],{compat,[{0,25908}]}};
unicode_table(12098) ->
    {0,[],{compat,[{0,25991}]}};
unicode_table(12099) ->
    {0,[],{compat,[{0,26007}]}};
unicode_table(12100) ->
    {0,[],{compat,[{0,26020}]}};
unicode_table(12101) ->
    {0,[],{compat,[{0,26041}]}};
unicode_table(12102) ->
    {0,[],{compat,[{0,26080}]}};
unicode_table(12103) ->
    {0,[],{compat,[{0,26085}]}};
unicode_table(12104) ->
    {0,[],{compat,[{0,26352}]}};
unicode_table(12105) ->
    {0,[],{compat,[{0,26376}]}};
unicode_table(12106) ->
    {0,[],{compat,[{0,26408}]}};
unicode_table(12107) ->
    {0,[],{compat,[{0,27424}]}};
unicode_table(12108) ->
    {0,[],{compat,[{0,27490}]}};
unicode_table(12109) ->
    {0,[],{compat,[{0,27513}]}};
unicode_table(12110) ->
    {0,[],{compat,[{0,27571}]}};
unicode_table(12111) ->
    {0,[],{compat,[{0,27595}]}};
unicode_table(12112) ->
    {0,[],{compat,[{0,27604}]}};
unicode_table(12113) ->
    {0,[],{compat,[{0,27611}]}};
unicode_table(12114) ->
    {0,[],{compat,[{0,27663}]}};
unicode_table(12115) ->
    {0,[],{compat,[{0,27668}]}};
unicode_table(12116) ->
    {0,[],{compat,[{0,27700}]}};
unicode_table(12117) ->
    {0,[],{compat,[{0,28779}]}};
unicode_table(12118) ->
    {0,[],{compat,[{0,29226}]}};
unicode_table(12119) ->
    {0,[],{compat,[{0,29238}]}};
unicode_table(12120) ->
    {0,[],{compat,[{0,29243}]}};
unicode_table(12121) ->
    {0,[],{compat,[{0,29247}]}};
unicode_table(12122) ->
    {0,[],{compat,[{0,29255}]}};
unicode_table(12123) ->
    {0,[],{compat,[{0,29273}]}};
unicode_table(12124) ->
    {0,[],{compat,[{0,29275}]}};
unicode_table(12125) ->
    {0,[],{compat,[{0,29356}]}};
unicode_table(12126) ->
    {0,[],{compat,[{0,29572}]}};
unicode_table(12127) ->
    {0,[],{compat,[{0,29577}]}};
unicode_table(12128) ->
    {0,[],{compat,[{0,29916}]}};
unicode_table(12129) ->
    {0,[],{compat,[{0,29926}]}};
unicode_table(12130) ->
    {0,[],{compat,[{0,29976}]}};
unicode_table(12131) ->
    {0,[],{compat,[{0,29983}]}};
unicode_table(12132) ->
    {0,[],{compat,[{0,29992}]}};
unicode_table(12133) ->
    {0,[],{compat,[{0,30000}]}};
unicode_table(12134) ->
    {0,[],{compat,[{0,30091}]}};
unicode_table(12135) ->
    {0,[],{compat,[{0,30098}]}};
unicode_table(12136) ->
    {0,[],{compat,[{0,30326}]}};
unicode_table(12137) ->
    {0,[],{compat,[{0,30333}]}};
unicode_table(12138) ->
    {0,[],{compat,[{0,30382}]}};
unicode_table(12139) ->
    {0,[],{compat,[{0,30399}]}};
unicode_table(12140) ->
    {0,[],{compat,[{0,30446}]}};
unicode_table(12141) ->
    {0,[],{compat,[{0,30683}]}};
unicode_table(12142) ->
    {0,[],{compat,[{0,30690}]}};
unicode_table(12143) ->
    {0,[],{compat,[{0,30707}]}};
unicode_table(12144) ->
    {0,[],{compat,[{0,31034}]}};
unicode_table(12145) ->
    {0,[],{compat,[{0,31160}]}};
unicode_table(12146) ->
    {0,[],{compat,[{0,31166}]}};
unicode_table(12147) ->
    {0,[],{compat,[{0,31348}]}};
unicode_table(12148) ->
    {0,[],{compat,[{0,31435}]}};
unicode_table(12149) ->
    {0,[],{compat,[{0,31481}]}};
unicode_table(12150) ->
    {0,[],{compat,[{0,31859}]}};
unicode_table(12151) ->
    {0,[],{compat,[{0,31992}]}};
unicode_table(12152) ->
    {0,[],{compat,[{0,32566}]}};
unicode_table(12153) ->
    {0,[],{compat,[{0,32593}]}};
unicode_table(12154) ->
    {0,[],{compat,[{0,32650}]}};
unicode_table(12155) ->
    {0,[],{compat,[{0,32701}]}};
unicode_table(12156) ->
    {0,[],{compat,[{0,32769}]}};
unicode_table(12157) ->
    {0,[],{compat,[{0,32780}]}};
unicode_table(12158) ->
    {0,[],{compat,[{0,32786}]}};
unicode_table(12159) ->
    {0,[],{compat,[{0,32819}]}};
unicode_table(12160) ->
    {0,[],{compat,[{0,32895}]}};
unicode_table(12161) ->
    {0,[],{compat,[{0,32905}]}};
unicode_table(12162) ->
    {0,[],{compat,[{0,33251}]}};
unicode_table(12163) ->
    {0,[],{compat,[{0,33258}]}};
unicode_table(12164) ->
    {0,[],{compat,[{0,33267}]}};
unicode_table(12165) ->
    {0,[],{compat,[{0,33276}]}};
unicode_table(12166) ->
    {0,[],{compat,[{0,33292}]}};
unicode_table(12167) ->
    {0,[],{compat,[{0,33307}]}};
unicode_table(12168) ->
    {0,[],{compat,[{0,33311}]}};
unicode_table(12169) ->
    {0,[],{compat,[{0,33390}]}};
unicode_table(12170) ->
    {0,[],{compat,[{0,33394}]}};
unicode_table(12171) ->
    {0,[],{compat,[{0,33400}]}};
unicode_table(12172) ->
    {0,[],{compat,[{0,34381}]}};
unicode_table(12173) ->
    {0,[],{compat,[{0,34411}]}};
unicode_table(12174) ->
    {0,[],{compat,[{0,34880}]}};
unicode_table(12175) ->
    {0,[],{compat,[{0,34892}]}};
unicode_table(12176) ->
    {0,[],{compat,[{0,34915}]}};
unicode_table(12177) ->
    {0,[],{compat,[{0,35198}]}};
unicode_table(12178) ->
    {0,[],{compat,[{0,35211}]}};
unicode_table(12179) ->
    {0,[],{compat,[{0,35282}]}};
unicode_table(12180) ->
    {0,[],{compat,[{0,35328}]}};
unicode_table(12181) ->
    {0,[],{compat,[{0,35895}]}};
unicode_table(12182) ->
    {0,[],{compat,[{0,35910}]}};
unicode_table(12183) ->
    {0,[],{compat,[{0,35925}]}};
unicode_table(12184) ->
    {0,[],{compat,[{0,35960}]}};
unicode_table(12185) ->
    {0,[],{compat,[{0,35997}]}};
unicode_table(12186) ->
    {0,[],{compat,[{0,36196}]}};
unicode_table(12187) ->
    {0,[],{compat,[{0,36208}]}};
unicode_table(12188) ->
    {0,[],{compat,[{0,36275}]}};
unicode_table(12189) ->
    {0,[],{compat,[{0,36523}]}};
unicode_table(12190) ->
    {0,[],{compat,[{0,36554}]}};
unicode_table(12191) ->
    {0,[],{compat,[{0,36763}]}};
unicode_table(12192) ->
    {0,[],{compat,[{0,36784}]}};
unicode_table(12193) ->
    {0,[],{compat,[{0,36789}]}};
unicode_table(12194) ->
    {0,[],{compat,[{0,37009}]}};
unicode_table(12195) ->
    {0,[],{compat,[{0,37193}]}};
unicode_table(12196) ->
    {0,[],{compat,[{0,37318}]}};
unicode_table(12197) ->
    {0,[],{compat,[{0,37324}]}};
unicode_table(12198) ->
    {0,[],{compat,[{0,37329}]}};
unicode_table(12199) ->
    {0,[],{compat,[{0,38263}]}};
unicode_table(12200) ->
    {0,[],{compat,[{0,38272}]}};
unicode_table(12201) ->
    {0,[],{compat,[{0,38428}]}};
unicode_table(12202) ->
    {0,[],{compat,[{0,38582}]}};
unicode_table(12203) ->
    {0,[],{compat,[{0,38585}]}};
unicode_table(12204) ->
    {0,[],{compat,[{0,38632}]}};
unicode_table(12205) ->
    {0,[],{compat,[{0,38737}]}};
unicode_table(12206) ->
    {0,[],{compat,[{0,38750}]}};
unicode_table(12207) ->
    {0,[],{compat,[{0,38754}]}};
unicode_table(12208) ->
    {0,[],{compat,[{0,38761}]}};
unicode_table(12209) ->
    {0,[],{compat,[{0,38859}]}};
unicode_table(12210) ->
    {0,[],{compat,[{0,38893}]}};
unicode_table(12211) ->
    {0,[],{compat,[{0,38899}]}};
unicode_table(12212) ->
    {0,[],{compat,[{0,38913}]}};
unicode_table(12213) ->
    {0,[],{compat,[{0,39080}]}};
unicode_table(12214) ->
    {0,[],{compat,[{0,39131}]}};
unicode_table(12215) ->
    {0,[],{compat,[{0,39135}]}};
unicode_table(12216) ->
    {0,[],{compat,[{0,39318}]}};
unicode_table(12217) ->
    {0,[],{compat,[{0,39321}]}};
unicode_table(12218) ->
    {0,[],{compat,[{0,39340}]}};
unicode_table(12219) ->
    {0,[],{compat,[{0,39592}]}};
unicode_table(12220) ->
    {0,[],{compat,[{0,39640}]}};
unicode_table(12221) ->
    {0,[],{compat,[{0,39647}]}};
unicode_table(12222) ->
    {0,[],{compat,[{0,39717}]}};
unicode_table(12223) ->
    {0,[],{compat,[{0,39727}]}};
unicode_table(12224) ->
    {0,[],{compat,[{0,39730}]}};
unicode_table(12225) ->
    {0,[],{compat,[{0,39740}]}};
unicode_table(12226) ->
    {0,[],{compat,[{0,39770}]}};
unicode_table(12227) ->
    {0,[],{compat,[{0,40165}]}};
unicode_table(12228) ->
    {0,[],{compat,[{0,40565}]}};
unicode_table(12229) ->
    {0,[],{compat,[{0,40575}]}};
unicode_table(12230) ->
    {0,[],{compat,[{0,40613}]}};
unicode_table(12231) ->
    {0,[],{compat,[{0,40635}]}};
unicode_table(12232) ->
    {0,[],{compat,[{0,40643}]}};
unicode_table(12233) ->
    {0,[],{compat,[{0,40653}]}};
unicode_table(12234) ->
    {0,[],{compat,[{0,40657}]}};
unicode_table(12235) ->
    {0,[],{compat,[{0,40697}]}};
unicode_table(12236) ->
    {0,[],{compat,[{0,40701}]}};
unicode_table(12237) ->
    {0,[],{compat,[{0,40718}]}};
unicode_table(12238) ->
    {0,[],{compat,[{0,40723}]}};
unicode_table(12239) ->
    {0,[],{compat,[{0,40736}]}};
unicode_table(12240) ->
    {0,[],{compat,[{0,40763}]}};
unicode_table(12241) ->
    {0,[],{compat,[{0,40778}]}};
unicode_table(12242) ->
    {0,[],{compat,[{0,40786}]}};
unicode_table(12243) ->
    {0,[],{compat,[{0,40845}]}};
unicode_table(12244) ->
    {0,[],{compat,[{0,40860}]}};
unicode_table(12245) ->
    {0,[],{compat,[{0,40864}]}};
unicode_table(12288) ->
    {0,[],{wide,[{0,32}]}};
unicode_table(12330) ->
    {218,[],[]};
unicode_table(12331) ->
    {228,[],[]};
unicode_table(12332) ->
    {232,[],[]};
unicode_table(12333) ->
    {222,[],[]};
unicode_table(12334) ->
    {224,[],[]};
unicode_table(12335) ->
    {224,[],[]};
unicode_table(12342) ->
    {0,[],{compat,[{0,12306}]}};
unicode_table(12344) ->
    {0,[],{compat,[{0,21313}]}};
unicode_table(12345) ->
    {0,[],{compat,[{0,21316}]}};
unicode_table(12346) ->
    {0,[],{compat,[{0,21317}]}};
unicode_table(12364) ->
    {0,[{0,12363}, {8,12441}],[]};
unicode_table(12366) ->
    {0,[{0,12365}, {8,12441}],[]};
unicode_table(12368) ->
    {0,[{0,12367}, {8,12441}],[]};
unicode_table(12370) ->
    {0,[{0,12369}, {8,12441}],[]};
unicode_table(12372) ->
    {0,[{0,12371}, {8,12441}],[]};
unicode_table(12374) ->
    {0,[{0,12373}, {8,12441}],[]};
unicode_table(12376) ->
    {0,[{0,12375}, {8,12441}],[]};
unicode_table(12378) ->
    {0,[{0,12377}, {8,12441}],[]};
unicode_table(12380) ->
    {0,[{0,12379}, {8,12441}],[]};
unicode_table(12382) ->
    {0,[{0,12381}, {8,12441}],[]};
unicode_table(12384) ->
    {0,[{0,12383}, {8,12441}],[]};
unicode_table(12386) ->
    {0,[{0,12385}, {8,12441}],[]};
unicode_table(12389) ->
    {0,[{0,12388}, {8,12441}],[]};
unicode_table(12391) ->
    {0,[{0,12390}, {8,12441}],[]};
unicode_table(12393) ->
    {0,[{0,12392}, {8,12441}],[]};
unicode_table(12400) ->
    {0,[{0,12399}, {8,12441}],[]};
unicode_table(12401) ->
    {0,[{0,12399}, {8,12442}],[]};
unicode_table(12403) ->
    {0,[{0,12402}, {8,12441}],[]};
unicode_table(12404) ->
    {0,[{0,12402}, {8,12442}],[]};
unicode_table(12406) ->
    {0,[{0,12405}, {8,12441}],[]};
unicode_table(12407) ->
    {0,[{0,12405}, {8,12442}],[]};
unicode_table(12409) ->
    {0,[{0,12408}, {8,12441}],[]};
unicode_table(12410) ->
    {0,[{0,12408}, {8,12442}],[]};
unicode_table(12412) ->
    {0,[{0,12411}, {8,12441}],[]};
unicode_table(12413) ->
    {0,[{0,12411}, {8,12442}],[]};
unicode_table(12436) ->
    {0,[{0,12358}, {8,12441}],[]};
unicode_table(12441) ->
    {8,[],[]};
unicode_table(12442) ->
    {8,[],[]};
unicode_table(12443) ->
    {0,[],{compat,[{0,32}, {8,12441}]}};
unicode_table(12444) ->
    {0,[],{compat,[{0,32}, {8,12442}]}};
unicode_table(12446) ->
    {0,[{0,12445}, {8,12441}],[]};
unicode_table(12447) ->
    {0,[],{vertical,[{0,12424}, {0,12426}]}};
unicode_table(12460) ->
    {0,[{0,12459}, {8,12441}],[]};
unicode_table(12462) ->
    {0,[{0,12461}, {8,12441}],[]};
unicode_table(12464) ->
    {0,[{0,12463}, {8,12441}],[]};
unicode_table(12466) ->
    {0,[{0,12465}, {8,12441}],[]};
unicode_table(12468) ->
    {0,[{0,12467}, {8,12441}],[]};
unicode_table(12470) ->
    {0,[{0,12469}, {8,12441}],[]};
unicode_table(12472) ->
    {0,[{0,12471}, {8,12441}],[]};
unicode_table(12474) ->
    {0,[{0,12473}, {8,12441}],[]};
unicode_table(12476) ->
    {0,[{0,12475}, {8,12441}],[]};
unicode_table(12478) ->
    {0,[{0,12477}, {8,12441}],[]};
unicode_table(12480) ->
    {0,[{0,12479}, {8,12441}],[]};
unicode_table(12482) ->
    {0,[{0,12481}, {8,12441}],[]};
unicode_table(12485) ->
    {0,[{0,12484}, {8,12441}],[]};
unicode_table(12487) ->
    {0,[{0,12486}, {8,12441}],[]};
unicode_table(12489) ->
    {0,[{0,12488}, {8,12441}],[]};
unicode_table(12496) ->
    {0,[{0,12495}, {8,12441}],[]};
unicode_table(12497) ->
    {0,[{0,12495}, {8,12442}],[]};
unicode_table(12499) ->
    {0,[{0,12498}, {8,12441}],[]};
unicode_table(12500) ->
    {0,[{0,12498}, {8,12442}],[]};
unicode_table(12502) ->
    {0,[{0,12501}, {8,12441}],[]};
unicode_table(12503) ->
    {0,[{0,12501}, {8,12442}],[]};
unicode_table(12505) ->
    {0,[{0,12504}, {8,12441}],[]};
unicode_table(12506) ->
    {0,[{0,12504}, {8,12442}],[]};
unicode_table(12508) ->
    {0,[{0,12507}, {8,12441}],[]};
unicode_table(12509) ->
    {0,[{0,12507}, {8,12442}],[]};
unicode_table(12532) ->
    {0,[{0,12454}, {8,12441}],[]};
unicode_table(12535) ->
    {0,[{0,12527}, {8,12441}],[]};
unicode_table(12536) ->
    {0,[{0,12528}, {8,12441}],[]};
unicode_table(12537) ->
    {0,[{0,12529}, {8,12441}],[]};
unicode_table(12538) ->
    {0,[{0,12530}, {8,12441}],[]};
unicode_table(12542) ->
    {0,[{0,12541}, {8,12441}],[]};
unicode_table(12543) ->
    {0,[],{vertical,[{0,12467}, {0,12488}]}};
unicode_table(12593) ->
    {0,[],{compat,[{0,4352}]}};
unicode_table(12594) ->
    {0,[],{compat,[{0,4353}]}};
unicode_table(12595) ->
    {0,[],{compat,[{0,4522}]}};
unicode_table(12596) ->
    {0,[],{compat,[{0,4354}]}};
unicode_table(12597) ->
    {0,[],{compat,[{0,4524}]}};
unicode_table(12598) ->
    {0,[],{compat,[{0,4525}]}};
unicode_table(12599) ->
    {0,[],{compat,[{0,4355}]}};
unicode_table(12600) ->
    {0,[],{compat,[{0,4356}]}};
unicode_table(12601) ->
    {0,[],{compat,[{0,4357}]}};
unicode_table(12602) ->
    {0,[],{compat,[{0,4528}]}};
unicode_table(12603) ->
    {0,[],{compat,[{0,4529}]}};
unicode_table(12604) ->
    {0,[],{compat,[{0,4530}]}};
unicode_table(12605) ->
    {0,[],{compat,[{0,4531}]}};
unicode_table(12606) ->
    {0,[],{compat,[{0,4532}]}};
unicode_table(12607) ->
    {0,[],{compat,[{0,4533}]}};
unicode_table(12608) ->
    {0,[],{compat,[{0,4378}]}};
unicode_table(12609) ->
    {0,[],{compat,[{0,4358}]}};
unicode_table(12610) ->
    {0,[],{compat,[{0,4359}]}};
unicode_table(12611) ->
    {0,[],{compat,[{0,4360}]}};
unicode_table(12612) ->
    {0,[],{compat,[{0,4385}]}};
unicode_table(12613) ->
    {0,[],{compat,[{0,4361}]}};
unicode_table(12614) ->
    {0,[],{compat,[{0,4362}]}};
unicode_table(12615) ->
    {0,[],{compat,[{0,4363}]}};
unicode_table(12616) ->
    {0,[],{compat,[{0,4364}]}};
unicode_table(12617) ->
    {0,[],{compat,[{0,4365}]}};
unicode_table(12618) ->
    {0,[],{compat,[{0,4366}]}};
unicode_table(12619) ->
    {0,[],{compat,[{0,4367}]}};
unicode_table(12620) ->
    {0,[],{compat,[{0,4368}]}};
unicode_table(12621) ->
    {0,[],{compat,[{0,4369}]}};
unicode_table(12622) ->
    {0,[],{compat,[{0,4370}]}};
unicode_table(12623) ->
    {0,[],{compat,[{0,4449}]}};
unicode_table(12624) ->
    {0,[],{compat,[{0,4450}]}};
unicode_table(12625) ->
    {0,[],{compat,[{0,4451}]}};
unicode_table(12626) ->
    {0,[],{compat,[{0,4452}]}};
unicode_table(12627) ->
    {0,[],{compat,[{0,4453}]}};
unicode_table(12628) ->
    {0,[],{compat,[{0,4454}]}};
unicode_table(12629) ->
    {0,[],{compat,[{0,4455}]}};
unicode_table(12630) ->
    {0,[],{compat,[{0,4456}]}};
unicode_table(12631) ->
    {0,[],{compat,[{0,4457}]}};
unicode_table(12632) ->
    {0,[],{compat,[{0,4458}]}};
unicode_table(12633) ->
    {0,[],{compat,[{0,4459}]}};
unicode_table(12634) ->
    {0,[],{compat,[{0,4460}]}};
unicode_table(12635) ->
    {0,[],{compat,[{0,4461}]}};
unicode_table(12636) ->
    {0,[],{compat,[{0,4462}]}};
unicode_table(12637) ->
    {0,[],{compat,[{0,4463}]}};
unicode_table(12638) ->
    {0,[],{compat,[{0,4464}]}};
unicode_table(12639) ->
    {0,[],{compat,[{0,4465}]}};
unicode_table(12640) ->
    {0,[],{compat,[{0,4466}]}};
unicode_table(12641) ->
    {0,[],{compat,[{0,4467}]}};
unicode_table(12642) ->
    {0,[],{compat,[{0,4468}]}};
unicode_table(12643) ->
    {0,[],{compat,[{0,4469}]}};
unicode_table(12644) ->
    {0,[],{compat,[{0,4448}]}};
unicode_table(12645) ->
    {0,[],{compat,[{0,4372}]}};
unicode_table(12646) ->
    {0,[],{compat,[{0,4373}]}};
unicode_table(12647) ->
    {0,[],{compat,[{0,4551}]}};
unicode_table(12648) ->
    {0,[],{compat,[{0,4552}]}};
unicode_table(12649) ->
    {0,[],{compat,[{0,4556}]}};
unicode_table(12650) ->
    {0,[],{compat,[{0,4558}]}};
unicode_table(12651) ->
    {0,[],{compat,[{0,4563}]}};
unicode_table(12652) ->
    {0,[],{compat,[{0,4567}]}};
unicode_table(12653) ->
    {0,[],{compat,[{0,4569}]}};
unicode_table(12654) ->
    {0,[],{compat,[{0,4380}]}};
unicode_table(12655) ->
    {0,[],{compat,[{0,4573}]}};
unicode_table(12656) ->
    {0,[],{compat,[{0,4575}]}};
unicode_table(12657) ->
    {0,[],{compat,[{0,4381}]}};
unicode_table(12658) ->
    {0,[],{compat,[{0,4382}]}};
unicode_table(12659) ->
    {0,[],{compat,[{0,4384}]}};
unicode_table(12660) ->
    {0,[],{compat,[{0,4386}]}};
unicode_table(12661) ->
    {0,[],{compat,[{0,4387}]}};
unicode_table(12662) ->
    {0,[],{compat,[{0,4391}]}};
unicode_table(12663) ->
    {0,[],{compat,[{0,4393}]}};
unicode_table(12664) ->
    {0,[],{compat,[{0,4395}]}};
unicode_table(12665) ->
    {0,[],{compat,[{0,4396}]}};
unicode_table(12666) ->
    {0,[],{compat,[{0,4397}]}};
unicode_table(12667) ->
    {0,[],{compat,[{0,4398}]}};
unicode_table(12668) ->
    {0,[],{compat,[{0,4399}]}};
unicode_table(12669) ->
    {0,[],{compat,[{0,4402}]}};
unicode_table(12670) ->
    {0,[],{compat,[{0,4406}]}};
unicode_table(12671) ->
    {0,[],{compat,[{0,4416}]}};
unicode_table(12672) ->
    {0,[],{compat,[{0,4423}]}};
unicode_table(12673) ->
    {0,[],{compat,[{0,4428}]}};
unicode_table(12674) ->
    {0,[],{compat,[{0,4593}]}};
unicode_table(12675) ->
    {0,[],{compat,[{0,4594}]}};
unicode_table(12676) ->
    {0,[],{compat,[{0,4439}]}};
unicode_table(12677) ->
    {0,[],{compat,[{0,4440}]}};
unicode_table(12678) ->
    {0,[],{compat,[{0,4441}]}};
unicode_table(12679) ->
    {0,[],{compat,[{0,4484}]}};
unicode_table(12680) ->
    {0,[],{compat,[{0,4485}]}};
unicode_table(12681) ->
    {0,[],{compat,[{0,4488}]}};
unicode_table(12682) ->
    {0,[],{compat,[{0,4497}]}};
unicode_table(12683) ->
    {0,[],{compat,[{0,4498}]}};
unicode_table(12684) ->
    {0,[],{compat,[{0,4500}]}};
unicode_table(12685) ->
    {0,[],{compat,[{0,4510}]}};
unicode_table(12686) ->
    {0,[],{compat,[{0,4513}]}};
unicode_table(12690) ->
    {0,[],{super,[{0,19968}]}};
unicode_table(12691) ->
    {0,[],{super,[{0,20108}]}};
unicode_table(12692) ->
    {0,[],{super,[{0,19977}]}};
unicode_table(12693) ->
    {0,[],{super,[{0,22235}]}};
unicode_table(12694) ->
    {0,[],{super,[{0,19978}]}};
unicode_table(12695) ->
    {0,[],{super,[{0,20013}]}};
unicode_table(12696) ->
    {0,[],{super,[{0,19979}]}};
unicode_table(12697) ->
    {0,[],{super,[{0,30002}]}};
unicode_table(12698) ->
    {0,[],{super,[{0,20057}]}};
unicode_table(12699) ->
    {0,[],{super,[{0,19993}]}};
unicode_table(12700) ->
    {0,[],{super,[{0,19969}]}};
unicode_table(12701) ->
    {0,[],{super,[{0,22825}]}};
unicode_table(12702) ->
    {0,[],{super,[{0,22320}]}};
unicode_table(12703) ->
    {0,[],{super,[{0,20154}]}};
unicode_table(12800) ->
    {0,[],{compat,[{0,40}, {0,4352}, {0,41}]}};
unicode_table(12801) ->
    {0,[],{compat,[{0,40}, {0,4354}, {0,41}]}};
unicode_table(12802) ->
    {0,[],{compat,[{0,40}, {0,4355}, {0,41}]}};
unicode_table(12803) ->
    {0,[],{compat,[{0,40}, {0,4357}, {0,41}]}};
unicode_table(12804) ->
    {0,[],{compat,[{0,40}, {0,4358}, {0,41}]}};
unicode_table(12805) ->
    {0,[],{compat,[{0,40}, {0,4359}, {0,41}]}};
unicode_table(12806) ->
    {0,[],{compat,[{0,40}, {0,4361}, {0,41}]}};
unicode_table(12807) ->
    {0,[],{compat,[{0,40}, {0,4363}, {0,41}]}};
unicode_table(12808) ->
    {0,[],{compat,[{0,40}, {0,4364}, {0,41}]}};
unicode_table(12809) ->
    {0,[],{compat,[{0,40}, {0,4366}, {0,41}]}};
unicode_table(12810) ->
    {0,[],{compat,[{0,40}, {0,4367}, {0,41}]}};
unicode_table(12811) ->
    {0,[],{compat,[{0,40}, {0,4368}, {0,41}]}};
unicode_table(12812) ->
    {0,[],{compat,[{0,40}, {0,4369}, {0,41}]}};
unicode_table(12813) ->
    {0,[],{compat,[{0,40}, {0,4370}, {0,41}]}};
unicode_table(12814) ->
    {0,[],{compat,[{0,40}, {0,4352}, {0,4449}, {0,41}]}};
unicode_table(12815) ->
    {0,[],{compat,[{0,40}, {0,4354}, {0,4449}, {0,41}]}};
unicode_table(12816) ->
    {0,[],{compat,[{0,40}, {0,4355}, {0,4449}, {0,41}]}};
unicode_table(12817) ->
    {0,[],{compat,[{0,40}, {0,4357}, {0,4449}, {0,41}]}};
unicode_table(12818) ->
    {0,[],{compat,[{0,40}, {0,4358}, {0,4449}, {0,41}]}};
unicode_table(12819) ->
    {0,[],{compat,[{0,40}, {0,4359}, {0,4449}, {0,41}]}};
unicode_table(12820) ->
    {0,[],{compat,[{0,40}, {0,4361}, {0,4449}, {0,41}]}};
unicode_table(12821) ->
    {0,[],{compat,[{0,40}, {0,4363}, {0,4449}, {0,41}]}};
unicode_table(12822) ->
    {0,[],{compat,[{0,40}, {0,4364}, {0,4449}, {0,41}]}};
unicode_table(12823) ->
    {0,[],{compat,[{0,40}, {0,4366}, {0,4449}, {0,41}]}};
unicode_table(12824) ->
    {0,[],{compat,[{0,40}, {0,4367}, {0,4449}, {0,41}]}};
unicode_table(12825) ->
    {0,[],{compat,[{0,40}, {0,4368}, {0,4449}, {0,41}]}};
unicode_table(12826) ->
    {0,[],{compat,[{0,40}, {0,4369}, {0,4449}, {0,41}]}};
unicode_table(12827) ->
    {0,[],{compat,[{0,40}, {0,4370}, {0,4449}, {0,41}]}};
unicode_table(12828) ->
    {0,[],{compat,[{0,40}, {0,4364}, {0,4462}, {0,41}]}};
unicode_table(12829) ->
    {0,[],{compat,[{0,40}, {0,4363}, {0,4457}, {0,4364}, {0,4453}, {0,4523}, {0,41}]}};
unicode_table(12830) ->
    {0,[],{compat,[{0,40}, {0,4363}, {0,4457}, {0,4370}, {0,4462}, {0,41}]}};
unicode_table(12832) ->
    {0,[],{compat,[{0,40}, {0,19968}, {0,41}]}};
unicode_table(12833) ->
    {0,[],{compat,[{0,40}, {0,20108}, {0,41}]}};
unicode_table(12834) ->
    {0,[],{compat,[{0,40}, {0,19977}, {0,41}]}};
unicode_table(12835) ->
    {0,[],{compat,[{0,40}, {0,22235}, {0,41}]}};
unicode_table(12836) ->
    {0,[],{compat,[{0,40}, {0,20116}, {0,41}]}};
unicode_table(12837) ->
    {0,[],{compat,[{0,40}, {0,20845}, {0,41}]}};
unicode_table(12838) ->
    {0,[],{compat,[{0,40}, {0,19971}, {0,41}]}};
unicode_table(12839) ->
    {0,[],{compat,[{0,40}, {0,20843}, {0,41}]}};
unicode_table(12840) ->
    {0,[],{compat,[{0,40}, {0,20061}, {0,41}]}};
unicode_table(12841) ->
    {0,[],{compat,[{0,40}, {0,21313}, {0,41}]}};
unicode_table(12842) ->
    {0,[],{compat,[{0,40}, {0,26376}, {0,41}]}};
unicode_table(12843) ->
    {0,[],{compat,[{0,40}, {0,28779}, {0,41}]}};
unicode_table(12844) ->
    {0,[],{compat,[{0,40}, {0,27700}, {0,41}]}};
unicode_table(12845) ->
    {0,[],{compat,[{0,40}, {0,26408}, {0,41}]}};
unicode_table(12846) ->
    {0,[],{compat,[{0,40}, {0,37329}, {0,41}]}};
unicode_table(12847) ->
    {0,[],{compat,[{0,40}, {0,22303}, {0,41}]}};
unicode_table(12848) ->
    {0,[],{compat,[{0,40}, {0,26085}, {0,41}]}};
unicode_table(12849) ->
    {0,[],{compat,[{0,40}, {0,26666}, {0,41}]}};
unicode_table(12850) ->
    {0,[],{compat,[{0,40}, {0,26377}, {0,41}]}};
unicode_table(12851) ->
    {0,[],{compat,[{0,40}, {0,31038}, {0,41}]}};
unicode_table(12852) ->
    {0,[],{compat,[{0,40}, {0,21517}, {0,41}]}};
unicode_table(12853) ->
    {0,[],{compat,[{0,40}, {0,29305}, {0,41}]}};
unicode_table(12854) ->
    {0,[],{compat,[{0,40}, {0,36001}, {0,41}]}};
unicode_table(12855) ->
    {0,[],{compat,[{0,40}, {0,31069}, {0,41}]}};
unicode_table(12856) ->
    {0,[],{compat,[{0,40}, {0,21172}, {0,41}]}};
unicode_table(12857) ->
    {0,[],{compat,[{0,40}, {0,20195}, {0,41}]}};
unicode_table(12858) ->
    {0,[],{compat,[{0,40}, {0,21628}, {0,41}]}};
unicode_table(12859) ->
    {0,[],{compat,[{0,40}, {0,23398}, {0,41}]}};
unicode_table(12860) ->
    {0,[],{compat,[{0,40}, {0,30435}, {0,41}]}};
unicode_table(12861) ->
    {0,[],{compat,[{0,40}, {0,20225}, {0,41}]}};
unicode_table(12862) ->
    {0,[],{compat,[{0,40}, {0,36039}, {0,41}]}};
unicode_table(12863) ->
    {0,[],{compat,[{0,40}, {0,21332}, {0,41}]}};
unicode_table(12864) ->
    {0,[],{compat,[{0,40}, {0,31085}, {0,41}]}};
unicode_table(12865) ->
    {0,[],{compat,[{0,40}, {0,20241}, {0,41}]}};
unicode_table(12866) ->
    {0,[],{compat,[{0,40}, {0,33258}, {0,41}]}};
unicode_table(12867) ->
    {0,[],{compat,[{0,40}, {0,33267}, {0,41}]}};
unicode_table(12868) ->
    {0,[],{circle,[{0,21839}]}};
unicode_table(12869) ->
    {0,[],{circle,[{0,24188}]}};
unicode_table(12870) ->
    {0,[],{circle,[{0,25991}]}};
unicode_table(12871) ->
    {0,[],{circle,[{0,31631}]}};
unicode_table(12880) ->
    {0,[],{square,[{0,80}, {0,84}, {0,69}]}};
unicode_table(12881) ->
    {0,[],{circle,[{0,50}, {0,49}]}};
unicode_table(12882) ->
    {0,[],{circle,[{0,50}, {0,50}]}};
unicode_table(12883) ->
    {0,[],{circle,[{0,50}, {0,51}]}};
unicode_table(12884) ->
    {0,[],{circle,[{0,50}, {0,52}]}};
unicode_table(12885) ->
    {0,[],{circle,[{0,50}, {0,53}]}};
unicode_table(12886) ->
    {0,[],{circle,[{0,50}, {0,54}]}};
unicode_table(12887) ->
    {0,[],{circle,[{0,50}, {0,55}]}};
unicode_table(12888) ->
    {0,[],{circle,[{0,50}, {0,56}]}};
unicode_table(12889) ->
    {0,[],{circle,[{0,50}, {0,57}]}};
unicode_table(12890) ->
    {0,[],{circle,[{0,51}, {0,48}]}};
unicode_table(12891) ->
    {0,[],{circle,[{0,51}, {0,49}]}};
unicode_table(12892) ->
    {0,[],{circle,[{0,51}, {0,50}]}};
unicode_table(12893) ->
    {0,[],{circle,[{0,51}, {0,51}]}};
unicode_table(12894) ->
    {0,[],{circle,[{0,51}, {0,52}]}};
unicode_table(12895) ->
    {0,[],{circle,[{0,51}, {0,53}]}};
unicode_table(12896) ->
    {0,[],{circle,[{0,4352}]}};
unicode_table(12897) ->
    {0,[],{circle,[{0,4354}]}};
unicode_table(12898) ->
    {0,[],{circle,[{0,4355}]}};
unicode_table(12899) ->
    {0,[],{circle,[{0,4357}]}};
unicode_table(12900) ->
    {0,[],{circle,[{0,4358}]}};
unicode_table(12901) ->
    {0,[],{circle,[{0,4359}]}};
unicode_table(12902) ->
    {0,[],{circle,[{0,4361}]}};
unicode_table(12903) ->
    {0,[],{circle,[{0,4363}]}};
unicode_table(12904) ->
    {0,[],{circle,[{0,4364}]}};
unicode_table(12905) ->
    {0,[],{circle,[{0,4366}]}};
unicode_table(12906) ->
    {0,[],{circle,[{0,4367}]}};
unicode_table(12907) ->
    {0,[],{circle,[{0,4368}]}};
unicode_table(12908) ->
    {0,[],{circle,[{0,4369}]}};
unicode_table(12909) ->
    {0,[],{circle,[{0,4370}]}};
unicode_table(12910) ->
    {0,[],{circle,[{0,4352}, {0,4449}]}};
unicode_table(12911) ->
    {0,[],{circle,[{0,4354}, {0,4449}]}};
unicode_table(12912) ->
    {0,[],{circle,[{0,4355}, {0,4449}]}};
unicode_table(12913) ->
    {0,[],{circle,[{0,4357}, {0,4449}]}};
unicode_table(12914) ->
    {0,[],{circle,[{0,4358}, {0,4449}]}};
unicode_table(12915) ->
    {0,[],{circle,[{0,4359}, {0,4449}]}};
unicode_table(12916) ->
    {0,[],{circle,[{0,4361}, {0,4449}]}};
unicode_table(12917) ->
    {0,[],{circle,[{0,4363}, {0,4449}]}};
unicode_table(12918) ->
    {0,[],{circle,[{0,4364}, {0,4449}]}};
unicode_table(12919) ->
    {0,[],{circle,[{0,4366}, {0,4449}]}};
unicode_table(12920) ->
    {0,[],{circle,[{0,4367}, {0,4449}]}};
unicode_table(12921) ->
    {0,[],{circle,[{0,4368}, {0,4449}]}};
unicode_table(12922) ->
    {0,[],{circle,[{0,4369}, {0,4449}]}};
unicode_table(12923) ->
    {0,[],{circle,[{0,4370}, {0,4449}]}};
unicode_table(12924) ->
    {0,[],{circle,[{0,4366}, {0,4449}, {0,4535}, {0,4352}, {0,4457}]}};
unicode_table(12925) ->
    {0,[],{circle,[{0,4364}, {0,4462}, {0,4363}, {0,4468}]}};
unicode_table(12926) ->
    {0,[],{circle,[{0,4363}, {0,4462}]}};
unicode_table(12928) ->
    {0,[],{circle,[{0,19968}]}};
unicode_table(12929) ->
    {0,[],{circle,[{0,20108}]}};
unicode_table(12930) ->
    {0,[],{circle,[{0,19977}]}};
unicode_table(12931) ->
    {0,[],{circle,[{0,22235}]}};
unicode_table(12932) ->
    {0,[],{circle,[{0,20116}]}};
unicode_table(12933) ->
    {0,[],{circle,[{0,20845}]}};
unicode_table(12934) ->
    {0,[],{circle,[{0,19971}]}};
unicode_table(12935) ->
    {0,[],{circle,[{0,20843}]}};
unicode_table(12936) ->
    {0,[],{circle,[{0,20061}]}};
unicode_table(12937) ->
    {0,[],{circle,[{0,21313}]}};
unicode_table(12938) ->
    {0,[],{circle,[{0,26376}]}};
unicode_table(12939) ->
    {0,[],{circle,[{0,28779}]}};
unicode_table(12940) ->
    {0,[],{circle,[{0,27700}]}};
unicode_table(12941) ->
    {0,[],{circle,[{0,26408}]}};
unicode_table(12942) ->
    {0,[],{circle,[{0,37329}]}};
unicode_table(12943) ->
    {0,[],{circle,[{0,22303}]}};
unicode_table(12944) ->
    {0,[],{circle,[{0,26085}]}};
unicode_table(12945) ->
    {0,[],{circle,[{0,26666}]}};
unicode_table(12946) ->
    {0,[],{circle,[{0,26377}]}};
unicode_table(12947) ->
    {0,[],{circle,[{0,31038}]}};
unicode_table(12948) ->
    {0,[],{circle,[{0,21517}]}};
unicode_table(12949) ->
    {0,[],{circle,[{0,29305}]}};
unicode_table(12950) ->
    {0,[],{circle,[{0,36001}]}};
unicode_table(12951) ->
    {0,[],{circle,[{0,31069}]}};
unicode_table(12952) ->
    {0,[],{circle,[{0,21172}]}};
unicode_table(12953) ->
    {0,[],{circle,[{0,31192}]}};
unicode_table(12954) ->
    {0,[],{circle,[{0,30007}]}};
unicode_table(12955) ->
    {0,[],{circle,[{0,22899}]}};
unicode_table(12956) ->
    {0,[],{circle,[{0,36969}]}};
unicode_table(12957) ->
    {0,[],{circle,[{0,20778}]}};
unicode_table(12958) ->
    {0,[],{circle,[{0,21360}]}};
unicode_table(12959) ->
    {0,[],{circle,[{0,27880}]}};
unicode_table(12960) ->
    {0,[],{circle,[{0,38917}]}};
unicode_table(12961) ->
    {0,[],{circle,[{0,20241}]}};
unicode_table(12962) ->
    {0,[],{circle,[{0,20889}]}};
unicode_table(12963) ->
    {0,[],{circle,[{0,27491}]}};
unicode_table(12964) ->
    {0,[],{circle,[{0,19978}]}};
unicode_table(12965) ->
    {0,[],{circle,[{0,20013}]}};
unicode_table(12966) ->
    {0,[],{circle,[{0,19979}]}};
unicode_table(12967) ->
    {0,[],{circle,[{0,24038}]}};
unicode_table(12968) ->
    {0,[],{circle,[{0,21491}]}};
unicode_table(12969) ->
    {0,[],{circle,[{0,21307}]}};
unicode_table(12970) ->
    {0,[],{circle,[{0,23447}]}};
unicode_table(12971) ->
    {0,[],{circle,[{0,23398}]}};
unicode_table(12972) ->
    {0,[],{circle,[{0,30435}]}};
unicode_table(12973) ->
    {0,[],{circle,[{0,20225}]}};
unicode_table(12974) ->
    {0,[],{circle,[{0,36039}]}};
unicode_table(12975) ->
    {0,[],{circle,[{0,21332}]}};
unicode_table(12976) ->
    {0,[],{circle,[{0,22812}]}};
unicode_table(12977) ->
    {0,[],{circle,[{0,51}, {0,54}]}};
unicode_table(12978) ->
    {0,[],{circle,[{0,51}, {0,55}]}};
unicode_table(12979) ->
    {0,[],{circle,[{0,51}, {0,56}]}};
unicode_table(12980) ->
    {0,[],{circle,[{0,51}, {0,57}]}};
unicode_table(12981) ->
    {0,[],{circle,[{0,52}, {0,48}]}};
unicode_table(12982) ->
    {0,[],{circle,[{0,52}, {0,49}]}};
unicode_table(12983) ->
    {0,[],{circle,[{0,52}, {0,50}]}};
unicode_table(12984) ->
    {0,[],{circle,[{0,52}, {0,51}]}};
unicode_table(12985) ->
    {0,[],{circle,[{0,52}, {0,52}]}};
unicode_table(12986) ->
    {0,[],{circle,[{0,52}, {0,53}]}};
unicode_table(12987) ->
    {0,[],{circle,[{0,52}, {0,54}]}};
unicode_table(12988) ->
    {0,[],{circle,[{0,52}, {0,55}]}};
unicode_table(12989) ->
    {0,[],{circle,[{0,52}, {0,56}]}};
unicode_table(12990) ->
    {0,[],{circle,[{0,52}, {0,57}]}};
unicode_table(12991) ->
    {0,[],{circle,[{0,53}, {0,48}]}};
unicode_table(12992) ->
    {0,[],{compat,[{0,49}, {0,26376}]}};
unicode_table(12993) ->
    {0,[],{compat,[{0,50}, {0,26376}]}};
unicode_table(12994) ->
    {0,[],{compat,[{0,51}, {0,26376}]}};
unicode_table(12995) ->
    {0,[],{compat,[{0,52}, {0,26376}]}};
unicode_table(12996) ->
    {0,[],{compat,[{0,53}, {0,26376}]}};
unicode_table(12997) ->
    {0,[],{compat,[{0,54}, {0,26376}]}};
unicode_table(12998) ->
    {0,[],{compat,[{0,55}, {0,26376}]}};
unicode_table(12999) ->
    {0,[],{compat,[{0,56}, {0,26376}]}};
unicode_table(13000) ->
    {0,[],{compat,[{0,57}, {0,26376}]}};
unicode_table(13001) ->
    {0,[],{compat,[{0,49}, {0,48}, {0,26376}]}};
unicode_table(13002) ->
    {0,[],{compat,[{0,49}, {0,49}, {0,26376}]}};
unicode_table(13003) ->
    {0,[],{compat,[{0,49}, {0,50}, {0,26376}]}};
unicode_table(13004) ->
    {0,[],{square,[{0,72}, {0,103}]}};
unicode_table(13005) ->
    {0,[],{square,[{0,101}, {0,114}, {0,103}]}};
unicode_table(13006) ->
    {0,[],{square,[{0,101}, {0,86}]}};
unicode_table(13007) ->
    {0,[],{square,[{0,76}, {0,84}, {0,68}]}};
unicode_table(13008) ->
    {0,[],{circle,[{0,12450}]}};
unicode_table(13009) ->
    {0,[],{circle,[{0,12452}]}};
unicode_table(13010) ->
    {0,[],{circle,[{0,12454}]}};
unicode_table(13011) ->
    {0,[],{circle,[{0,12456}]}};
unicode_table(13012) ->
    {0,[],{circle,[{0,12458}]}};
unicode_table(13013) ->
    {0,[],{circle,[{0,12459}]}};
unicode_table(13014) ->
    {0,[],{circle,[{0,12461}]}};
unicode_table(13015) ->
    {0,[],{circle,[{0,12463}]}};
unicode_table(13016) ->
    {0,[],{circle,[{0,12465}]}};
unicode_table(13017) ->
    {0,[],{circle,[{0,12467}]}};
unicode_table(13018) ->
    {0,[],{circle,[{0,12469}]}};
unicode_table(13019) ->
    {0,[],{circle,[{0,12471}]}};
unicode_table(13020) ->
    {0,[],{circle,[{0,12473}]}};
unicode_table(13021) ->
    {0,[],{circle,[{0,12475}]}};
unicode_table(13022) ->
    {0,[],{circle,[{0,12477}]}};
unicode_table(13023) ->
    {0,[],{circle,[{0,12479}]}};
unicode_table(13024) ->
    {0,[],{circle,[{0,12481}]}};
unicode_table(13025) ->
    {0,[],{circle,[{0,12484}]}};
unicode_table(13026) ->
    {0,[],{circle,[{0,12486}]}};
unicode_table(13027) ->
    {0,[],{circle,[{0,12488}]}};
unicode_table(13028) ->
    {0,[],{circle,[{0,12490}]}};
unicode_table(13029) ->
    {0,[],{circle,[{0,12491}]}};
unicode_table(13030) ->
    {0,[],{circle,[{0,12492}]}};
unicode_table(13031) ->
    {0,[],{circle,[{0,12493}]}};
unicode_table(13032) ->
    {0,[],{circle,[{0,12494}]}};
unicode_table(13033) ->
    {0,[],{circle,[{0,12495}]}};
unicode_table(13034) ->
    {0,[],{circle,[{0,12498}]}};
unicode_table(13035) ->
    {0,[],{circle,[{0,12501}]}};
unicode_table(13036) ->
    {0,[],{circle,[{0,12504}]}};
unicode_table(13037) ->
    {0,[],{circle,[{0,12507}]}};
unicode_table(13038) ->
    {0,[],{circle,[{0,12510}]}};
unicode_table(13039) ->
    {0,[],{circle,[{0,12511}]}};
unicode_table(13040) ->
    {0,[],{circle,[{0,12512}]}};
unicode_table(13041) ->
    {0,[],{circle,[{0,12513}]}};
unicode_table(13042) ->
    {0,[],{circle,[{0,12514}]}};
unicode_table(13043) ->
    {0,[],{circle,[{0,12516}]}};
unicode_table(13044) ->
    {0,[],{circle,[{0,12518}]}};
unicode_table(13045) ->
    {0,[],{circle,[{0,12520}]}};
unicode_table(13046) ->
    {0,[],{circle,[{0,12521}]}};
unicode_table(13047) ->
    {0,[],{circle,[{0,12522}]}};
unicode_table(13048) ->
    {0,[],{circle,[{0,12523}]}};
unicode_table(13049) ->
    {0,[],{circle,[{0,12524}]}};
unicode_table(13050) ->
    {0,[],{circle,[{0,12525}]}};
unicode_table(13051) ->
    {0,[],{circle,[{0,12527}]}};
unicode_table(13052) ->
    {0,[],{circle,[{0,12528}]}};
unicode_table(13053) ->
    {0,[],{circle,[{0,12529}]}};
unicode_table(13054) ->
    {0,[],{circle,[{0,12530}]}};
unicode_table(13055) ->
    {0,[],{square,[{0,20196}, {0,21644}]}};
unicode_table(13056) ->
    {0,[],{square,[{0,12450}, {0,12495}, {8,12442}, {0,12540}, {0,12488}]}};
unicode_table(13057) ->
    {0,[],{square,[{0,12450}, {0,12523}, {0,12501}, {0,12449}]}};
unicode_table(13058) ->
    {0,[],{square,[{0,12450}, {0,12531}, {0,12504}, {8,12442}, {0,12450}]}};
unicode_table(13059) ->
    {0,[],{square,[{0,12450}, {0,12540}, {0,12523}]}};
unicode_table(13060) ->
    {0,[],{square,[{0,12452}, {0,12491}, {0,12531}, {0,12463}, {8,12441}]}};
unicode_table(13061) ->
    {0,[],{square,[{0,12452}, {0,12531}, {0,12481}]}};
unicode_table(13062) ->
    {0,[],{square,[{0,12454}, {0,12457}, {0,12531}]}};
unicode_table(13063) ->
    {0,[],{square,[{0,12456}, {0,12473}, {0,12463}, {0,12540}, {0,12488}, {8,12441}]}};
unicode_table(13064) ->
    {0,[],{square,[{0,12456}, {0,12540}, {0,12459}, {0,12540}]}};
unicode_table(13065) ->
    {0,[],{square,[{0,12458}, {0,12531}, {0,12473}]}};
unicode_table(13066) ->
    {0,[],{square,[{0,12458}, {0,12540}, {0,12512}]}};
unicode_table(13067) ->
    {0,[],{square,[{0,12459}, {0,12452}, {0,12522}]}};
unicode_table(13068) ->
    {0,[],{square,[{0,12459}, {0,12521}, {0,12483}, {0,12488}]}};
unicode_table(13069) ->
    {0,[],{square,[{0,12459}, {0,12525}, {0,12522}, {0,12540}]}};
unicode_table(13070) ->
    {0,[],{square,[{0,12459}, {8,12441}, {0,12525}, {0,12531}]}};
unicode_table(13071) ->
    {0,[],{square,[{0,12459}, {8,12441}, {0,12531}, {0,12510}]}};
unicode_table(13072) ->
    {0,[],{square,[{0,12461}, {8,12441}, {0,12459}, {8,12441}]}};
unicode_table(13073) ->
    {0,[],{square,[{0,12461}, {8,12441}, {0,12491}, {0,12540}]}};
unicode_table(13074) ->
    {0,[],{square,[{0,12461}, {0,12517}, {0,12522}, {0,12540}]}};
unicode_table(13075) ->
    {0,[],{square,[{0,12461}, {8,12441}, {0,12523}, {0,12479}, {8,12441}, {0,12540}]}};
unicode_table(13076) ->
    {0,[],{square,[{0,12461}, {0,12525}]}};
unicode_table(13077) ->
    {0,[],{square,[{0,12461}, {0,12525}, {0,12463}, {8,12441}, {0,12521}, {0,12512}]}};
unicode_table(13078) ->
    {0,[],{square,[{0,12461}, {0,12525}, {0,12513}, {0,12540}, {0,12488}, {0,12523}]}};
unicode_table(13079) ->
    {0,[],{square,[{0,12461}, {0,12525}, {0,12527}, {0,12483}, {0,12488}]}};
unicode_table(13080) ->
    {0,[],{square,[{0,12463}, {8,12441}, {0,12521}, {0,12512}]}};
unicode_table(13081) ->
    {0,[],{square,[{0,12463}, {8,12441}, {0,12521}, {0,12512}, {0,12488}, {0,12531}]}};
unicode_table(13082) ->
    {0,[],{square,[{0,12463}, {0,12523}, {0,12475}, {8,12441}, {0,12452}, {0,12525}]}};
unicode_table(13083) ->
    {0,[],{square,[{0,12463}, {0,12525}, {0,12540}, {0,12493}]}};
unicode_table(13084) ->
    {0,[],{square,[{0,12465}, {0,12540}, {0,12473}]}};
unicode_table(13085) ->
    {0,[],{square,[{0,12467}, {0,12523}, {0,12490}]}};
unicode_table(13086) ->
    {0,[],{square,[{0,12467}, {0,12540}, {0,12507}, {8,12442}]}};
unicode_table(13087) ->
    {0,[],{square,[{0,12469}, {0,12452}, {0,12463}, {0,12523}]}};
unicode_table(13088) ->
    {0,[],{square,[{0,12469}, {0,12531}, {0,12481}, {0,12540}, {0,12512}]}};
unicode_table(13089) ->
    {0,[],{square,[{0,12471}, {0,12522}, {0,12531}, {0,12463}, {8,12441}]}};
unicode_table(13090) ->
    {0,[],{square,[{0,12475}, {0,12531}, {0,12481}]}};
unicode_table(13091) ->
    {0,[],{square,[{0,12475}, {0,12531}, {0,12488}]}};
unicode_table(13092) ->
    {0,[],{square,[{0,12479}, {8,12441}, {0,12540}, {0,12473}]}};
unicode_table(13093) ->
    {0,[],{square,[{0,12486}, {8,12441}, {0,12471}]}};
unicode_table(13094) ->
    {0,[],{square,[{0,12488}, {8,12441}, {0,12523}]}};
unicode_table(13095) ->
    {0,[],{square,[{0,12488}, {0,12531}]}};
unicode_table(13096) ->
    {0,[],{square,[{0,12490}, {0,12494}]}};
unicode_table(13097) ->
    {0,[],{square,[{0,12494}, {0,12483}, {0,12488}]}};
unicode_table(13098) ->
    {0,[],{square,[{0,12495}, {0,12452}, {0,12484}]}};
unicode_table(13099) ->
    {0,[],{square,[{0,12495}, {8,12442}, {0,12540}, {0,12475}, {0,12531}, {0,12488}]}};
unicode_table(13100) ->
    {0,[],{square,[{0,12495}, {8,12442}, {0,12540}, {0,12484}]}};
unicode_table(13101) ->
    {0,[],{square,[{0,12495}, {8,12441}, {0,12540}, {0,12524}, {0,12523}]}};
unicode_table(13102) ->
    {0,[],{square,[{0,12498}, {8,12442}, {0,12450}, {0,12473}, {0,12488}, {0,12523}]}};
unicode_table(13103) ->
    {0,[],{square,[{0,12498}, {8,12442}, {0,12463}, {0,12523}]}};
unicode_table(13104) ->
    {0,[],{square,[{0,12498}, {8,12442}, {0,12467}]}};
unicode_table(13105) ->
    {0,[],{square,[{0,12498}, {8,12441}, {0,12523}]}};
unicode_table(13106) ->
    {0,[],{square,[{0,12501}, {0,12449}, {0,12521}, {0,12483}, {0,12488}, {8,12441}]}};
unicode_table(13107) ->
    {0,[],{square,[{0,12501}, {0,12451}, {0,12540}, {0,12488}]}};
unicode_table(13108) ->
    {0,[],{square,[{0,12501}, {8,12441}, {0,12483}, {0,12471}, {0,12455}, {0,12523}]}};
unicode_table(13109) ->
    {0,[],{square,[{0,12501}, {0,12521}, {0,12531}]}};
unicode_table(13110) ->
    {0,[],{square,[{0,12504}, {0,12463}, {0,12479}, {0,12540}, {0,12523}]}};
unicode_table(13111) ->
    {0,[],{square,[{0,12504}, {8,12442}, {0,12477}]}};
unicode_table(13112) ->
    {0,[],{square,[{0,12504}, {8,12442}, {0,12491}, {0,12498}]}};
unicode_table(13113) ->
    {0,[],{square,[{0,12504}, {0,12523}, {0,12484}]}};
unicode_table(13114) ->
    {0,[],{square,[{0,12504}, {8,12442}, {0,12531}, {0,12473}]}};
unicode_table(13115) ->
    {0,[],{square,[{0,12504}, {8,12442}, {0,12540}, {0,12471}, {8,12441}]}};
unicode_table(13116) ->
    {0,[],{square,[{0,12504}, {8,12441}, {0,12540}, {0,12479}]}};
unicode_table(13117) ->
    {0,[],{square,[{0,12507}, {8,12442}, {0,12452}, {0,12531}, {0,12488}]}};
unicode_table(13118) ->
    {0,[],{square,[{0,12507}, {8,12441}, {0,12523}, {0,12488}]}};
unicode_table(13119) ->
    {0,[],{square,[{0,12507}, {0,12531}]}};
unicode_table(13120) ->
    {0,[],{square,[{0,12507}, {8,12442}, {0,12531}, {0,12488}, {8,12441}]}};
unicode_table(13121) ->
    {0,[],{square,[{0,12507}, {0,12540}, {0,12523}]}};
unicode_table(13122) ->
    {0,[],{square,[{0,12507}, {0,12540}, {0,12531}]}};
unicode_table(13123) ->
    {0,[],{square,[{0,12510}, {0,12452}, {0,12463}, {0,12525}]}};
unicode_table(13124) ->
    {0,[],{square,[{0,12510}, {0,12452}, {0,12523}]}};
unicode_table(13125) ->
    {0,[],{square,[{0,12510}, {0,12483}, {0,12495}]}};
unicode_table(13126) ->
    {0,[],{square,[{0,12510}, {0,12523}, {0,12463}]}};
unicode_table(13127) ->
    {0,[],{square,[{0,12510}, {0,12531}, {0,12471}, {0,12519}, {0,12531}]}};
unicode_table(13128) ->
    {0,[],{square,[{0,12511}, {0,12463}, {0,12525}, {0,12531}]}};
unicode_table(13129) ->
    {0,[],{square,[{0,12511}, {0,12522}]}};
unicode_table(13130) ->
    {0,[],{square,[{0,12511}, {0,12522}, {0,12495}, {8,12441}, {0,12540}, {0,12523}]}};
unicode_table(13131) ->
    {0,[],{square,[{0,12513}, {0,12459}, {8,12441}]}};
unicode_table(13132) ->
    {0,[],{square,[{0,12513}, {0,12459}, {8,12441}, {0,12488}, {0,12531}]}};
unicode_table(13133) ->
    {0,[],{square,[{0,12513}, {0,12540}, {0,12488}, {0,12523}]}};
unicode_table(13134) ->
    {0,[],{square,[{0,12516}, {0,12540}, {0,12488}, {8,12441}]}};
unicode_table(13135) ->
    {0,[],{square,[{0,12516}, {0,12540}, {0,12523}]}};
unicode_table(13136) ->
    {0,[],{square,[{0,12518}, {0,12450}, {0,12531}]}};
unicode_table(13137) ->
    {0,[],{square,[{0,12522}, {0,12483}, {0,12488}, {0,12523}]}};
unicode_table(13138) ->
    {0,[],{square,[{0,12522}, {0,12521}]}};
unicode_table(13139) ->
    {0,[],{square,[{0,12523}, {0,12498}, {8,12442}, {0,12540}]}};
unicode_table(13140) ->
    {0,[],{square,[{0,12523}, {0,12540}, {0,12501}, {8,12441}, {0,12523}]}};
unicode_table(13141) ->
    {0,[],{square,[{0,12524}, {0,12512}]}};
unicode_table(13142) ->
    {0,[],{square,[{0,12524}, {0,12531}, {0,12488}, {0,12465}, {8,12441}, {0,12531}]}};
unicode_table(13143) ->
    {0,[],{square,[{0,12527}, {0,12483}, {0,12488}]}};
unicode_table(13144) ->
    {0,[],{compat,[{0,48}, {0,28857}]}};
unicode_table(13145) ->
    {0,[],{compat,[{0,49}, {0,28857}]}};
unicode_table(13146) ->
    {0,[],{compat,[{0,50}, {0,28857}]}};
unicode_table(13147) ->
    {0,[],{compat,[{0,51}, {0,28857}]}};
unicode_table(13148) ->
    {0,[],{compat,[{0,52}, {0,28857}]}};
unicode_table(13149) ->
    {0,[],{compat,[{0,53}, {0,28857}]}};
unicode_table(13150) ->
    {0,[],{compat,[{0,54}, {0,28857}]}};
unicode_table(13151) ->
    {0,[],{compat,[{0,55}, {0,28857}]}};
unicode_table(13152) ->
    {0,[],{compat,[{0,56}, {0,28857}]}};
unicode_table(13153) ->
    {0,[],{compat,[{0,57}, {0,28857}]}};
unicode_table(13154) ->
    {0,[],{compat,[{0,49}, {0,48}, {0,28857}]}};
unicode_table(13155) ->
    {0,[],{compat,[{0,49}, {0,49}, {0,28857}]}};
unicode_table(13156) ->
    {0,[],{compat,[{0,49}, {0,50}, {0,28857}]}};
unicode_table(13157) ->
    {0,[],{compat,[{0,49}, {0,51}, {0,28857}]}};
unicode_table(13158) ->
    {0,[],{compat,[{0,49}, {0,52}, {0,28857}]}};
unicode_table(13159) ->
    {0,[],{compat,[{0,49}, {0,53}, {0,28857}]}};
unicode_table(13160) ->
    {0,[],{compat,[{0,49}, {0,54}, {0,28857}]}};
unicode_table(13161) ->
    {0,[],{compat,[{0,49}, {0,55}, {0,28857}]}};
unicode_table(13162) ->
    {0,[],{compat,[{0,49}, {0,56}, {0,28857}]}};
unicode_table(13163) ->
    {0,[],{compat,[{0,49}, {0,57}, {0,28857}]}};
unicode_table(13164) ->
    {0,[],{compat,[{0,50}, {0,48}, {0,28857}]}};
unicode_table(13165) ->
    {0,[],{compat,[{0,50}, {0,49}, {0,28857}]}};
unicode_table(13166) ->
    {0,[],{compat,[{0,50}, {0,50}, {0,28857}]}};
unicode_table(13167) ->
    {0,[],{compat,[{0,50}, {0,51}, {0,28857}]}};
unicode_table(13168) ->
    {0,[],{compat,[{0,50}, {0,52}, {0,28857}]}};
unicode_table(13169) ->
    {0,[],{square,[{0,104}, {0,80}, {0,97}]}};
unicode_table(13170) ->
    {0,[],{square,[{0,100}, {0,97}]}};
unicode_table(13171) ->
    {0,[],{square,[{0,65}, {0,85}]}};
unicode_table(13172) ->
    {0,[],{square,[{0,98}, {0,97}, {0,114}]}};
unicode_table(13173) ->
    {0,[],{square,[{0,111}, {0,86}]}};
unicode_table(13174) ->
    {0,[],{square,[{0,112}, {0,99}]}};
unicode_table(13175) ->
    {0,[],{square,[{0,100}, {0,109}]}};
unicode_table(13176) ->
    {0,[],{square,[{0,100}, {0,109}, {0,50}]}};
unicode_table(13177) ->
    {0,[],{square,[{0,100}, {0,109}, {0,51}]}};
unicode_table(13178) ->
    {0,[],{square,[{0,73}, {0,85}]}};
unicode_table(13179) ->
    {0,[],{square,[{0,24179}, {0,25104}]}};
unicode_table(13180) ->
    {0,[],{square,[{0,26157}, {0,21644}]}};
unicode_table(13181) ->
    {0,[],{square,[{0,22823}, {0,27491}]}};
unicode_table(13182) ->
    {0,[],{square,[{0,26126}, {0,27835}]}};
unicode_table(13183) ->
    {0,[],{square,[{0,26666}, {0,24335}, {0,20250}, {0,31038}]}};
unicode_table(13184) ->
    {0,[],{square,[{0,112}, {0,65}]}};
unicode_table(13185) ->
    {0,[],{square,[{0,110}, {0,65}]}};
unicode_table(13186) ->
    {0,[],{square,[{0,956}, {0,65}]}};
unicode_table(13187) ->
    {0,[],{square,[{0,109}, {0,65}]}};
unicode_table(13188) ->
    {0,[],{square,[{0,107}, {0,65}]}};
unicode_table(13189) ->
    {0,[],{square,[{0,75}, {0,66}]}};
unicode_table(13190) ->
    {0,[],{square,[{0,77}, {0,66}]}};
unicode_table(13191) ->
    {0,[],{square,[{0,71}, {0,66}]}};
unicode_table(13192) ->
    {0,[],{square,[{0,99}, {0,97}, {0,108}]}};
unicode_table(13193) ->
    {0,[],{square,[{0,107}, {0,99}, {0,97}, {0,108}]}};
unicode_table(13194) ->
    {0,[],{square,[{0,112}, {0,70}]}};
unicode_table(13195) ->
    {0,[],{square,[{0,110}, {0,70}]}};
unicode_table(13196) ->
    {0,[],{square,[{0,956}, {0,70}]}};
unicode_table(13197) ->
    {0,[],{square,[{0,956}, {0,103}]}};
unicode_table(13198) ->
    {0,[],{square,[{0,109}, {0,103}]}};
unicode_table(13199) ->
    {0,[],{square,[{0,107}, {0,103}]}};
unicode_table(13200) ->
    {0,[],{square,[{0,72}, {0,122}]}};
unicode_table(13201) ->
    {0,[],{square,[{0,107}, {0,72}, {0,122}]}};
unicode_table(13202) ->
    {0,[],{square,[{0,77}, {0,72}, {0,122}]}};
unicode_table(13203) ->
    {0,[],{square,[{0,71}, {0,72}, {0,122}]}};
unicode_table(13204) ->
    {0,[],{square,[{0,84}, {0,72}, {0,122}]}};
unicode_table(13205) ->
    {0,[],{square,[{0,956}, {0,108}]}};
unicode_table(13206) ->
    {0,[],{square,[{0,109}, {0,108}]}};
unicode_table(13207) ->
    {0,[],{square,[{0,100}, {0,108}]}};
unicode_table(13208) ->
    {0,[],{square,[{0,107}, {0,108}]}};
unicode_table(13209) ->
    {0,[],{square,[{0,102}, {0,109}]}};
unicode_table(13210) ->
    {0,[],{square,[{0,110}, {0,109}]}};
unicode_table(13211) ->
    {0,[],{square,[{0,956}, {0,109}]}};
unicode_table(13212) ->
    {0,[],{square,[{0,109}, {0,109}]}};
unicode_table(13213) ->
    {0,[],{square,[{0,99}, {0,109}]}};
unicode_table(13214) ->
    {0,[],{square,[{0,107}, {0,109}]}};
unicode_table(13215) ->
    {0,[],{square,[{0,109}, {0,109}, {0,50}]}};
unicode_table(13216) ->
    {0,[],{square,[{0,99}, {0,109}, {0,50}]}};
unicode_table(13217) ->
    {0,[],{square,[{0,109}, {0,50}]}};
unicode_table(13218) ->
    {0,[],{square,[{0,107}, {0,109}, {0,50}]}};
unicode_table(13219) ->
    {0,[],{square,[{0,109}, {0,109}, {0,51}]}};
unicode_table(13220) ->
    {0,[],{square,[{0,99}, {0,109}, {0,51}]}};
unicode_table(13221) ->
    {0,[],{square,[{0,109}, {0,51}]}};
unicode_table(13222) ->
    {0,[],{square,[{0,107}, {0,109}, {0,51}]}};
unicode_table(13223) ->
    {0,[],{square,[{0,109}, {0,8725}, {0,115}]}};
unicode_table(13224) ->
    {0,[],{square,[{0,109}, {0,8725}, {0,115}, {0,50}]}};
unicode_table(13225) ->
    {0,[],{square,[{0,80}, {0,97}]}};
unicode_table(13226) ->
    {0,[],{square,[{0,107}, {0,80}, {0,97}]}};
unicode_table(13227) ->
    {0,[],{square,[{0,77}, {0,80}, {0,97}]}};
unicode_table(13228) ->
    {0,[],{square,[{0,71}, {0,80}, {0,97}]}};
unicode_table(13229) ->
    {0,[],{square,[{0,114}, {0,97}, {0,100}]}};
unicode_table(13230) ->
    {0,[],{square,[{0,114}, {0,97}, {0,100}, {0,8725}, {0,115}]}};
unicode_table(13231) ->
    {0,[],{square,[{0,114}, {0,97}, {0,100}, {0,8725}, {0,115}, {0,50}]}};
unicode_table(13232) ->
    {0,[],{square,[{0,112}, {0,115}]}};
unicode_table(13233) ->
    {0,[],{square,[{0,110}, {0,115}]}};
unicode_table(13234) ->
    {0,[],{square,[{0,956}, {0,115}]}};
unicode_table(13235) ->
    {0,[],{square,[{0,109}, {0,115}]}};
unicode_table(13236) ->
    {0,[],{square,[{0,112}, {0,86}]}};
unicode_table(13237) ->
    {0,[],{square,[{0,110}, {0,86}]}};
unicode_table(13238) ->
    {0,[],{square,[{0,956}, {0,86}]}};
unicode_table(13239) ->
    {0,[],{square,[{0,109}, {0,86}]}};
unicode_table(13240) ->
    {0,[],{square,[{0,107}, {0,86}]}};
unicode_table(13241) ->
    {0,[],{square,[{0,77}, {0,86}]}};
unicode_table(13242) ->
    {0,[],{square,[{0,112}, {0,87}]}};
unicode_table(13243) ->
    {0,[],{square,[{0,110}, {0,87}]}};
unicode_table(13244) ->
    {0,[],{square,[{0,956}, {0,87}]}};
unicode_table(13245) ->
    {0,[],{square,[{0,109}, {0,87}]}};
unicode_table(13246) ->
    {0,[],{square,[{0,107}, {0,87}]}};
unicode_table(13247) ->
    {0,[],{square,[{0,77}, {0,87}]}};
unicode_table(13248) ->
    {0,[],{square,[{0,107}, {0,937}]}};
unicode_table(13249) ->
    {0,[],{square,[{0,77}, {0,937}]}};
unicode_table(13250) ->
    {0,[],{square,[{0,97}, {0,46}, {0,109}, {0,46}]}};
unicode_table(13251) ->
    {0,[],{square,[{0,66}, {0,113}]}};
unicode_table(13252) ->
    {0,[],{square,[{0,99}, {0,99}]}};
unicode_table(13253) ->
    {0,[],{square,[{0,99}, {0,100}]}};
unicode_table(13254) ->
    {0,[],{square,[{0,67}, {0,8725}, {0,107}, {0,103}]}};
unicode_table(13255) ->
    {0,[],{square,[{0,67}, {0,111}, {0,46}]}};
unicode_table(13256) ->
    {0,[],{square,[{0,100}, {0,66}]}};
unicode_table(13257) ->
    {0,[],{square,[{0,71}, {0,121}]}};
unicode_table(13258) ->
    {0,[],{square,[{0,104}, {0,97}]}};
unicode_table(13259) ->
    {0,[],{square,[{0,72}, {0,80}]}};
unicode_table(13260) ->
    {0,[],{square,[{0,105}, {0,110}]}};
unicode_table(13261) ->
    {0,[],{square,[{0,75}, {0,75}]}};
unicode_table(13262) ->
    {0,[],{square,[{0,75}, {0,77}]}};
unicode_table(13263) ->
    {0,[],{square,[{0,107}, {0,116}]}};
unicode_table(13264) ->
    {0,[],{square,[{0,108}, {0,109}]}};
unicode_table(13265) ->
    {0,[],{square,[{0,108}, {0,110}]}};
unicode_table(13266) ->
    {0,[],{square,[{0,108}, {0,111}, {0,103}]}};
unicode_table(13267) ->
    {0,[],{square,[{0,108}, {0,120}]}};
unicode_table(13268) ->
    {0,[],{square,[{0,109}, {0,98}]}};
unicode_table(13269) ->
    {0,[],{square,[{0,109}, {0,105}, {0,108}]}};
unicode_table(13270) ->
    {0,[],{square,[{0,109}, {0,111}, {0,108}]}};
unicode_table(13271) ->
    {0,[],{square,[{0,80}, {0,72}]}};
unicode_table(13272) ->
    {0,[],{square,[{0,112}, {0,46}, {0,109}, {0,46}]}};
unicode_table(13273) ->
    {0,[],{square,[{0,80}, {0,80}, {0,77}]}};
unicode_table(13274) ->
    {0,[],{square,[{0,80}, {0,82}]}};
unicode_table(13275) ->
    {0,[],{square,[{0,115}, {0,114}]}};
unicode_table(13276) ->
    {0,[],{square,[{0,83}, {0,118}]}};
unicode_table(13277) ->
    {0,[],{square,[{0,87}, {0,98}]}};
unicode_table(13278) ->
    {0,[],{square,[{0,86}, {0,8725}, {0,109}]}};
unicode_table(13279) ->
    {0,[],{square,[{0,65}, {0,8725}, {0,109}]}};
unicode_table(13280) ->
    {0,[],{compat,[{0,49}, {0,26085}]}};
unicode_table(13281) ->
    {0,[],{compat,[{0,50}, {0,26085}]}};
unicode_table(13282) ->
    {0,[],{compat,[{0,51}, {0,26085}]}};
unicode_table(13283) ->
    {0,[],{compat,[{0,52}, {0,26085}]}};
unicode_table(13284) ->
    {0,[],{compat,[{0,53}, {0,26085}]}};
unicode_table(13285) ->
    {0,[],{compat,[{0,54}, {0,26085}]}};
unicode_table(13286) ->
    {0,[],{compat,[{0,55}, {0,26085}]}};
unicode_table(13287) ->
    {0,[],{compat,[{0,56}, {0,26085}]}};
unicode_table(13288) ->
    {0,[],{compat,[{0,57}, {0,26085}]}};
unicode_table(13289) ->
    {0,[],{compat,[{0,49}, {0,48}, {0,26085}]}};
unicode_table(13290) ->
    {0,[],{compat,[{0,49}, {0,49}, {0,26085}]}};
unicode_table(13291) ->
    {0,[],{compat,[{0,49}, {0,50}, {0,26085}]}};
unicode_table(13292) ->
    {0,[],{compat,[{0,49}, {0,51}, {0,26085}]}};
unicode_table(13293) ->
    {0,[],{compat,[{0,49}, {0,52}, {0,26085}]}};
unicode_table(13294) ->
    {0,[],{compat,[{0,49}, {0,53}, {0,26085}]}};
unicode_table(13295) ->
    {0,[],{compat,[{0,49}, {0,54}, {0,26085}]}};
unicode_table(13296) ->
    {0,[],{compat,[{0,49}, {0,55}, {0,26085}]}};
unicode_table(13297) ->
    {0,[],{compat,[{0,49}, {0,56}, {0,26085}]}};
unicode_table(13298) ->
    {0,[],{compat,[{0,49}, {0,57}, {0,26085}]}};
unicode_table(13299) ->
    {0,[],{compat,[{0,50}, {0,48}, {0,26085}]}};
unicode_table(13300) ->
    {0,[],{compat,[{0,50}, {0,49}, {0,26085}]}};
unicode_table(13301) ->
    {0,[],{compat,[{0,50}, {0,50}, {0,26085}]}};
unicode_table(13302) ->
    {0,[],{compat,[{0,50}, {0,51}, {0,26085}]}};
unicode_table(13303) ->
    {0,[],{compat,[{0,50}, {0,52}, {0,26085}]}};
unicode_table(13304) ->
    {0,[],{compat,[{0,50}, {0,53}, {0,26085}]}};
unicode_table(13305) ->
    {0,[],{compat,[{0,50}, {0,54}, {0,26085}]}};
unicode_table(13306) ->
    {0,[],{compat,[{0,50}, {0,55}, {0,26085}]}};
unicode_table(13307) ->
    {0,[],{compat,[{0,50}, {0,56}, {0,26085}]}};
unicode_table(13308) ->
    {0,[],{compat,[{0,50}, {0,57}, {0,26085}]}};
unicode_table(13309) ->
    {0,[],{compat,[{0,51}, {0,48}, {0,26085}]}};
unicode_table(13310) ->
    {0,[],{compat,[{0,51}, {0,49}, {0,26085}]}};
unicode_table(13311) ->
    {0,[],{square,[{0,103}, {0,97}, {0,108}]}};
unicode_table(42607) ->
    {230,[],[]};
unicode_table(42612) ->
    {230,[],[]};
unicode_table(42613) ->
    {230,[],[]};
unicode_table(42614) ->
    {230,[],[]};
unicode_table(42615) ->
    {230,[],[]};
unicode_table(42616) ->
    {230,[],[]};
unicode_table(42617) ->
    {230,[],[]};
unicode_table(42618) ->
    {230,[],[]};
unicode_table(42619) ->
    {230,[],[]};
unicode_table(42620) ->
    {230,[],[]};
unicode_table(42621) ->
    {230,[],[]};
unicode_table(42652) ->
    {0,[],{super,[{0,1098}]}};
unicode_table(42653) ->
    {0,[],{super,[{0,1100}]}};
unicode_table(42654) ->
    {230,[],[]};
unicode_table(42655) ->
    {230,[],[]};
unicode_table(42736) ->
    {230,[],[]};
unicode_table(42737) ->
    {230,[],[]};
unicode_table(42864) ->
    {0,[],{super,[{0,42863}]}};
unicode_table(43000) ->
    {0,[],{super,[{0,294}]}};
unicode_table(43001) ->
    {0,[],{super,[{0,339}]}};
unicode_table(43014) ->
    {9,[],[]};
unicode_table(43204) ->
    {9,[],[]};
unicode_table(43232) ->
    {230,[],[]};
unicode_table(43233) ->
    {230,[],[]};
unicode_table(43234) ->
    {230,[],[]};
unicode_table(43235) ->
    {230,[],[]};
unicode_table(43236) ->
    {230,[],[]};
unicode_table(43237) ->
    {230,[],[]};
unicode_table(43238) ->
    {230,[],[]};
unicode_table(43239) ->
    {230,[],[]};
unicode_table(43240) ->
    {230,[],[]};
unicode_table(43241) ->
    {230,[],[]};
unicode_table(43242) ->
    {230,[],[]};
unicode_table(43243) ->
    {230,[],[]};
unicode_table(43244) ->
    {230,[],[]};
unicode_table(43245) ->
    {230,[],[]};
unicode_table(43246) ->
    {230,[],[]};
unicode_table(43247) ->
    {230,[],[]};
unicode_table(43248) ->
    {230,[],[]};
unicode_table(43249) ->
    {230,[],[]};
unicode_table(43307) ->
    {220,[],[]};
unicode_table(43308) ->
    {220,[],[]};
unicode_table(43309) ->
    {220,[],[]};
unicode_table(43347) ->
    {9,[],[]};
unicode_table(43443) ->
    {7,[],[]};
unicode_table(43456) ->
    {9,[],[]};
unicode_table(43696) ->
    {230,[],[]};
unicode_table(43698) ->
    {230,[],[]};
unicode_table(43699) ->
    {230,[],[]};
unicode_table(43700) ->
    {220,[],[]};
unicode_table(43703) ->
    {230,[],[]};
unicode_table(43704) ->
    {230,[],[]};
unicode_table(43710) ->
    {230,[],[]};
unicode_table(43711) ->
    {230,[],[]};
unicode_table(43713) ->
    {230,[],[]};
unicode_table(43766) ->
    {9,[],[]};
unicode_table(43868) ->
    {0,[],{super,[{0,42791}]}};
unicode_table(43869) ->
    {0,[],{super,[{0,43831}]}};
unicode_table(43870) ->
    {0,[],{super,[{0,619}]}};
unicode_table(43871) ->
    {0,[],{super,[{0,43858}]}};
unicode_table(44013) ->
    {9,[],[]};
unicode_table(63744) ->
    {0,[{0,35912}],[]};
unicode_table(63745) ->
    {0,[{0,26356}],[]};
unicode_table(63746) ->
    {0,[{0,36554}],[]};
unicode_table(63747) ->
    {0,[{0,36040}],[]};
unicode_table(63748) ->
    {0,[{0,28369}],[]};
unicode_table(63749) ->
    {0,[{0,20018}],[]};
unicode_table(63750) ->
    {0,[{0,21477}],[]};
unicode_table(63751) ->
    {0,[{0,40860}],[]};
unicode_table(63752) ->
    {0,[{0,40860}],[]};
unicode_table(63753) ->
    {0,[{0,22865}],[]};
unicode_table(63754) ->
    {0,[{0,37329}],[]};
unicode_table(63755) ->
    {0,[{0,21895}],[]};
unicode_table(63756) ->
    {0,[{0,22856}],[]};
unicode_table(63757) ->
    {0,[{0,25078}],[]};
unicode_table(63758) ->
    {0,[{0,30313}],[]};
unicode_table(63759) ->
    {0,[{0,32645}],[]};
unicode_table(63760) ->
    {0,[{0,34367}],[]};
unicode_table(63761) ->
    {0,[{0,34746}],[]};
unicode_table(63762) ->
    {0,[{0,35064}],[]};
unicode_table(63763) ->
    {0,[{0,37007}],[]};
unicode_table(63764) ->
    {0,[{0,27138}],[]};
unicode_table(63765) ->
    {0,[{0,27931}],[]};
unicode_table(63766) ->
    {0,[{0,28889}],[]};
unicode_table(63767) ->
    {0,[{0,29662}],[]};
unicode_table(63768) ->
    {0,[{0,33853}],[]};
unicode_table(63769) ->
    {0,[{0,37226}],[]};
unicode_table(63770) ->
    {0,[{0,39409}],[]};
unicode_table(63771) ->
    {0,[{0,20098}],[]};
unicode_table(63772) ->
    {0,[{0,21365}],[]};
unicode_table(63773) ->
    {0,[{0,27396}],[]};
unicode_table(63774) ->
    {0,[{0,29211}],[]};
unicode_table(63775) ->
    {0,[{0,34349}],[]};
unicode_table(63776) ->
    {0,[{0,40478}],[]};
unicode_table(63777) ->
    {0,[{0,23888}],[]};
unicode_table(63778) ->
    {0,[{0,28651}],[]};
unicode_table(63779) ->
    {0,[{0,34253}],[]};
unicode_table(63780) ->
    {0,[{0,35172}],[]};
unicode_table(63781) ->
    {0,[{0,25289}],[]};
unicode_table(63782) ->
    {0,[{0,33240}],[]};
unicode_table(63783) ->
    {0,[{0,34847}],[]};
unicode_table(63784) ->
    {0,[{0,24266}],[]};
unicode_table(63785) ->
    {0,[{0,26391}],[]};
unicode_table(63786) ->
    {0,[{0,28010}],[]};
unicode_table(63787) ->
    {0,[{0,29436}],[]};
unicode_table(63788) ->
    {0,[{0,37070}],[]};
unicode_table(63789) ->
    {0,[{0,20358}],[]};
unicode_table(63790) ->
    {0,[{0,20919}],[]};
unicode_table(63791) ->
    {0,[{0,21214}],[]};
unicode_table(63792) ->
    {0,[{0,25796}],[]};
unicode_table(63793) ->
    {0,[{0,27347}],[]};
unicode_table(63794) ->
    {0,[{0,29200}],[]};
unicode_table(63795) ->
    {0,[{0,30439}],[]};
unicode_table(63796) ->
    {0,[{0,32769}],[]};
unicode_table(63797) ->
    {0,[{0,34310}],[]};
unicode_table(63798) ->
    {0,[{0,34396}],[]};
unicode_table(63799) ->
    {0,[{0,36335}],[]};
unicode_table(63800) ->
    {0,[{0,38706}],[]};
unicode_table(63801) ->
    {0,[{0,39791}],[]};
unicode_table(63802) ->
    {0,[{0,40442}],[]};
unicode_table(63803) ->
    {0,[{0,30860}],[]};
unicode_table(63804) ->
    {0,[{0,31103}],[]};
unicode_table(63805) ->
    {0,[{0,32160}],[]};
unicode_table(63806) ->
    {0,[{0,33737}],[]};
unicode_table(63807) ->
    {0,[{0,37636}],[]};
unicode_table(63808) ->
    {0,[{0,40575}],[]};
unicode_table(63809) ->
    {0,[{0,35542}],[]};
unicode_table(63810) ->
    {0,[{0,22751}],[]};
unicode_table(63811) ->
    {0,[{0,24324}],[]};
unicode_table(63812) ->
    {0,[{0,31840}],[]};
unicode_table(63813) ->
    {0,[{0,32894}],[]};
unicode_table(63814) ->
    {0,[{0,29282}],[]};
unicode_table(63815) ->
    {0,[{0,30922}],[]};
unicode_table(63816) ->
    {0,[{0,36034}],[]};
unicode_table(63817) ->
    {0,[{0,38647}],[]};
unicode_table(63818) ->
    {0,[{0,22744}],[]};
unicode_table(63819) ->
    {0,[{0,23650}],[]};
unicode_table(63820) ->
    {0,[{0,27155}],[]};
unicode_table(63821) ->
    {0,[{0,28122}],[]};
unicode_table(63822) ->
    {0,[{0,28431}],[]};
unicode_table(63823) ->
    {0,[{0,32047}],[]};
unicode_table(63824) ->
    {0,[{0,32311}],[]};
unicode_table(63825) ->
    {0,[{0,38475}],[]};
unicode_table(63826) ->
    {0,[{0,21202}],[]};
unicode_table(63827) ->
    {0,[{0,32907}],[]};
unicode_table(63828) ->
    {0,[{0,20956}],[]};
unicode_table(63829) ->
    {0,[{0,20940}],[]};
unicode_table(63830) ->
    {0,[{0,31260}],[]};
unicode_table(63831) ->
    {0,[{0,32190}],[]};
unicode_table(63832) ->
    {0,[{0,33777}],[]};
unicode_table(63833) ->
    {0,[{0,38517}],[]};
unicode_table(63834) ->
    {0,[{0,35712}],[]};
unicode_table(63835) ->
    {0,[{0,25295}],[]};
unicode_table(63836) ->
    {0,[{0,27138}],[]};
unicode_table(63837) ->
    {0,[{0,35582}],[]};
unicode_table(63838) ->
    {0,[{0,20025}],[]};
unicode_table(63839) ->
    {0,[{0,23527}],[]};
unicode_table(63840) ->
    {0,[{0,24594}],[]};
unicode_table(63841) ->
    {0,[{0,29575}],[]};
unicode_table(63842) ->
    {0,[{0,30064}],[]};
unicode_table(63843) ->
    {0,[{0,21271}],[]};
unicode_table(63844) ->
    {0,[{0,30971}],[]};
unicode_table(63845) ->
    {0,[{0,20415}],[]};
unicode_table(63846) ->
    {0,[{0,24489}],[]};
unicode_table(63847) ->
    {0,[{0,19981}],[]};
unicode_table(63848) ->
    {0,[{0,27852}],[]};
unicode_table(63849) ->
    {0,[{0,25976}],[]};
unicode_table(63850) ->
    {0,[{0,32034}],[]};
unicode_table(63851) ->
    {0,[{0,21443}],[]};
unicode_table(63852) ->
    {0,[{0,22622}],[]};
unicode_table(63853) ->
    {0,[{0,30465}],[]};
unicode_table(63854) ->
    {0,[{0,33865}],[]};
unicode_table(63855) ->
    {0,[{0,35498}],[]};
unicode_table(63856) ->
    {0,[{0,27578}],[]};
unicode_table(63857) ->
    {0,[{0,36784}],[]};
unicode_table(63858) ->
    {0,[{0,27784}],[]};
unicode_table(63859) ->
    {0,[{0,25342}],[]};
unicode_table(63860) ->
    {0,[{0,33509}],[]};
unicode_table(63861) ->
    {0,[{0,25504}],[]};
unicode_table(63862) ->
    {0,[{0,30053}],[]};
unicode_table(63863) ->
    {0,[{0,20142}],[]};
unicode_table(63864) ->
    {0,[{0,20841}],[]};
unicode_table(63865) ->
    {0,[{0,20937}],[]};
unicode_table(63866) ->
    {0,[{0,26753}],[]};
unicode_table(63867) ->
    {0,[{0,31975}],[]};
unicode_table(63868) ->
    {0,[{0,33391}],[]};
unicode_table(63869) ->
    {0,[{0,35538}],[]};
unicode_table(63870) ->
    {0,[{0,37327}],[]};
unicode_table(63871) ->
    {0,[{0,21237}],[]};
unicode_table(63872) ->
    {0,[{0,21570}],[]};
unicode_table(63873) ->
    {0,[{0,22899}],[]};
unicode_table(63874) ->
    {0,[{0,24300}],[]};
unicode_table(63875) ->
    {0,[{0,26053}],[]};
unicode_table(63876) ->
    {0,[{0,28670}],[]};
unicode_table(63877) ->
    {0,[{0,31018}],[]};
unicode_table(63878) ->
    {0,[{0,38317}],[]};
unicode_table(63879) ->
    {0,[{0,39530}],[]};
unicode_table(63880) ->
    {0,[{0,40599}],[]};
unicode_table(63881) ->
    {0,[{0,40654}],[]};
unicode_table(63882) ->
    {0,[{0,21147}],[]};
unicode_table(63883) ->
    {0,[{0,26310}],[]};
unicode_table(63884) ->
    {0,[{0,27511}],[]};
unicode_table(63885) ->
    {0,[{0,36706}],[]};
unicode_table(63886) ->
    {0,[{0,24180}],[]};
unicode_table(63887) ->
    {0,[{0,24976}],[]};
unicode_table(63888) ->
    {0,[{0,25088}],[]};
unicode_table(63889) ->
    {0,[{0,25754}],[]};
unicode_table(63890) ->
    {0,[{0,28451}],[]};
unicode_table(63891) ->
    {0,[{0,29001}],[]};
unicode_table(63892) ->
    {0,[{0,29833}],[]};
unicode_table(63893) ->
    {0,[{0,31178}],[]};
unicode_table(63894) ->
    {0,[{0,32244}],[]};
unicode_table(63895) ->
    {0,[{0,32879}],[]};
unicode_table(63896) ->
    {0,[{0,36646}],[]};
unicode_table(63897) ->
    {0,[{0,34030}],[]};
unicode_table(63898) ->
    {0,[{0,36899}],[]};
unicode_table(63899) ->
    {0,[{0,37706}],[]};
unicode_table(63900) ->
    {0,[{0,21015}],[]};
unicode_table(63901) ->
    {0,[{0,21155}],[]};
unicode_table(63902) ->
    {0,[{0,21693}],[]};
unicode_table(63903) ->
    {0,[{0,28872}],[]};
unicode_table(63904) ->
    {0,[{0,35010}],[]};
unicode_table(63905) ->
    {0,[{0,35498}],[]};
unicode_table(63906) ->
    {0,[{0,24265}],[]};
unicode_table(63907) ->
    {0,[{0,24565}],[]};
unicode_table(63908) ->
    {0,[{0,25467}],[]};
unicode_table(63909) ->
    {0,[{0,27566}],[]};
unicode_table(63910) ->
    {0,[{0,31806}],[]};
unicode_table(63911) ->
    {0,[{0,29557}],[]};
unicode_table(63912) ->
    {0,[{0,20196}],[]};
unicode_table(63913) ->
    {0,[{0,22265}],[]};
unicode_table(63914) ->
    {0,[{0,23527}],[]};
unicode_table(63915) ->
    {0,[{0,23994}],[]};
unicode_table(63916) ->
    {0,[{0,24604}],[]};
unicode_table(63917) ->
    {0,[{0,29618}],[]};
unicode_table(63918) ->
    {0,[{0,29801}],[]};
unicode_table(63919) ->
    {0,[{0,32666}],[]};
unicode_table(63920) ->
    {0,[{0,32838}],[]};
unicode_table(63921) ->
    {0,[{0,37428}],[]};
unicode_table(63922) ->
    {0,[{0,38646}],[]};
unicode_table(63923) ->
    {0,[{0,38728}],[]};
unicode_table(63924) ->
    {0,[{0,38936}],[]};
unicode_table(63925) ->
    {0,[{0,20363}],[]};
unicode_table(63926) ->
    {0,[{0,31150}],[]};
unicode_table(63927) ->
    {0,[{0,37300}],[]};
unicode_table(63928) ->
    {0,[{0,38584}],[]};
unicode_table(63929) ->
    {0,[{0,24801}],[]};
unicode_table(63930) ->
    {0,[{0,20102}],[]};
unicode_table(63931) ->
    {0,[{0,20698}],[]};
unicode_table(63932) ->
    {0,[{0,23534}],[]};
unicode_table(63933) ->
    {0,[{0,23615}],[]};
unicode_table(63934) ->
    {0,[{0,26009}],[]};
unicode_table(63935) ->
    {0,[{0,27138}],[]};
unicode_table(63936) ->
    {0,[{0,29134}],[]};
unicode_table(63937) ->
    {0,[{0,30274}],[]};
unicode_table(63938) ->
    {0,[{0,34044}],[]};
unicode_table(63939) ->
    {0,[{0,36988}],[]};
unicode_table(63940) ->
    {0,[{0,40845}],[]};
unicode_table(63941) ->
    {0,[{0,26248}],[]};
unicode_table(63942) ->
    {0,[{0,38446}],[]};
unicode_table(63943) ->
    {0,[{0,21129}],[]};
unicode_table(63944) ->
    {0,[{0,26491}],[]};
unicode_table(63945) ->
    {0,[{0,26611}],[]};
unicode_table(63946) ->
    {0,[{0,27969}],[]};
unicode_table(63947) ->
    {0,[{0,28316}],[]};
unicode_table(63948) ->
    {0,[{0,29705}],[]};
unicode_table(63949) ->
    {0,[{0,30041}],[]};
unicode_table(63950) ->
    {0,[{0,30827}],[]};
unicode_table(63951) ->
    {0,[{0,32016}],[]};
unicode_table(63952) ->
    {0,[{0,39006}],[]};
unicode_table(63953) ->
    {0,[{0,20845}],[]};
unicode_table(63954) ->
    {0,[{0,25134}],[]};
unicode_table(63955) ->
    {0,[{0,38520}],[]};
unicode_table(63956) ->
    {0,[{0,20523}],[]};
unicode_table(63957) ->
    {0,[{0,23833}],[]};
unicode_table(63958) ->
    {0,[{0,28138}],[]};
unicode_table(63959) ->
    {0,[{0,36650}],[]};
unicode_table(63960) ->
    {0,[{0,24459}],[]};
unicode_table(63961) ->
    {0,[{0,24900}],[]};
unicode_table(63962) ->
    {0,[{0,26647}],[]};
unicode_table(63963) ->
    {0,[{0,29575}],[]};
unicode_table(63964) ->
    {0,[{0,38534}],[]};
unicode_table(63965) ->
    {0,[{0,21033}],[]};
unicode_table(63966) ->
    {0,[{0,21519}],[]};
unicode_table(63967) ->
    {0,[{0,23653}],[]};
unicode_table(63968) ->
    {0,[{0,26131}],[]};
unicode_table(63969) ->
    {0,[{0,26446}],[]};
unicode_table(63970) ->
    {0,[{0,26792}],[]};
unicode_table(63971) ->
    {0,[{0,27877}],[]};
unicode_table(63972) ->
    {0,[{0,29702}],[]};
unicode_table(63973) ->
    {0,[{0,30178}],[]};
unicode_table(63974) ->
    {0,[{0,32633}],[]};
unicode_table(63975) ->
    {0,[{0,35023}],[]};
unicode_table(63976) ->
    {0,[{0,35041}],[]};
unicode_table(63977) ->
    {0,[{0,37324}],[]};
unicode_table(63978) ->
    {0,[{0,38626}],[]};
unicode_table(63979) ->
    {0,[{0,21311}],[]};
unicode_table(63980) ->
    {0,[{0,28346}],[]};
unicode_table(63981) ->
    {0,[{0,21533}],[]};
unicode_table(63982) ->
    {0,[{0,29136}],[]};
unicode_table(63983) ->
    {0,[{0,29848}],[]};
unicode_table(63984) ->
    {0,[{0,34298}],[]};
unicode_table(63985) ->
    {0,[{0,38563}],[]};
unicode_table(63986) ->
    {0,[{0,40023}],[]};
unicode_table(63987) ->
    {0,[{0,40607}],[]};
unicode_table(63988) ->
    {0,[{0,26519}],[]};
unicode_table(63989) ->
    {0,[{0,28107}],[]};
unicode_table(63990) ->
    {0,[{0,33256}],[]};
unicode_table(63991) ->
    {0,[{0,31435}],[]};
unicode_table(63992) ->
    {0,[{0,31520}],[]};
unicode_table(63993) ->
    {0,[{0,31890}],[]};
unicode_table(63994) ->
    {0,[{0,29376}],[]};
unicode_table(63995) ->
    {0,[{0,28825}],[]};
unicode_table(63996) ->
    {0,[{0,35672}],[]};
unicode_table(63997) ->
    {0,[{0,20160}],[]};
unicode_table(63998) ->
    {0,[{0,33590}],[]};
unicode_table(63999) ->
    {0,[{0,21050}],[]};
unicode_table(64000) ->
    {0,[{0,20999}],[]};
unicode_table(64001) ->
    {0,[{0,24230}],[]};
unicode_table(64002) ->
    {0,[{0,25299}],[]};
unicode_table(64003) ->
    {0,[{0,31958}],[]};
unicode_table(64004) ->
    {0,[{0,23429}],[]};
unicode_table(64005) ->
    {0,[{0,27934}],[]};
unicode_table(64006) ->
    {0,[{0,26292}],[]};
unicode_table(64007) ->
    {0,[{0,36667}],[]};
unicode_table(64008) ->
    {0,[{0,34892}],[]};
unicode_table(64009) ->
    {0,[{0,38477}],[]};
unicode_table(64010) ->
    {0,[{0,35211}],[]};
unicode_table(64011) ->
    {0,[{0,24275}],[]};
unicode_table(64012) ->
    {0,[{0,20800}],[]};
unicode_table(64013) ->
    {0,[{0,21952}],[]};
unicode_table(64016) ->
    {0,[{0,22618}],[]};
unicode_table(64018) ->
    {0,[{0,26228}],[]};
unicode_table(64021) ->
    {0,[{0,20958}],[]};
unicode_table(64022) ->
    {0,[{0,29482}],[]};
unicode_table(64023) ->
    {0,[{0,30410}],[]};
unicode_table(64024) ->
    {0,[{0,31036}],[]};
unicode_table(64025) ->
    {0,[{0,31070}],[]};
unicode_table(64026) ->
    {0,[{0,31077}],[]};
unicode_table(64027) ->
    {0,[{0,31119}],[]};
unicode_table(64028) ->
    {0,[{0,38742}],[]};
unicode_table(64029) ->
    {0,[{0,31934}],[]};
unicode_table(64030) ->
    {0,[{0,32701}],[]};
unicode_table(64032) ->
    {0,[{0,34322}],[]};
unicode_table(64034) ->
    {0,[{0,35576}],[]};
unicode_table(64037) ->
    {0,[{0,36920}],[]};
unicode_table(64038) ->
    {0,[{0,37117}],[]};
unicode_table(64042) ->
    {0,[{0,39151}],[]};
unicode_table(64043) ->
    {0,[{0,39164}],[]};
unicode_table(64044) ->
    {0,[{0,39208}],[]};
unicode_table(64045) ->
    {0,[{0,40372}],[]};
unicode_table(64046) ->
    {0,[{0,37086}],[]};
unicode_table(64047) ->
    {0,[{0,38583}],[]};
unicode_table(64048) ->
    {0,[{0,20398}],[]};
unicode_table(64049) ->
    {0,[{0,20711}],[]};
unicode_table(64050) ->
    {0,[{0,20813}],[]};
unicode_table(64051) ->
    {0,[{0,21193}],[]};
unicode_table(64052) ->
    {0,[{0,21220}],[]};
unicode_table(64053) ->
    {0,[{0,21329}],[]};
unicode_table(64054) ->
    {0,[{0,21917}],[]};
unicode_table(64055) ->
    {0,[{0,22022}],[]};
unicode_table(64056) ->
    {0,[{0,22120}],[]};
unicode_table(64057) ->
    {0,[{0,22592}],[]};
unicode_table(64058) ->
    {0,[{0,22696}],[]};
unicode_table(64059) ->
    {0,[{0,23652}],[]};
unicode_table(64060) ->
    {0,[{0,23662}],[]};
unicode_table(64061) ->
    {0,[{0,24724}],[]};
unicode_table(64062) ->
    {0,[{0,24936}],[]};
unicode_table(64063) ->
    {0,[{0,24974}],[]};
unicode_table(64064) ->
    {0,[{0,25074}],[]};
unicode_table(64065) ->
    {0,[{0,25935}],[]};
unicode_table(64066) ->
    {0,[{0,26082}],[]};
unicode_table(64067) ->
    {0,[{0,26257}],[]};
unicode_table(64068) ->
    {0,[{0,26757}],[]};
unicode_table(64069) ->
    {0,[{0,28023}],[]};
unicode_table(64070) ->
    {0,[{0,28186}],[]};
unicode_table(64071) ->
    {0,[{0,28450}],[]};
unicode_table(64072) ->
    {0,[{0,29038}],[]};
unicode_table(64073) ->
    {0,[{0,29227}],[]};
unicode_table(64074) ->
    {0,[{0,29730}],[]};
unicode_table(64075) ->
    {0,[{0,30865}],[]};
unicode_table(64076) ->
    {0,[{0,31038}],[]};
unicode_table(64077) ->
    {0,[{0,31049}],[]};
unicode_table(64078) ->
    {0,[{0,31048}],[]};
unicode_table(64079) ->
    {0,[{0,31056}],[]};
unicode_table(64080) ->
    {0,[{0,31062}],[]};
unicode_table(64081) ->
    {0,[{0,31069}],[]};
unicode_table(64082) ->
    {0,[{0,31117}],[]};
unicode_table(64083) ->
    {0,[{0,31118}],[]};
unicode_table(64084) ->
    {0,[{0,31296}],[]};
unicode_table(64085) ->
    {0,[{0,31361}],[]};
unicode_table(64086) ->
    {0,[{0,31680}],[]};
unicode_table(64087) ->
    {0,[{0,32244}],[]};
unicode_table(64088) ->
    {0,[{0,32265}],[]};
unicode_table(64089) ->
    {0,[{0,32321}],[]};
unicode_table(64090) ->
    {0,[{0,32626}],[]};
unicode_table(64091) ->
    {0,[{0,32773}],[]};
unicode_table(64092) ->
    {0,[{0,33261}],[]};
unicode_table(64093) ->
    {0,[{0,33401}],[]};
unicode_table(64094) ->
    {0,[{0,33401}],[]};
unicode_table(64095) ->
    {0,[{0,33879}],[]};
unicode_table(64096) ->
    {0,[{0,35088}],[]};
unicode_table(64097) ->
    {0,[{0,35222}],[]};
unicode_table(64098) ->
    {0,[{0,35585}],[]};
unicode_table(64099) ->
    {0,[{0,35641}],[]};
unicode_table(64100) ->
    {0,[{0,36051}],[]};
unicode_table(64101) ->
    {0,[{0,36104}],[]};
unicode_table(64102) ->
    {0,[{0,36790}],[]};
unicode_table(64103) ->
    {0,[{0,36920}],[]};
unicode_table(64104) ->
    {0,[{0,38627}],[]};
unicode_table(64105) ->
    {0,[{0,38911}],[]};
unicode_table(64106) ->
    {0,[{0,38971}],[]};
unicode_table(64107) ->
    {0,[{0,24693}],[]};
unicode_table(64108) ->
    {0,[{0,148206}],[]};
unicode_table(64109) ->
    {0,[{0,33304}],[]};
unicode_table(64112) ->
    {0,[{0,20006}],[]};
unicode_table(64113) ->
    {0,[{0,20917}],[]};
unicode_table(64114) ->
    {0,[{0,20840}],[]};
unicode_table(64115) ->
    {0,[{0,20352}],[]};
unicode_table(64116) ->
    {0,[{0,20805}],[]};
unicode_table(64117) ->
    {0,[{0,20864}],[]};
unicode_table(64118) ->
    {0,[{0,21191}],[]};
unicode_table(64119) ->
    {0,[{0,21242}],[]};
unicode_table(64120) ->
    {0,[{0,21917}],[]};
unicode_table(64121) ->
    {0,[{0,21845}],[]};
unicode_table(64122) ->
    {0,[{0,21913}],[]};
unicode_table(64123) ->
    {0,[{0,21986}],[]};
unicode_table(64124) ->
    {0,[{0,22618}],[]};
unicode_table(64125) ->
    {0,[{0,22707}],[]};
unicode_table(64126) ->
    {0,[{0,22852}],[]};
unicode_table(64127) ->
    {0,[{0,22868}],[]};
unicode_table(64128) ->
    {0,[{0,23138}],[]};
unicode_table(64129) ->
    {0,[{0,23336}],[]};
unicode_table(64130) ->
    {0,[{0,24274}],[]};
unicode_table(64131) ->
    {0,[{0,24281}],[]};
unicode_table(64132) ->
    {0,[{0,24425}],[]};
unicode_table(64133) ->
    {0,[{0,24493}],[]};
unicode_table(64134) ->
    {0,[{0,24792}],[]};
unicode_table(64135) ->
    {0,[{0,24910}],[]};
unicode_table(64136) ->
    {0,[{0,24840}],[]};
unicode_table(64137) ->
    {0,[{0,24974}],[]};
unicode_table(64138) ->
    {0,[{0,24928}],[]};
unicode_table(64139) ->
    {0,[{0,25074}],[]};
unicode_table(64140) ->
    {0,[{0,25140}],[]};
unicode_table(64141) ->
    {0,[{0,25540}],[]};
unicode_table(64142) ->
    {0,[{0,25628}],[]};
unicode_table(64143) ->
    {0,[{0,25682}],[]};
unicode_table(64144) ->
    {0,[{0,25942}],[]};
unicode_table(64145) ->
    {0,[{0,26228}],[]};
unicode_table(64146) ->
    {0,[{0,26391}],[]};
unicode_table(64147) ->
    {0,[{0,26395}],[]};
unicode_table(64148) ->
    {0,[{0,26454}],[]};
unicode_table(64149) ->
    {0,[{0,27513}],[]};
unicode_table(64150) ->
    {0,[{0,27578}],[]};
unicode_table(64151) ->
    {0,[{0,27969}],[]};
unicode_table(64152) ->
    {0,[{0,28379}],[]};
unicode_table(64153) ->
    {0,[{0,28363}],[]};
unicode_table(64154) ->
    {0,[{0,28450}],[]};
unicode_table(64155) ->
    {0,[{0,28702}],[]};
unicode_table(64156) ->
    {0,[{0,29038}],[]};
unicode_table(64157) ->
    {0,[{0,30631}],[]};
unicode_table(64158) ->
    {0,[{0,29237}],[]};
unicode_table(64159) ->
    {0,[{0,29359}],[]};
unicode_table(64160) ->
    {0,[{0,29482}],[]};
unicode_table(64161) ->
    {0,[{0,29809}],[]};
unicode_table(64162) ->
    {0,[{0,29958}],[]};
unicode_table(64163) ->
    {0,[{0,30011}],[]};
unicode_table(64164) ->
    {0,[{0,30237}],[]};
unicode_table(64165) ->
    {0,[{0,30239}],[]};
unicode_table(64166) ->
    {0,[{0,30410}],[]};
unicode_table(64167) ->
    {0,[{0,30427}],[]};
unicode_table(64168) ->
    {0,[{0,30452}],[]};
unicode_table(64169) ->
    {0,[{0,30538}],[]};
unicode_table(64170) ->
    {0,[{0,30528}],[]};
unicode_table(64171) ->
    {0,[{0,30924}],[]};
unicode_table(64172) ->
    {0,[{0,31409}],[]};
unicode_table(64173) ->
    {0,[{0,31680}],[]};
unicode_table(64174) ->
    {0,[{0,31867}],[]};
unicode_table(64175) ->
    {0,[{0,32091}],[]};
unicode_table(64176) ->
    {0,[{0,32244}],[]};
unicode_table(64177) ->
    {0,[{0,32574}],[]};
unicode_table(64178) ->
    {0,[{0,32773}],[]};
unicode_table(64179) ->
    {0,[{0,33618}],[]};
unicode_table(64180) ->
    {0,[{0,33775}],[]};
unicode_table(64181) ->
    {0,[{0,34681}],[]};
unicode_table(64182) ->
    {0,[{0,35137}],[]};
unicode_table(64183) ->
    {0,[{0,35206}],[]};
unicode_table(64184) ->
    {0,[{0,35222}],[]};
unicode_table(64185) ->
    {0,[{0,35519}],[]};
unicode_table(64186) ->
    {0,[{0,35576}],[]};
unicode_table(64187) ->
    {0,[{0,35531}],[]};
unicode_table(64188) ->
    {0,[{0,35585}],[]};
unicode_table(64189) ->
    {0,[{0,35582}],[]};
unicode_table(64190) ->
    {0,[{0,35565}],[]};
unicode_table(64191) ->
    {0,[{0,35641}],[]};
unicode_table(64192) ->
    {0,[{0,35722}],[]};
unicode_table(64193) ->
    {0,[{0,36104}],[]};
unicode_table(64194) ->
    {0,[{0,36664}],[]};
unicode_table(64195) ->
    {0,[{0,36978}],[]};
unicode_table(64196) ->
    {0,[{0,37273}],[]};
unicode_table(64197) ->
    {0,[{0,37494}],[]};
unicode_table(64198) ->
    {0,[{0,38524}],[]};
unicode_table(64199) ->
    {0,[{0,38627}],[]};
unicode_table(64200) ->
    {0,[{0,38742}],[]};
unicode_table(64201) ->
    {0,[{0,38875}],[]};
unicode_table(64202) ->
    {0,[{0,38911}],[]};
unicode_table(64203) ->
    {0,[{0,38923}],[]};
unicode_table(64204) ->
    {0,[{0,38971}],[]};
unicode_table(64205) ->
    {0,[{0,39698}],[]};
unicode_table(64206) ->
    {0,[{0,40860}],[]};
unicode_table(64207) ->
    {0,[{0,141386}],[]};
unicode_table(64208) ->
    {0,[{0,141380}],[]};
unicode_table(64209) ->
    {0,[{0,144341}],[]};
unicode_table(64210) ->
    {0,[{0,15261}],[]};
unicode_table(64211) ->
    {0,[{0,16408}],[]};
unicode_table(64212) ->
    {0,[{0,16441}],[]};
unicode_table(64213) ->
    {0,[{0,152137}],[]};
unicode_table(64214) ->
    {0,[{0,154832}],[]};
unicode_table(64215) ->
    {0,[{0,163539}],[]};
unicode_table(64216) ->
    {0,[{0,40771}],[]};
unicode_table(64217) ->
    {0,[{0,40846}],[]};
unicode_table(64256) ->
    {0,[],{compat,[{0,102}, {0,102}]}};
unicode_table(64257) ->
    {0,[],{compat,[{0,102}, {0,105}]}};
unicode_table(64258) ->
    {0,[],{compat,[{0,102}, {0,108}]}};
unicode_table(64259) ->
    {0,[],{compat,[{0,102}, {0,102}, {0,105}]}};
unicode_table(64260) ->
    {0,[],{compat,[{0,102}, {0,102}, {0,108}]}};
unicode_table(64261) ->
    {0,[],{compat,[{0,115}, {0,116}]}};
unicode_table(64262) ->
    {0,[],{compat,[{0,115}, {0,116}]}};
unicode_table(64275) ->
    {0,[],{compat,[{0,1396}, {0,1398}]}};
unicode_table(64276) ->
    {0,[],{compat,[{0,1396}, {0,1381}]}};
unicode_table(64277) ->
    {0,[],{compat,[{0,1396}, {0,1387}]}};
unicode_table(64278) ->
    {0,[],{compat,[{0,1406}, {0,1398}]}};
unicode_table(64279) ->
    {0,[],{compat,[{0,1396}, {0,1389}]}};
unicode_table(64285) ->
    {0,[{0,1497}, {14,1460}],[]};
unicode_table(64286) ->
    {26,[],[]};
unicode_table(64287) ->
    {0,[{0,1522}, {17,1463}],[]};
unicode_table(64288) ->
    {0,[],{font,[{0,1506}]}};
unicode_table(64289) ->
    {0,[],{font,[{0,1488}]}};
unicode_table(64290) ->
    {0,[],{font,[{0,1491}]}};
unicode_table(64291) ->
    {0,[],{font,[{0,1492}]}};
unicode_table(64292) ->
    {0,[],{font,[{0,1499}]}};
unicode_table(64293) ->
    {0,[],{font,[{0,1500}]}};
unicode_table(64294) ->
    {0,[],{font,[{0,1501}]}};
unicode_table(64295) ->
    {0,[],{font,[{0,1512}]}};
unicode_table(64296) ->
    {0,[],{font,[{0,1514}]}};
unicode_table(64297) ->
    {0,[],{font,[{0,43}]}};
unicode_table(64298) ->
    {0,[{0,1513}, {24,1473}],[]};
unicode_table(64299) ->
    {0,[{0,1513}, {25,1474}],[]};
unicode_table(64300) ->
    {0,[{0,1513}, {21,1468}, {24,1473}],[]};
unicode_table(64301) ->
    {0,[{0,1513}, {21,1468}, {25,1474}],[]};
unicode_table(64302) ->
    {0,[{0,1488}, {17,1463}],[]};
unicode_table(64303) ->
    {0,[{0,1488}, {18,1464}],[]};
unicode_table(64304) ->
    {0,[{0,1488}, {21,1468}],[]};
unicode_table(64305) ->
    {0,[{0,1489}, {21,1468}],[]};
unicode_table(64306) ->
    {0,[{0,1490}, {21,1468}],[]};
unicode_table(64307) ->
    {0,[{0,1491}, {21,1468}],[]};
unicode_table(64308) ->
    {0,[{0,1492}, {21,1468}],[]};
unicode_table(64309) ->
    {0,[{0,1493}, {21,1468}],[]};
unicode_table(64310) ->
    {0,[{0,1494}, {21,1468}],[]};
unicode_table(64312) ->
    {0,[{0,1496}, {21,1468}],[]};
unicode_table(64313) ->
    {0,[{0,1497}, {21,1468}],[]};
unicode_table(64314) ->
    {0,[{0,1498}, {21,1468}],[]};
unicode_table(64315) ->
    {0,[{0,1499}, {21,1468}],[]};
unicode_table(64316) ->
    {0,[{0,1500}, {21,1468}],[]};
unicode_table(64318) ->
    {0,[{0,1502}, {21,1468}],[]};
unicode_table(64320) ->
    {0,[{0,1504}, {21,1468}],[]};
unicode_table(64321) ->
    {0,[{0,1505}, {21,1468}],[]};
unicode_table(64323) ->
    {0,[{0,1507}, {21,1468}],[]};
unicode_table(64324) ->
    {0,[{0,1508}, {21,1468}],[]};
unicode_table(64326) ->
    {0,[{0,1510}, {21,1468}],[]};
unicode_table(64327) ->
    {0,[{0,1511}, {21,1468}],[]};
unicode_table(64328) ->
    {0,[{0,1512}, {21,1468}],[]};
unicode_table(64329) ->
    {0,[{0,1513}, {21,1468}],[]};
unicode_table(64330) ->
    {0,[{0,1514}, {21,1468}],[]};
unicode_table(64331) ->
    {0,[{0,1493}, {19,1465}],[]};
unicode_table(64332) ->
    {0,[{0,1489}, {23,1471}],[]};
unicode_table(64333) ->
    {0,[{0,1499}, {23,1471}],[]};
unicode_table(64334) ->
    {0,[{0,1508}, {23,1471}],[]};
unicode_table(64335) ->
    {0,[],{compat,[{0,1488}, {0,1500}]}};
unicode_table(64336) ->
    {0,[],{isolated,[{0,1649}]}};
unicode_table(64337) ->
    {0,[],{final,[{0,1649}]}};
unicode_table(64338) ->
    {0,[],{isolated,[{0,1659}]}};
unicode_table(64339) ->
    {0,[],{final,[{0,1659}]}};
unicode_table(64340) ->
    {0,[],{initial,[{0,1659}]}};
unicode_table(64341) ->
    {0,[],{medial,[{0,1659}]}};
unicode_table(64342) ->
    {0,[],{isolated,[{0,1662}]}};
unicode_table(64343) ->
    {0,[],{final,[{0,1662}]}};
unicode_table(64344) ->
    {0,[],{initial,[{0,1662}]}};
unicode_table(64345) ->
    {0,[],{medial,[{0,1662}]}};
unicode_table(64346) ->
    {0,[],{isolated,[{0,1664}]}};
unicode_table(64347) ->
    {0,[],{final,[{0,1664}]}};
unicode_table(64348) ->
    {0,[],{initial,[{0,1664}]}};
unicode_table(64349) ->
    {0,[],{medial,[{0,1664}]}};
unicode_table(64350) ->
    {0,[],{isolated,[{0,1658}]}};
unicode_table(64351) ->
    {0,[],{final,[{0,1658}]}};
unicode_table(64352) ->
    {0,[],{initial,[{0,1658}]}};
unicode_table(64353) ->
    {0,[],{medial,[{0,1658}]}};
unicode_table(64354) ->
    {0,[],{isolated,[{0,1663}]}};
unicode_table(64355) ->
    {0,[],{final,[{0,1663}]}};
unicode_table(64356) ->
    {0,[],{initial,[{0,1663}]}};
unicode_table(64357) ->
    {0,[],{medial,[{0,1663}]}};
unicode_table(64358) ->
    {0,[],{isolated,[{0,1657}]}};
unicode_table(64359) ->
    {0,[],{final,[{0,1657}]}};
unicode_table(64360) ->
    {0,[],{initial,[{0,1657}]}};
unicode_table(64361) ->
    {0,[],{medial,[{0,1657}]}};
unicode_table(64362) ->
    {0,[],{isolated,[{0,1700}]}};
unicode_table(64363) ->
    {0,[],{final,[{0,1700}]}};
unicode_table(64364) ->
    {0,[],{initial,[{0,1700}]}};
unicode_table(64365) ->
    {0,[],{medial,[{0,1700}]}};
unicode_table(64366) ->
    {0,[],{isolated,[{0,1702}]}};
unicode_table(64367) ->
    {0,[],{final,[{0,1702}]}};
unicode_table(64368) ->
    {0,[],{initial,[{0,1702}]}};
unicode_table(64369) ->
    {0,[],{medial,[{0,1702}]}};
unicode_table(64370) ->
    {0,[],{isolated,[{0,1668}]}};
unicode_table(64371) ->
    {0,[],{final,[{0,1668}]}};
unicode_table(64372) ->
    {0,[],{initial,[{0,1668}]}};
unicode_table(64373) ->
    {0,[],{medial,[{0,1668}]}};
unicode_table(64374) ->
    {0,[],{isolated,[{0,1667}]}};
unicode_table(64375) ->
    {0,[],{final,[{0,1667}]}};
unicode_table(64376) ->
    {0,[],{initial,[{0,1667}]}};
unicode_table(64377) ->
    {0,[],{medial,[{0,1667}]}};
unicode_table(64378) ->
    {0,[],{isolated,[{0,1670}]}};
unicode_table(64379) ->
    {0,[],{final,[{0,1670}]}};
unicode_table(64380) ->
    {0,[],{initial,[{0,1670}]}};
unicode_table(64381) ->
    {0,[],{medial,[{0,1670}]}};
unicode_table(64382) ->
    {0,[],{isolated,[{0,1671}]}};
unicode_table(64383) ->
    {0,[],{final,[{0,1671}]}};
unicode_table(64384) ->
    {0,[],{initial,[{0,1671}]}};
unicode_table(64385) ->
    {0,[],{medial,[{0,1671}]}};
unicode_table(64386) ->
    {0,[],{isolated,[{0,1677}]}};
unicode_table(64387) ->
    {0,[],{final,[{0,1677}]}};
unicode_table(64388) ->
    {0,[],{isolated,[{0,1676}]}};
unicode_table(64389) ->
    {0,[],{final,[{0,1676}]}};
unicode_table(64390) ->
    {0,[],{isolated,[{0,1678}]}};
unicode_table(64391) ->
    {0,[],{final,[{0,1678}]}};
unicode_table(64392) ->
    {0,[],{isolated,[{0,1672}]}};
unicode_table(64393) ->
    {0,[],{final,[{0,1672}]}};
unicode_table(64394) ->
    {0,[],{isolated,[{0,1688}]}};
unicode_table(64395) ->
    {0,[],{final,[{0,1688}]}};
unicode_table(64396) ->
    {0,[],{isolated,[{0,1681}]}};
unicode_table(64397) ->
    {0,[],{final,[{0,1681}]}};
unicode_table(64398) ->
    {0,[],{isolated,[{0,1705}]}};
unicode_table(64399) ->
    {0,[],{final,[{0,1705}]}};
unicode_table(64400) ->
    {0,[],{initial,[{0,1705}]}};
unicode_table(64401) ->
    {0,[],{medial,[{0,1705}]}};
unicode_table(64402) ->
    {0,[],{isolated,[{0,1711}]}};
unicode_table(64403) ->
    {0,[],{final,[{0,1711}]}};
unicode_table(64404) ->
    {0,[],{initial,[{0,1711}]}};
unicode_table(64405) ->
    {0,[],{medial,[{0,1711}]}};
unicode_table(64406) ->
    {0,[],{isolated,[{0,1715}]}};
unicode_table(64407) ->
    {0,[],{final,[{0,1715}]}};
unicode_table(64408) ->
    {0,[],{initial,[{0,1715}]}};
unicode_table(64409) ->
    {0,[],{medial,[{0,1715}]}};
unicode_table(64410) ->
    {0,[],{isolated,[{0,1713}]}};
unicode_table(64411) ->
    {0,[],{final,[{0,1713}]}};
unicode_table(64412) ->
    {0,[],{initial,[{0,1713}]}};
unicode_table(64413) ->
    {0,[],{medial,[{0,1713}]}};
unicode_table(64414) ->
    {0,[],{isolated,[{0,1722}]}};
unicode_table(64415) ->
    {0,[],{final,[{0,1722}]}};
unicode_table(64416) ->
    {0,[],{isolated,[{0,1723}]}};
unicode_table(64417) ->
    {0,[],{final,[{0,1723}]}};
unicode_table(64418) ->
    {0,[],{initial,[{0,1723}]}};
unicode_table(64419) ->
    {0,[],{medial,[{0,1723}]}};
unicode_table(64420) ->
    {0,[],{isolated,[{0,1749}, {230,1620}]}};
unicode_table(64421) ->
    {0,[],{final,[{0,1749}, {230,1620}]}};
unicode_table(64422) ->
    {0,[],{isolated,[{0,1729}]}};
unicode_table(64423) ->
    {0,[],{final,[{0,1729}]}};
unicode_table(64424) ->
    {0,[],{initial,[{0,1729}]}};
unicode_table(64425) ->
    {0,[],{medial,[{0,1729}]}};
unicode_table(64426) ->
    {0,[],{isolated,[{0,1726}]}};
unicode_table(64427) ->
    {0,[],{final,[{0,1726}]}};
unicode_table(64428) ->
    {0,[],{initial,[{0,1726}]}};
unicode_table(64429) ->
    {0,[],{medial,[{0,1726}]}};
unicode_table(64430) ->
    {0,[],{isolated,[{0,1746}]}};
unicode_table(64431) ->
    {0,[],{final,[{0,1746}]}};
unicode_table(64432) ->
    {0,[],{isolated,[{0,1746}, {230,1620}]}};
unicode_table(64433) ->
    {0,[],{final,[{0,1746}, {230,1620}]}};
unicode_table(64467) ->
    {0,[],{isolated,[{0,1709}]}};
unicode_table(64468) ->
    {0,[],{final,[{0,1709}]}};
unicode_table(64469) ->
    {0,[],{initial,[{0,1709}]}};
unicode_table(64470) ->
    {0,[],{medial,[{0,1709}]}};
unicode_table(64471) ->
    {0,[],{isolated,[{0,1735}]}};
unicode_table(64472) ->
    {0,[],{final,[{0,1735}]}};
unicode_table(64473) ->
    {0,[],{isolated,[{0,1734}]}};
unicode_table(64474) ->
    {0,[],{final,[{0,1734}]}};
unicode_table(64475) ->
    {0,[],{isolated,[{0,1736}]}};
unicode_table(64476) ->
    {0,[],{final,[{0,1736}]}};
unicode_table(64477) ->
    {0,[],{isolated,[{0,1735}, {0,1652}]}};
unicode_table(64478) ->
    {0,[],{isolated,[{0,1739}]}};
unicode_table(64479) ->
    {0,[],{final,[{0,1739}]}};
unicode_table(64480) ->
    {0,[],{isolated,[{0,1733}]}};
unicode_table(64481) ->
    {0,[],{final,[{0,1733}]}};
unicode_table(64482) ->
    {0,[],{isolated,[{0,1737}]}};
unicode_table(64483) ->
    {0,[],{final,[{0,1737}]}};
unicode_table(64484) ->
    {0,[],{isolated,[{0,1744}]}};
unicode_table(64485) ->
    {0,[],{final,[{0,1744}]}};
unicode_table(64486) ->
    {0,[],{initial,[{0,1744}]}};
unicode_table(64487) ->
    {0,[],{medial,[{0,1744}]}};
unicode_table(64488) ->
    {0,[],{initial,[{0,1609}]}};
unicode_table(64489) ->
    {0,[],{medial,[{0,1609}]}};
unicode_table(64490) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1575}]}};
unicode_table(64491) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1575}]}};
unicode_table(64492) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1749}]}};
unicode_table(64493) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1749}]}};
unicode_table(64494) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1608}]}};
unicode_table(64495) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1608}]}};
unicode_table(64496) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1735}]}};
unicode_table(64497) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1735}]}};
unicode_table(64498) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1734}]}};
unicode_table(64499) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1734}]}};
unicode_table(64500) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1736}]}};
unicode_table(64501) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1736}]}};
unicode_table(64502) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1744}]}};
unicode_table(64503) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1744}]}};
unicode_table(64504) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1744}]}};
unicode_table(64505) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1609}]}};
unicode_table(64506) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1609}]}};
unicode_table(64507) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1609}]}};
unicode_table(64508) ->
    {0,[],{isolated,[{0,1740}]}};
unicode_table(64509) ->
    {0,[],{final,[{0,1740}]}};
unicode_table(64510) ->
    {0,[],{initial,[{0,1740}]}};
unicode_table(64511) ->
    {0,[],{medial,[{0,1740}]}};
unicode_table(64512) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1580}]}};
unicode_table(64513) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1581}]}};
unicode_table(64514) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1605}]}};
unicode_table(64515) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1609}]}};
unicode_table(64516) ->
    {0,[],{isolated,[{0,1610}, {230,1620}, {0,1610}]}};
unicode_table(64517) ->
    {0,[],{isolated,[{0,1576}, {0,1580}]}};
unicode_table(64518) ->
    {0,[],{isolated,[{0,1576}, {0,1581}]}};
unicode_table(64519) ->
    {0,[],{isolated,[{0,1576}, {0,1582}]}};
unicode_table(64520) ->
    {0,[],{isolated,[{0,1576}, {0,1605}]}};
unicode_table(64521) ->
    {0,[],{isolated,[{0,1576}, {0,1609}]}};
unicode_table(64522) ->
    {0,[],{isolated,[{0,1576}, {0,1610}]}};
unicode_table(64523) ->
    {0,[],{isolated,[{0,1578}, {0,1580}]}};
unicode_table(64524) ->
    {0,[],{isolated,[{0,1578}, {0,1581}]}};
unicode_table(64525) ->
    {0,[],{isolated,[{0,1578}, {0,1582}]}};
unicode_table(64526) ->
    {0,[],{isolated,[{0,1578}, {0,1605}]}};
unicode_table(64527) ->
    {0,[],{isolated,[{0,1578}, {0,1609}]}};
unicode_table(64528) ->
    {0,[],{isolated,[{0,1578}, {0,1610}]}};
unicode_table(64529) ->
    {0,[],{isolated,[{0,1579}, {0,1580}]}};
unicode_table(64530) ->
    {0,[],{isolated,[{0,1579}, {0,1605}]}};
unicode_table(64531) ->
    {0,[],{isolated,[{0,1579}, {0,1609}]}};
unicode_table(64532) ->
    {0,[],{isolated,[{0,1579}, {0,1610}]}};
unicode_table(64533) ->
    {0,[],{isolated,[{0,1580}, {0,1581}]}};
unicode_table(64534) ->
    {0,[],{isolated,[{0,1580}, {0,1605}]}};
unicode_table(64535) ->
    {0,[],{isolated,[{0,1581}, {0,1580}]}};
unicode_table(64536) ->
    {0,[],{isolated,[{0,1581}, {0,1605}]}};
unicode_table(64537) ->
    {0,[],{isolated,[{0,1582}, {0,1580}]}};
unicode_table(64538) ->
    {0,[],{isolated,[{0,1582}, {0,1581}]}};
unicode_table(64539) ->
    {0,[],{isolated,[{0,1582}, {0,1605}]}};
unicode_table(64540) ->
    {0,[],{isolated,[{0,1587}, {0,1580}]}};
unicode_table(64541) ->
    {0,[],{isolated,[{0,1587}, {0,1581}]}};
unicode_table(64542) ->
    {0,[],{isolated,[{0,1587}, {0,1582}]}};
unicode_table(64543) ->
    {0,[],{isolated,[{0,1587}, {0,1605}]}};
unicode_table(64544) ->
    {0,[],{isolated,[{0,1589}, {0,1581}]}};
unicode_table(64545) ->
    {0,[],{isolated,[{0,1589}, {0,1605}]}};
unicode_table(64546) ->
    {0,[],{isolated,[{0,1590}, {0,1580}]}};
unicode_table(64547) ->
    {0,[],{isolated,[{0,1590}, {0,1581}]}};
unicode_table(64548) ->
    {0,[],{isolated,[{0,1590}, {0,1582}]}};
unicode_table(64549) ->
    {0,[],{isolated,[{0,1590}, {0,1605}]}};
unicode_table(64550) ->
    {0,[],{isolated,[{0,1591}, {0,1581}]}};
unicode_table(64551) ->
    {0,[],{isolated,[{0,1591}, {0,1605}]}};
unicode_table(64552) ->
    {0,[],{isolated,[{0,1592}, {0,1605}]}};
unicode_table(64553) ->
    {0,[],{isolated,[{0,1593}, {0,1580}]}};
unicode_table(64554) ->
    {0,[],{isolated,[{0,1593}, {0,1605}]}};
unicode_table(64555) ->
    {0,[],{isolated,[{0,1594}, {0,1580}]}};
unicode_table(64556) ->
    {0,[],{isolated,[{0,1594}, {0,1605}]}};
unicode_table(64557) ->
    {0,[],{isolated,[{0,1601}, {0,1580}]}};
unicode_table(64558) ->
    {0,[],{isolated,[{0,1601}, {0,1581}]}};
unicode_table(64559) ->
    {0,[],{isolated,[{0,1601}, {0,1582}]}};
unicode_table(64560) ->
    {0,[],{isolated,[{0,1601}, {0,1605}]}};
unicode_table(64561) ->
    {0,[],{isolated,[{0,1601}, {0,1609}]}};
unicode_table(64562) ->
    {0,[],{isolated,[{0,1601}, {0,1610}]}};
unicode_table(64563) ->
    {0,[],{isolated,[{0,1602}, {0,1581}]}};
unicode_table(64564) ->
    {0,[],{isolated,[{0,1602}, {0,1605}]}};
unicode_table(64565) ->
    {0,[],{isolated,[{0,1602}, {0,1609}]}};
unicode_table(64566) ->
    {0,[],{isolated,[{0,1602}, {0,1610}]}};
unicode_table(64567) ->
    {0,[],{isolated,[{0,1603}, {0,1575}]}};
unicode_table(64568) ->
    {0,[],{isolated,[{0,1603}, {0,1580}]}};
unicode_table(64569) ->
    {0,[],{isolated,[{0,1603}, {0,1581}]}};
unicode_table(64570) ->
    {0,[],{isolated,[{0,1603}, {0,1582}]}};
unicode_table(64571) ->
    {0,[],{isolated,[{0,1603}, {0,1604}]}};
unicode_table(64572) ->
    {0,[],{isolated,[{0,1603}, {0,1605}]}};
unicode_table(64573) ->
    {0,[],{isolated,[{0,1603}, {0,1609}]}};
unicode_table(64574) ->
    {0,[],{isolated,[{0,1603}, {0,1610}]}};
unicode_table(64575) ->
    {0,[],{isolated,[{0,1604}, {0,1580}]}};
unicode_table(64576) ->
    {0,[],{isolated,[{0,1604}, {0,1581}]}};
unicode_table(64577) ->
    {0,[],{isolated,[{0,1604}, {0,1582}]}};
unicode_table(64578) ->
    {0,[],{isolated,[{0,1604}, {0,1605}]}};
unicode_table(64579) ->
    {0,[],{isolated,[{0,1604}, {0,1609}]}};
unicode_table(64580) ->
    {0,[],{isolated,[{0,1604}, {0,1610}]}};
unicode_table(64581) ->
    {0,[],{isolated,[{0,1605}, {0,1580}]}};
unicode_table(64582) ->
    {0,[],{isolated,[{0,1605}, {0,1581}]}};
unicode_table(64583) ->
    {0,[],{isolated,[{0,1605}, {0,1582}]}};
unicode_table(64584) ->
    {0,[],{isolated,[{0,1605}, {0,1605}]}};
unicode_table(64585) ->
    {0,[],{isolated,[{0,1605}, {0,1609}]}};
unicode_table(64586) ->
    {0,[],{isolated,[{0,1605}, {0,1610}]}};
unicode_table(64587) ->
    {0,[],{isolated,[{0,1606}, {0,1580}]}};
unicode_table(64588) ->
    {0,[],{isolated,[{0,1606}, {0,1581}]}};
unicode_table(64589) ->
    {0,[],{isolated,[{0,1606}, {0,1582}]}};
unicode_table(64590) ->
    {0,[],{isolated,[{0,1606}, {0,1605}]}};
unicode_table(64591) ->
    {0,[],{isolated,[{0,1606}, {0,1609}]}};
unicode_table(64592) ->
    {0,[],{isolated,[{0,1606}, {0,1610}]}};
unicode_table(64593) ->
    {0,[],{isolated,[{0,1607}, {0,1580}]}};
unicode_table(64594) ->
    {0,[],{isolated,[{0,1607}, {0,1605}]}};
unicode_table(64595) ->
    {0,[],{isolated,[{0,1607}, {0,1609}]}};
unicode_table(64596) ->
    {0,[],{isolated,[{0,1607}, {0,1610}]}};
unicode_table(64597) ->
    {0,[],{isolated,[{0,1610}, {0,1580}]}};
unicode_table(64598) ->
    {0,[],{isolated,[{0,1610}, {0,1581}]}};
unicode_table(64599) ->
    {0,[],{isolated,[{0,1610}, {0,1582}]}};
unicode_table(64600) ->
    {0,[],{isolated,[{0,1610}, {0,1605}]}};
unicode_table(64601) ->
    {0,[],{isolated,[{0,1610}, {0,1609}]}};
unicode_table(64602) ->
    {0,[],{isolated,[{0,1610}, {0,1610}]}};
unicode_table(64603) ->
    {0,[],{isolated,[{0,1584}, {35,1648}]}};
unicode_table(64604) ->
    {0,[],{isolated,[{0,1585}, {35,1648}]}};
unicode_table(64605) ->
    {0,[],{isolated,[{0,1609}, {35,1648}]}};
unicode_table(64606) ->
    {0,[],{isolated,[{0,32}, {28,1612}, {33,1617}]}};
unicode_table(64607) ->
    {0,[],{isolated,[{0,32}, {29,1613}, {33,1617}]}};
unicode_table(64608) ->
    {0,[],{isolated,[{0,32}, {30,1614}, {33,1617}]}};
unicode_table(64609) ->
    {0,[],{isolated,[{0,32}, {31,1615}, {33,1617}]}};
unicode_table(64610) ->
    {0,[],{isolated,[{0,32}, {32,1616}, {33,1617}]}};
unicode_table(64611) ->
    {0,[],{isolated,[{0,32}, {33,1617}, {35,1648}]}};
unicode_table(64612) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1585}]}};
unicode_table(64613) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1586}]}};
unicode_table(64614) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1605}]}};
unicode_table(64615) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1606}]}};
unicode_table(64616) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1609}]}};
unicode_table(64617) ->
    {0,[],{final,[{0,1610}, {230,1620}, {0,1610}]}};
unicode_table(64618) ->
    {0,[],{final,[{0,1576}, {0,1585}]}};
unicode_table(64619) ->
    {0,[],{final,[{0,1576}, {0,1586}]}};
unicode_table(64620) ->
    {0,[],{final,[{0,1576}, {0,1605}]}};
unicode_table(64621) ->
    {0,[],{final,[{0,1576}, {0,1606}]}};
unicode_table(64622) ->
    {0,[],{final,[{0,1576}, {0,1609}]}};
unicode_table(64623) ->
    {0,[],{final,[{0,1576}, {0,1610}]}};
unicode_table(64624) ->
    {0,[],{final,[{0,1578}, {0,1585}]}};
unicode_table(64625) ->
    {0,[],{final,[{0,1578}, {0,1586}]}};
unicode_table(64626) ->
    {0,[],{final,[{0,1578}, {0,1605}]}};
unicode_table(64627) ->
    {0,[],{final,[{0,1578}, {0,1606}]}};
unicode_table(64628) ->
    {0,[],{final,[{0,1578}, {0,1609}]}};
unicode_table(64629) ->
    {0,[],{final,[{0,1578}, {0,1610}]}};
unicode_table(64630) ->
    {0,[],{final,[{0,1579}, {0,1585}]}};
unicode_table(64631) ->
    {0,[],{final,[{0,1579}, {0,1586}]}};
unicode_table(64632) ->
    {0,[],{final,[{0,1579}, {0,1605}]}};
unicode_table(64633) ->
    {0,[],{final,[{0,1579}, {0,1606}]}};
unicode_table(64634) ->
    {0,[],{final,[{0,1579}, {0,1609}]}};
unicode_table(64635) ->
    {0,[],{final,[{0,1579}, {0,1610}]}};
unicode_table(64636) ->
    {0,[],{final,[{0,1601}, {0,1609}]}};
unicode_table(64637) ->
    {0,[],{final,[{0,1601}, {0,1610}]}};
unicode_table(64638) ->
    {0,[],{final,[{0,1602}, {0,1609}]}};
unicode_table(64639) ->
    {0,[],{final,[{0,1602}, {0,1610}]}};
unicode_table(64640) ->
    {0,[],{final,[{0,1603}, {0,1575}]}};
unicode_table(64641) ->
    {0,[],{final,[{0,1603}, {0,1604}]}};
unicode_table(64642) ->
    {0,[],{final,[{0,1603}, {0,1605}]}};
unicode_table(64643) ->
    {0,[],{final,[{0,1603}, {0,1609}]}};
unicode_table(64644) ->
    {0,[],{final,[{0,1603}, {0,1610}]}};
unicode_table(64645) ->
    {0,[],{final,[{0,1604}, {0,1605}]}};
unicode_table(64646) ->
    {0,[],{final,[{0,1604}, {0,1609}]}};
unicode_table(64647) ->
    {0,[],{final,[{0,1604}, {0,1610}]}};
unicode_table(64648) ->
    {0,[],{final,[{0,1605}, {0,1575}]}};
unicode_table(64649) ->
    {0,[],{final,[{0,1605}, {0,1605}]}};
unicode_table(64650) ->
    {0,[],{final,[{0,1606}, {0,1585}]}};
unicode_table(64651) ->
    {0,[],{final,[{0,1606}, {0,1586}]}};
unicode_table(64652) ->
    {0,[],{final,[{0,1606}, {0,1605}]}};
unicode_table(64653) ->
    {0,[],{final,[{0,1606}, {0,1606}]}};
unicode_table(64654) ->
    {0,[],{final,[{0,1606}, {0,1609}]}};
unicode_table(64655) ->
    {0,[],{final,[{0,1606}, {0,1610}]}};
unicode_table(64656) ->
    {0,[],{final,[{0,1609}, {35,1648}]}};
unicode_table(64657) ->
    {0,[],{final,[{0,1610}, {0,1585}]}};
unicode_table(64658) ->
    {0,[],{final,[{0,1610}, {0,1586}]}};
unicode_table(64659) ->
    {0,[],{final,[{0,1610}, {0,1605}]}};
unicode_table(64660) ->
    {0,[],{final,[{0,1610}, {0,1606}]}};
unicode_table(64661) ->
    {0,[],{final,[{0,1610}, {0,1609}]}};
unicode_table(64662) ->
    {0,[],{final,[{0,1610}, {0,1610}]}};
unicode_table(64663) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1580}]}};
unicode_table(64664) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1581}]}};
unicode_table(64665) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1582}]}};
unicode_table(64666) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1605}]}};
unicode_table(64667) ->
    {0,[],{initial,[{0,1610}, {230,1620}, {0,1607}]}};
unicode_table(64668) ->
    {0,[],{initial,[{0,1576}, {0,1580}]}};
unicode_table(64669) ->
    {0,[],{initial,[{0,1576}, {0,1581}]}};
unicode_table(64670) ->
    {0,[],{initial,[{0,1576}, {0,1582}]}};
unicode_table(64671) ->
    {0,[],{initial,[{0,1576}, {0,1605}]}};
unicode_table(64672) ->
    {0,[],{initial,[{0,1576}, {0,1607}]}};
unicode_table(64673) ->
    {0,[],{initial,[{0,1578}, {0,1580}]}};
unicode_table(64674) ->
    {0,[],{initial,[{0,1578}, {0,1581}]}};
unicode_table(64675) ->
    {0,[],{initial,[{0,1578}, {0,1582}]}};
unicode_table(64676) ->
    {0,[],{initial,[{0,1578}, {0,1605}]}};
unicode_table(64677) ->
    {0,[],{initial,[{0,1578}, {0,1607}]}};
unicode_table(64678) ->
    {0,[],{initial,[{0,1579}, {0,1605}]}};
unicode_table(64679) ->
    {0,[],{initial,[{0,1580}, {0,1581}]}};
unicode_table(64680) ->
    {0,[],{initial,[{0,1580}, {0,1605}]}};
unicode_table(64681) ->
    {0,[],{initial,[{0,1581}, {0,1580}]}};
unicode_table(64682) ->
    {0,[],{initial,[{0,1581}, {0,1605}]}};
unicode_table(64683) ->
    {0,[],{initial,[{0,1582}, {0,1580}]}};
unicode_table(64684) ->
    {0,[],{initial,[{0,1582}, {0,1605}]}};
unicode_table(64685) ->
    {0,[],{initial,[{0,1587}, {0,1580}]}};
unicode_table(64686) ->
    {0,[],{initial,[{0,1587}, {0,1581}]}};
unicode_table(64687) ->
    {0,[],{initial,[{0,1587}, {0,1582}]}};
unicode_table(64688) ->
    {0,[],{initial,[{0,1587}, {0,1605}]}};
unicode_table(64689) ->
    {0,[],{initial,[{0,1589}, {0,1581}]}};
unicode_table(64690) ->
    {0,[],{initial,[{0,1589}, {0,1582}]}};
unicode_table(64691) ->
    {0,[],{initial,[{0,1589}, {0,1605}]}};
unicode_table(64692) ->
    {0,[],{initial,[{0,1590}, {0,1580}]}};
unicode_table(64693) ->
    {0,[],{initial,[{0,1590}, {0,1581}]}};
unicode_table(64694) ->
    {0,[],{initial,[{0,1590}, {0,1582}]}};
unicode_table(64695) ->
    {0,[],{initial,[{0,1590}, {0,1605}]}};
unicode_table(64696) ->
    {0,[],{initial,[{0,1591}, {0,1581}]}};
unicode_table(64697) ->
    {0,[],{initial,[{0,1592}, {0,1605}]}};
unicode_table(64698) ->
    {0,[],{initial,[{0,1593}, {0,1580}]}};
unicode_table(64699) ->
    {0,[],{initial,[{0,1593}, {0,1605}]}};
unicode_table(64700) ->
    {0,[],{initial,[{0,1594}, {0,1580}]}};
unicode_table(64701) ->
    {0,[],{initial,[{0,1594}, {0,1605}]}};
unicode_table(64702) ->
    {0,[],{initial,[{0,1601}, {0,1580}]}};
unicode_table(64703) ->
    {0,[],{initial,[{0,1601}, {0,1581}]}};
unicode_table(64704) ->
    {0,[],{initial,[{0,1601}, {0,1582}]}};
unicode_table(64705) ->
    {0,[],{initial,[{0,1601}, {0,1605}]}};
unicode_table(64706) ->
    {0,[],{initial,[{0,1602}, {0,1581}]}};
unicode_table(64707) ->
    {0,[],{initial,[{0,1602}, {0,1605}]}};
unicode_table(64708) ->
    {0,[],{initial,[{0,1603}, {0,1580}]}};
unicode_table(64709) ->
    {0,[],{initial,[{0,1603}, {0,1581}]}};
unicode_table(64710) ->
    {0,[],{initial,[{0,1603}, {0,1582}]}};
unicode_table(64711) ->
    {0,[],{initial,[{0,1603}, {0,1604}]}};
unicode_table(64712) ->
    {0,[],{initial,[{0,1603}, {0,1605}]}};
unicode_table(64713) ->
    {0,[],{initial,[{0,1604}, {0,1580}]}};
unicode_table(64714) ->
    {0,[],{initial,[{0,1604}, {0,1581}]}};
unicode_table(64715) ->
    {0,[],{initial,[{0,1604}, {0,1582}]}};
unicode_table(64716) ->
    {0,[],{initial,[{0,1604}, {0,1605}]}};
unicode_table(64717) ->
    {0,[],{initial,[{0,1604}, {0,1607}]}};
unicode_table(64718) ->
    {0,[],{initial,[{0,1605}, {0,1580}]}};
unicode_table(64719) ->
    {0,[],{initial,[{0,1605}, {0,1581}]}};
unicode_table(64720) ->
    {0,[],{initial,[{0,1605}, {0,1582}]}};
unicode_table(64721) ->
    {0,[],{initial,[{0,1605}, {0,1605}]}};
unicode_table(64722) ->
    {0,[],{initial,[{0,1606}, {0,1580}]}};
unicode_table(64723) ->
    {0,[],{initial,[{0,1606}, {0,1581}]}};
unicode_table(64724) ->
    {0,[],{initial,[{0,1606}, {0,1582}]}};
unicode_table(64725) ->
    {0,[],{initial,[{0,1606}, {0,1605}]}};
unicode_table(64726) ->
    {0,[],{initial,[{0,1606}, {0,1607}]}};
unicode_table(64727) ->
    {0,[],{initial,[{0,1607}, {0,1580}]}};
unicode_table(64728) ->
    {0,[],{initial,[{0,1607}, {0,1605}]}};
unicode_table(64729) ->
    {0,[],{initial,[{0,1607}, {35,1648}]}};
unicode_table(64730) ->
    {0,[],{initial,[{0,1610}, {0,1580}]}};
unicode_table(64731) ->
    {0,[],{initial,[{0,1610}, {0,1581}]}};
unicode_table(64732) ->
    {0,[],{initial,[{0,1610}, {0,1582}]}};
unicode_table(64733) ->
    {0,[],{initial,[{0,1610}, {0,1605}]}};
unicode_table(64734) ->
    {0,[],{initial,[{0,1610}, {0,1607}]}};
unicode_table(64735) ->
    {0,[],{medial,[{0,1610}, {230,1620}, {0,1605}]}};
unicode_table(64736) ->
    {0,[],{medial,[{0,1610}, {230,1620}, {0,1607}]}};
unicode_table(64737) ->
    {0,[],{medial,[{0,1576}, {0,1605}]}};
unicode_table(64738) ->
    {0,[],{medial,[{0,1576}, {0,1607}]}};
unicode_table(64739) ->
    {0,[],{medial,[{0,1578}, {0,1605}]}};
unicode_table(64740) ->
    {0,[],{medial,[{0,1578}, {0,1607}]}};
unicode_table(64741) ->
    {0,[],{medial,[{0,1579}, {0,1605}]}};
unicode_table(64742) ->
    {0,[],{medial,[{0,1579}, {0,1607}]}};
unicode_table(64743) ->
    {0,[],{medial,[{0,1587}, {0,1605}]}};
unicode_table(64744) ->
    {0,[],{medial,[{0,1587}, {0,1607}]}};
unicode_table(64745) ->
    {0,[],{medial,[{0,1588}, {0,1605}]}};
unicode_table(64746) ->
    {0,[],{medial,[{0,1588}, {0,1607}]}};
unicode_table(64747) ->
    {0,[],{medial,[{0,1603}, {0,1604}]}};
unicode_table(64748) ->
    {0,[],{medial,[{0,1603}, {0,1605}]}};
unicode_table(64749) ->
    {0,[],{medial,[{0,1604}, {0,1605}]}};
unicode_table(64750) ->
    {0,[],{medial,[{0,1606}, {0,1605}]}};
unicode_table(64751) ->
    {0,[],{medial,[{0,1606}, {0,1607}]}};
unicode_table(64752) ->
    {0,[],{medial,[{0,1610}, {0,1605}]}};
unicode_table(64753) ->
    {0,[],{medial,[{0,1610}, {0,1607}]}};
unicode_table(64754) ->
    {0,[],{medial,[{0,1600}, {30,1614}, {33,1617}]}};
unicode_table(64755) ->
    {0,[],{medial,[{0,1600}, {31,1615}, {33,1617}]}};
unicode_table(64756) ->
    {0,[],{medial,[{0,1600}, {32,1616}, {33,1617}]}};
unicode_table(64757) ->
    {0,[],{isolated,[{0,1591}, {0,1609}]}};
unicode_table(64758) ->
    {0,[],{isolated,[{0,1591}, {0,1610}]}};
unicode_table(64759) ->
    {0,[],{isolated,[{0,1593}, {0,1609}]}};
unicode_table(64760) ->
    {0,[],{isolated,[{0,1593}, {0,1610}]}};
unicode_table(64761) ->
    {0,[],{isolated,[{0,1594}, {0,1609}]}};
unicode_table(64762) ->
    {0,[],{isolated,[{0,1594}, {0,1610}]}};
unicode_table(64763) ->
    {0,[],{isolated,[{0,1587}, {0,1609}]}};
unicode_table(64764) ->
    {0,[],{isolated,[{0,1587}, {0,1610}]}};
unicode_table(64765) ->
    {0,[],{isolated,[{0,1588}, {0,1609}]}};
unicode_table(64766) ->
    {0,[],{isolated,[{0,1588}, {0,1610}]}};
unicode_table(64767) ->
    {0,[],{isolated,[{0,1581}, {0,1609}]}};
unicode_table(64768) ->
    {0,[],{isolated,[{0,1581}, {0,1610}]}};
unicode_table(64769) ->
    {0,[],{isolated,[{0,1580}, {0,1609}]}};
unicode_table(64770) ->
    {0,[],{isolated,[{0,1580}, {0,1610}]}};
unicode_table(64771) ->
    {0,[],{isolated,[{0,1582}, {0,1609}]}};
unicode_table(64772) ->
    {0,[],{isolated,[{0,1582}, {0,1610}]}};
unicode_table(64773) ->
    {0,[],{isolated,[{0,1589}, {0,1609}]}};
unicode_table(64774) ->
    {0,[],{isolated,[{0,1589}, {0,1610}]}};
unicode_table(64775) ->
    {0,[],{isolated,[{0,1590}, {0,1609}]}};
unicode_table(64776) ->
    {0,[],{isolated,[{0,1590}, {0,1610}]}};
unicode_table(64777) ->
    {0,[],{isolated,[{0,1588}, {0,1580}]}};
unicode_table(64778) ->
    {0,[],{isolated,[{0,1588}, {0,1581}]}};
unicode_table(64779) ->
    {0,[],{isolated,[{0,1588}, {0,1582}]}};
unicode_table(64780) ->
    {0,[],{isolated,[{0,1588}, {0,1605}]}};
unicode_table(64781) ->
    {0,[],{isolated,[{0,1588}, {0,1585}]}};
unicode_table(64782) ->
    {0,[],{isolated,[{0,1587}, {0,1585}]}};
unicode_table(64783) ->
    {0,[],{isolated,[{0,1589}, {0,1585}]}};
unicode_table(64784) ->
    {0,[],{isolated,[{0,1590}, {0,1585}]}};
unicode_table(64785) ->
    {0,[],{final,[{0,1591}, {0,1609}]}};
unicode_table(64786) ->
    {0,[],{final,[{0,1591}, {0,1610}]}};
unicode_table(64787) ->
    {0,[],{final,[{0,1593}, {0,1609}]}};
unicode_table(64788) ->
    {0,[],{final,[{0,1593}, {0,1610}]}};
unicode_table(64789) ->
    {0,[],{final,[{0,1594}, {0,1609}]}};
unicode_table(64790) ->
    {0,[],{final,[{0,1594}, {0,1610}]}};
unicode_table(64791) ->
    {0,[],{final,[{0,1587}, {0,1609}]}};
unicode_table(64792) ->
    {0,[],{final,[{0,1587}, {0,1610}]}};
unicode_table(64793) ->
    {0,[],{final,[{0,1588}, {0,1609}]}};
unicode_table(64794) ->
    {0,[],{final,[{0,1588}, {0,1610}]}};
unicode_table(64795) ->
    {0,[],{final,[{0,1581}, {0,1609}]}};
unicode_table(64796) ->
    {0,[],{final,[{0,1581}, {0,1610}]}};
unicode_table(64797) ->
    {0,[],{final,[{0,1580}, {0,1609}]}};
unicode_table(64798) ->
    {0,[],{final,[{0,1580}, {0,1610}]}};
unicode_table(64799) ->
    {0,[],{final,[{0,1582}, {0,1609}]}};
unicode_table(64800) ->
    {0,[],{final,[{0,1582}, {0,1610}]}};
unicode_table(64801) ->
    {0,[],{final,[{0,1589}, {0,1609}]}};
unicode_table(64802) ->
    {0,[],{final,[{0,1589}, {0,1610}]}};
unicode_table(64803) ->
    {0,[],{final,[{0,1590}, {0,1609}]}};
unicode_table(64804) ->
    {0,[],{final,[{0,1590}, {0,1610}]}};
unicode_table(64805) ->
    {0,[],{final,[{0,1588}, {0,1580}]}};
unicode_table(64806) ->
    {0,[],{final,[{0,1588}, {0,1581}]}};
unicode_table(64807) ->
    {0,[],{final,[{0,1588}, {0,1582}]}};
unicode_table(64808) ->
    {0,[],{final,[{0,1588}, {0,1605}]}};
unicode_table(64809) ->
    {0,[],{final,[{0,1588}, {0,1585}]}};
unicode_table(64810) ->
    {0,[],{final,[{0,1587}, {0,1585}]}};
unicode_table(64811) ->
    {0,[],{final,[{0,1589}, {0,1585}]}};
unicode_table(64812) ->
    {0,[],{final,[{0,1590}, {0,1585}]}};
unicode_table(64813) ->
    {0,[],{initial,[{0,1588}, {0,1580}]}};
unicode_table(64814) ->
    {0,[],{initial,[{0,1588}, {0,1581}]}};
unicode_table(64815) ->
    {0,[],{initial,[{0,1588}, {0,1582}]}};
unicode_table(64816) ->
    {0,[],{initial,[{0,1588}, {0,1605}]}};
unicode_table(64817) ->
    {0,[],{initial,[{0,1587}, {0,1607}]}};
unicode_table(64818) ->
    {0,[],{initial,[{0,1588}, {0,1607}]}};
unicode_table(64819) ->
    {0,[],{initial,[{0,1591}, {0,1605}]}};
unicode_table(64820) ->
    {0,[],{medial,[{0,1587}, {0,1580}]}};
unicode_table(64821) ->
    {0,[],{medial,[{0,1587}, {0,1581}]}};
unicode_table(64822) ->
    {0,[],{medial,[{0,1587}, {0,1582}]}};
unicode_table(64823) ->
    {0,[],{medial,[{0,1588}, {0,1580}]}};
unicode_table(64824) ->
    {0,[],{medial,[{0,1588}, {0,1581}]}};
unicode_table(64825) ->
    {0,[],{medial,[{0,1588}, {0,1582}]}};
unicode_table(64826) ->
    {0,[],{medial,[{0,1591}, {0,1605}]}};
unicode_table(64827) ->
    {0,[],{medial,[{0,1592}, {0,1605}]}};
unicode_table(64828) ->
    {0,[],{final,[{0,1575}, {27,1611}]}};
unicode_table(64829) ->
    {0,[],{isolated,[{0,1575}, {27,1611}]}};
unicode_table(64848) ->
    {0,[],{initial,[{0,1578}, {0,1580}, {0,1605}]}};
unicode_table(64849) ->
    {0,[],{final,[{0,1578}, {0,1581}, {0,1580}]}};
unicode_table(64850) ->
    {0,[],{initial,[{0,1578}, {0,1581}, {0,1580}]}};
unicode_table(64851) ->
    {0,[],{initial,[{0,1578}, {0,1581}, {0,1605}]}};
unicode_table(64852) ->
    {0,[],{initial,[{0,1578}, {0,1582}, {0,1605}]}};
unicode_table(64853) ->
    {0,[],{initial,[{0,1578}, {0,1605}, {0,1580}]}};
unicode_table(64854) ->
    {0,[],{initial,[{0,1578}, {0,1605}, {0,1581}]}};
unicode_table(64855) ->
    {0,[],{initial,[{0,1578}, {0,1605}, {0,1582}]}};
unicode_table(64856) ->
    {0,[],{final,[{0,1580}, {0,1605}, {0,1581}]}};
unicode_table(64857) ->
    {0,[],{initial,[{0,1580}, {0,1605}, {0,1581}]}};
unicode_table(64858) ->
    {0,[],{final,[{0,1581}, {0,1605}, {0,1610}]}};
unicode_table(64859) ->
    {0,[],{final,[{0,1581}, {0,1605}, {0,1609}]}};
unicode_table(64860) ->
    {0,[],{initial,[{0,1587}, {0,1581}, {0,1580}]}};
unicode_table(64861) ->
    {0,[],{initial,[{0,1587}, {0,1580}, {0,1581}]}};
unicode_table(64862) ->
    {0,[],{final,[{0,1587}, {0,1580}, {0,1609}]}};
unicode_table(64863) ->
    {0,[],{final,[{0,1587}, {0,1605}, {0,1581}]}};
unicode_table(64864) ->
    {0,[],{initial,[{0,1587}, {0,1605}, {0,1581}]}};
unicode_table(64865) ->
    {0,[],{initial,[{0,1587}, {0,1605}, {0,1580}]}};
unicode_table(64866) ->
    {0,[],{final,[{0,1587}, {0,1605}, {0,1605}]}};
unicode_table(64867) ->
    {0,[],{initial,[{0,1587}, {0,1605}, {0,1605}]}};
unicode_table(64868) ->
    {0,[],{final,[{0,1589}, {0,1581}, {0,1581}]}};
unicode_table(64869) ->
    {0,[],{initial,[{0,1589}, {0,1581}, {0,1581}]}};
unicode_table(64870) ->
    {0,[],{final,[{0,1589}, {0,1605}, {0,1605}]}};
unicode_table(64871) ->
    {0,[],{final,[{0,1588}, {0,1581}, {0,1605}]}};
unicode_table(64872) ->
    {0,[],{initial,[{0,1588}, {0,1581}, {0,1605}]}};
unicode_table(64873) ->
    {0,[],{final,[{0,1588}, {0,1580}, {0,1610}]}};
unicode_table(64874) ->
    {0,[],{final,[{0,1588}, {0,1605}, {0,1582}]}};
unicode_table(64875) ->
    {0,[],{initial,[{0,1588}, {0,1605}, {0,1582}]}};
unicode_table(64876) ->
    {0,[],{final,[{0,1588}, {0,1605}, {0,1605}]}};
unicode_table(64877) ->
    {0,[],{initial,[{0,1588}, {0,1605}, {0,1605}]}};
unicode_table(64878) ->
    {0,[],{final,[{0,1590}, {0,1581}, {0,1609}]}};
unicode_table(64879) ->
    {0,[],{final,[{0,1590}, {0,1582}, {0,1605}]}};
unicode_table(64880) ->
    {0,[],{initial,[{0,1590}, {0,1582}, {0,1605}]}};
unicode_table(64881) ->
    {0,[],{final,[{0,1591}, {0,1605}, {0,1581}]}};
unicode_table(64882) ->
    {0,[],{initial,[{0,1591}, {0,1605}, {0,1581}]}};
unicode_table(64883) ->
    {0,[],{initial,[{0,1591}, {0,1605}, {0,1605}]}};
unicode_table(64884) ->
    {0,[],{final,[{0,1591}, {0,1605}, {0,1610}]}};
unicode_table(64885) ->
    {0,[],{final,[{0,1593}, {0,1580}, {0,1605}]}};
unicode_table(64886) ->
    {0,[],{final,[{0,1593}, {0,1605}, {0,1605}]}};
unicode_table(64887) ->
    {0,[],{initial,[{0,1593}, {0,1605}, {0,1605}]}};
unicode_table(64888) ->
    {0,[],{final,[{0,1593}, {0,1605}, {0,1609}]}};
unicode_table(64889) ->
    {0,[],{final,[{0,1594}, {0,1605}, {0,1605}]}};
unicode_table(64890) ->
    {0,[],{final,[{0,1594}, {0,1605}, {0,1610}]}};
unicode_table(64891) ->
    {0,[],{final,[{0,1594}, {0,1605}, {0,1609}]}};
unicode_table(64892) ->
    {0,[],{final,[{0,1601}, {0,1582}, {0,1605}]}};
unicode_table(64893) ->
    {0,[],{initial,[{0,1601}, {0,1582}, {0,1605}]}};
unicode_table(64894) ->
    {0,[],{final,[{0,1602}, {0,1605}, {0,1581}]}};
unicode_table(64895) ->
    {0,[],{final,[{0,1602}, {0,1605}, {0,1605}]}};
unicode_table(64896) ->
    {0,[],{final,[{0,1604}, {0,1581}, {0,1605}]}};
unicode_table(64897) ->
    {0,[],{final,[{0,1604}, {0,1581}, {0,1610}]}};
unicode_table(64898) ->
    {0,[],{final,[{0,1604}, {0,1581}, {0,1609}]}};
unicode_table(64899) ->
    {0,[],{initial,[{0,1604}, {0,1580}, {0,1580}]}};
unicode_table(64900) ->
    {0,[],{final,[{0,1604}, {0,1580}, {0,1580}]}};
unicode_table(64901) ->
    {0,[],{final,[{0,1604}, {0,1582}, {0,1605}]}};
unicode_table(64902) ->
    {0,[],{initial,[{0,1604}, {0,1582}, {0,1605}]}};
unicode_table(64903) ->
    {0,[],{final,[{0,1604}, {0,1605}, {0,1581}]}};
unicode_table(64904) ->
    {0,[],{initial,[{0,1604}, {0,1605}, {0,1581}]}};
unicode_table(64905) ->
    {0,[],{initial,[{0,1605}, {0,1581}, {0,1580}]}};
unicode_table(64906) ->
    {0,[],{initial,[{0,1605}, {0,1581}, {0,1605}]}};
unicode_table(64907) ->
    {0,[],{final,[{0,1605}, {0,1581}, {0,1610}]}};
unicode_table(64908) ->
    {0,[],{initial,[{0,1605}, {0,1580}, {0,1581}]}};
unicode_table(64909) ->
    {0,[],{initial,[{0,1605}, {0,1580}, {0,1605}]}};
unicode_table(64910) ->
    {0,[],{initial,[{0,1605}, {0,1582}, {0,1580}]}};
unicode_table(64911) ->
    {0,[],{initial,[{0,1605}, {0,1582}, {0,1605}]}};
unicode_table(64914) ->
    {0,[],{initial,[{0,1605}, {0,1580}, {0,1582}]}};
unicode_table(64915) ->
    {0,[],{initial,[{0,1607}, {0,1605}, {0,1580}]}};
unicode_table(64916) ->
    {0,[],{initial,[{0,1607}, {0,1605}, {0,1605}]}};
unicode_table(64917) ->
    {0,[],{initial,[{0,1606}, {0,1581}, {0,1605}]}};
unicode_table(64918) ->
    {0,[],{final,[{0,1606}, {0,1581}, {0,1609}]}};
unicode_table(64919) ->
    {0,[],{final,[{0,1606}, {0,1580}, {0,1605}]}};
unicode_table(64920) ->
    {0,[],{initial,[{0,1606}, {0,1580}, {0,1605}]}};
unicode_table(64921) ->
    {0,[],{final,[{0,1606}, {0,1580}, {0,1609}]}};
unicode_table(64922) ->
    {0,[],{final,[{0,1606}, {0,1605}, {0,1610}]}};
unicode_table(64923) ->
    {0,[],{final,[{0,1606}, {0,1605}, {0,1609}]}};
unicode_table(64924) ->
    {0,[],{final,[{0,1610}, {0,1605}, {0,1605}]}};
unicode_table(64925) ->
    {0,[],{initial,[{0,1610}, {0,1605}, {0,1605}]}};
unicode_table(64926) ->
    {0,[],{final,[{0,1576}, {0,1582}, {0,1610}]}};
unicode_table(64927) ->
    {0,[],{final,[{0,1578}, {0,1580}, {0,1610}]}};
unicode_table(64928) ->
    {0,[],{final,[{0,1578}, {0,1580}, {0,1609}]}};
unicode_table(64929) ->
    {0,[],{final,[{0,1578}, {0,1582}, {0,1610}]}};
unicode_table(64930) ->
    {0,[],{final,[{0,1578}, {0,1582}, {0,1609}]}};
unicode_table(64931) ->
    {0,[],{final,[{0,1578}, {0,1605}, {0,1610}]}};
unicode_table(64932) ->
    {0,[],{final,[{0,1578}, {0,1605}, {0,1609}]}};
unicode_table(64933) ->
    {0,[],{final,[{0,1580}, {0,1605}, {0,1610}]}};
unicode_table(64934) ->
    {0,[],{final,[{0,1580}, {0,1581}, {0,1609}]}};
unicode_table(64935) ->
    {0,[],{final,[{0,1580}, {0,1605}, {0,1609}]}};
unicode_table(64936) ->
    {0,[],{final,[{0,1587}, {0,1582}, {0,1609}]}};
unicode_table(64937) ->
    {0,[],{final,[{0,1589}, {0,1581}, {0,1610}]}};
unicode_table(64938) ->
    {0,[],{final,[{0,1588}, {0,1581}, {0,1610}]}};
unicode_table(64939) ->
    {0,[],{final,[{0,1590}, {0,1581}, {0,1610}]}};
unicode_table(64940) ->
    {0,[],{final,[{0,1604}, {0,1580}, {0,1610}]}};
unicode_table(64941) ->
    {0,[],{final,[{0,1604}, {0,1605}, {0,1610}]}};
unicode_table(64942) ->
    {0,[],{final,[{0,1610}, {0,1581}, {0,1610}]}};
unicode_table(64943) ->
    {0,[],{final,[{0,1610}, {0,1580}, {0,1610}]}};
unicode_table(64944) ->
    {0,[],{final,[{0,1610}, {0,1605}, {0,1610}]}};
unicode_table(64945) ->
    {0,[],{final,[{0,1605}, {0,1605}, {0,1610}]}};
unicode_table(64946) ->
    {0,[],{final,[{0,1602}, {0,1605}, {0,1610}]}};
unicode_table(64947) ->
    {0,[],{final,[{0,1606}, {0,1581}, {0,1610}]}};
unicode_table(64948) ->
    {0,[],{initial,[{0,1602}, {0,1605}, {0,1581}]}};
unicode_table(64949) ->
    {0,[],{initial,[{0,1604}, {0,1581}, {0,1605}]}};
unicode_table(64950) ->
    {0,[],{final,[{0,1593}, {0,1605}, {0,1610}]}};
unicode_table(64951) ->
    {0,[],{final,[{0,1603}, {0,1605}, {0,1610}]}};
unicode_table(64952) ->
    {0,[],{initial,[{0,1606}, {0,1580}, {0,1581}]}};
unicode_table(64953) ->
    {0,[],{final,[{0,1605}, {0,1582}, {0,1610}]}};
unicode_table(64954) ->
    {0,[],{initial,[{0,1604}, {0,1580}, {0,1605}]}};
unicode_table(64955) ->
    {0,[],{final,[{0,1603}, {0,1605}, {0,1605}]}};
unicode_table(64956) ->
    {0,[],{final,[{0,1604}, {0,1580}, {0,1605}]}};
unicode_table(64957) ->
    {0,[],{final,[{0,1606}, {0,1580}, {0,1581}]}};
unicode_table(64958) ->
    {0,[],{final,[{0,1580}, {0,1581}, {0,1610}]}};
unicode_table(64959) ->
    {0,[],{final,[{0,1581}, {0,1580}, {0,1610}]}};
unicode_table(64960) ->
    {0,[],{final,[{0,1605}, {0,1580}, {0,1610}]}};
unicode_table(64961) ->
    {0,[],{final,[{0,1601}, {0,1605}, {0,1610}]}};
unicode_table(64962) ->
    {0,[],{final,[{0,1576}, {0,1581}, {0,1610}]}};
unicode_table(64963) ->
    {0,[],{initial,[{0,1603}, {0,1605}, {0,1605}]}};
unicode_table(64964) ->
    {0,[],{initial,[{0,1593}, {0,1580}, {0,1605}]}};
unicode_table(64965) ->
    {0,[],{initial,[{0,1589}, {0,1605}, {0,1605}]}};
unicode_table(64966) ->
    {0,[],{final,[{0,1587}, {0,1582}, {0,1610}]}};
unicode_table(64967) ->
    {0,[],{final,[{0,1606}, {0,1580}, {0,1610}]}};
unicode_table(65008) ->
    {0,[],{isolated,[{0,1589}, {0,1604}, {0,1746}]}};
unicode_table(65009) ->
    {0,[],{isolated,[{0,1602}, {0,1604}, {0,1746}]}};
unicode_table(65010) ->
    {0,[],{isolated,[{0,1575}, {0,1604}, {0,1604}, {0,1607}]}};
unicode_table(65011) ->
    {0,[],{isolated,[{0,1575}, {0,1603}, {0,1576}, {0,1585}]}};
unicode_table(65012) ->
    {0,[],{isolated,[{0,1605}, {0,1581}, {0,1605}, {0,1583}]}};
unicode_table(65013) ->
    {0,[],{isolated,[{0,1589}, {0,1604}, {0,1593}, {0,1605}]}};
unicode_table(65014) ->
    {0,[],{isolated,[{0,1585}, {0,1587}, {0,1608}, {0,1604}]}};
unicode_table(65015) ->
    {0,[],{isolated,[{0,1593}, {0,1604}, {0,1610}, {0,1607}]}};
unicode_table(65016) ->
    {0,[],{isolated,[{0,1608}, {0,1587}, {0,1604}, {0,1605}]}};
unicode_table(65017) ->
    {0,[],{isolated,[{0,1589}, {0,1604}, {0,1609}]}};
unicode_table(65018) ->
    {0,[],{isolated,[{0,1589}, {0,1604}, {0,1609}, {0,32}, {0,1575}, {0,1604}, {0,1604}, {0,1607}, {0,32}, {0,1593}, {0,1604}, {0,1610}, {0,1607}, {0,32}, {0,1608}, {0,1587}, {0,1604}, {0,1605}]}};
unicode_table(65019) ->
    {0,[],{isolated,[{0,1580}, {0,1604}, {0,32}, {0,1580}, {0,1604}, {0,1575}, {0,1604}, {0,1607}]}};
unicode_table(65020) ->
    {0,[],{isolated,[{0,1585}, {0,1740}, {0,1575}, {0,1604}]}};
unicode_table(65040) ->
    {0,[],{vertical,[{0,44}]}};
unicode_table(65041) ->
    {0,[],{vertical,[{0,12289}]}};
unicode_table(65042) ->
    {0,[],{vertical,[{0,12290}]}};
unicode_table(65043) ->
    {0,[],{vertical,[{0,58}]}};
unicode_table(65044) ->
    {0,[],{vertical,[{0,59}]}};
unicode_table(65045) ->
    {0,[],{vertical,[{0,33}]}};
unicode_table(65046) ->
    {0,[],{vertical,[{0,63}]}};
unicode_table(65047) ->
    {0,[],{vertical,[{0,12310}]}};
unicode_table(65048) ->
    {0,[],{vertical,[{0,12311}]}};
unicode_table(65049) ->
    {0,[],{vertical,[{0,46}, {0,46}, {0,46}]}};
unicode_table(65056) ->
    {230,[],[]};
unicode_table(65057) ->
    {230,[],[]};
unicode_table(65058) ->
    {230,[],[]};
unicode_table(65059) ->
    {230,[],[]};
unicode_table(65060) ->
    {230,[],[]};
unicode_table(65061) ->
    {230,[],[]};
unicode_table(65062) ->
    {230,[],[]};
unicode_table(65063) ->
    {220,[],[]};
unicode_table(65064) ->
    {220,[],[]};
unicode_table(65065) ->
    {220,[],[]};
unicode_table(65066) ->
    {220,[],[]};
unicode_table(65067) ->
    {220,[],[]};
unicode_table(65068) ->
    {220,[],[]};
unicode_table(65069) ->
    {220,[],[]};
unicode_table(65070) ->
    {230,[],[]};
unicode_table(65071) ->
    {230,[],[]};
unicode_table(65072) ->
    {0,[],{vertical,[{0,46}, {0,46}]}};
unicode_table(65073) ->
    {0,[],{vertical,[{0,8212}]}};
unicode_table(65074) ->
    {0,[],{vertical,[{0,8211}]}};
unicode_table(65075) ->
    {0,[],{vertical,[{0,95}]}};
unicode_table(65076) ->
    {0,[],{vertical,[{0,95}]}};
unicode_table(65077) ->
    {0,[],{vertical,[{0,40}]}};
unicode_table(65078) ->
    {0,[],{vertical,[{0,41}]}};
unicode_table(65079) ->
    {0,[],{vertical,[{0,123}]}};
unicode_table(65080) ->
    {0,[],{vertical,[{0,125}]}};
unicode_table(65081) ->
    {0,[],{vertical,[{0,12308}]}};
unicode_table(65082) ->
    {0,[],{vertical,[{0,12309}]}};
unicode_table(65083) ->
    {0,[],{vertical,[{0,12304}]}};
unicode_table(65084) ->
    {0,[],{vertical,[{0,12305}]}};
unicode_table(65085) ->
    {0,[],{vertical,[{0,12298}]}};
unicode_table(65086) ->
    {0,[],{vertical,[{0,12299}]}};
unicode_table(65087) ->
    {0,[],{vertical,[{0,12296}]}};
unicode_table(65088) ->
    {0,[],{vertical,[{0,12297}]}};
unicode_table(65089) ->
    {0,[],{vertical,[{0,12300}]}};
unicode_table(65090) ->
    {0,[],{vertical,[{0,12301}]}};
unicode_table(65091) ->
    {0,[],{vertical,[{0,12302}]}};
unicode_table(65092) ->
    {0,[],{vertical,[{0,12303}]}};
unicode_table(65095) ->
    {0,[],{vertical,[{0,91}]}};
unicode_table(65096) ->
    {0,[],{vertical,[{0,93}]}};
unicode_table(65097) ->
    {0,[],{compat,[{0,32}, {230,773}]}};
unicode_table(65098) ->
    {0,[],{compat,[{0,32}, {230,773}]}};
unicode_table(65099) ->
    {0,[],{compat,[{0,32}, {230,773}]}};
unicode_table(65100) ->
    {0,[],{compat,[{0,32}, {230,773}]}};
unicode_table(65101) ->
    {0,[],{compat,[{0,95}]}};
unicode_table(65102) ->
    {0,[],{compat,[{0,95}]}};
unicode_table(65103) ->
    {0,[],{compat,[{0,95}]}};
unicode_table(65104) ->
    {0,[],{small,[{0,44}]}};
unicode_table(65105) ->
    {0,[],{small,[{0,12289}]}};
unicode_table(65106) ->
    {0,[],{small,[{0,46}]}};
unicode_table(65108) ->
    {0,[],{small,[{0,59}]}};
unicode_table(65109) ->
    {0,[],{small,[{0,58}]}};
unicode_table(65110) ->
    {0,[],{small,[{0,63}]}};
unicode_table(65111) ->
    {0,[],{small,[{0,33}]}};
unicode_table(65112) ->
    {0,[],{small,[{0,8212}]}};
unicode_table(65113) ->
    {0,[],{small,[{0,40}]}};
unicode_table(65114) ->
    {0,[],{small,[{0,41}]}};
unicode_table(65115) ->
    {0,[],{small,[{0,123}]}};
unicode_table(65116) ->
    {0,[],{small,[{0,125}]}};
unicode_table(65117) ->
    {0,[],{small,[{0,12308}]}};
unicode_table(65118) ->
    {0,[],{small,[{0,12309}]}};
unicode_table(65119) ->
    {0,[],{small,[{0,35}]}};
unicode_table(65120) ->
    {0,[],{small,[{0,38}]}};
unicode_table(65121) ->
    {0,[],{small,[{0,42}]}};
unicode_table(65122) ->
    {0,[],{small,[{0,43}]}};
unicode_table(65123) ->
    {0,[],{small,[{0,45}]}};
unicode_table(65124) ->
    {0,[],{small,[{0,60}]}};
unicode_table(65125) ->
    {0,[],{small,[{0,62}]}};
unicode_table(65126) ->
    {0,[],{small,[{0,61}]}};
unicode_table(65128) ->
    {0,[],{small,[{0,92}]}};
unicode_table(65129) ->
    {0,[],{small,[{0,36}]}};
unicode_table(65130) ->
    {0,[],{small,[{0,37}]}};
unicode_table(65131) ->
    {0,[],{small,[{0,64}]}};
unicode_table(65136) ->
    {0,[],{isolated,[{0,32}, {27,1611}]}};
unicode_table(65137) ->
    {0,[],{medial,[{0,1600}, {27,1611}]}};
unicode_table(65138) ->
    {0,[],{isolated,[{0,32}, {28,1612}]}};
unicode_table(65140) ->
    {0,[],{isolated,[{0,32}, {29,1613}]}};
unicode_table(65142) ->
    {0,[],{isolated,[{0,32}, {30,1614}]}};
unicode_table(65143) ->
    {0,[],{medial,[{0,1600}, {30,1614}]}};
unicode_table(65144) ->
    {0,[],{isolated,[{0,32}, {31,1615}]}};
unicode_table(65145) ->
    {0,[],{medial,[{0,1600}, {31,1615}]}};
unicode_table(65146) ->
    {0,[],{isolated,[{0,32}, {32,1616}]}};
unicode_table(65147) ->
    {0,[],{medial,[{0,1600}, {32,1616}]}};
unicode_table(65148) ->
    {0,[],{isolated,[{0,32}, {33,1617}]}};
unicode_table(65149) ->
    {0,[],{medial,[{0,1600}, {33,1617}]}};
unicode_table(65150) ->
    {0,[],{isolated,[{0,32}, {34,1618}]}};
unicode_table(65151) ->
    {0,[],{medial,[{0,1600}, {34,1618}]}};
unicode_table(65152) ->
    {0,[],{isolated,[{0,1569}]}};
unicode_table(65153) ->
    {0,[],{isolated,[{0,1575}, {230,1619}]}};
unicode_table(65154) ->
    {0,[],{final,[{0,1575}, {230,1619}]}};
unicode_table(65155) ->
    {0,[],{isolated,[{0,1575}, {230,1620}]}};
unicode_table(65156) ->
    {0,[],{final,[{0,1575}, {230,1620}]}};
unicode_table(65157) ->
    {0,[],{isolated,[{0,1608}, {230,1620}]}};
unicode_table(65158) ->
    {0,[],{final,[{0,1608}, {230,1620}]}};
unicode_table(65159) ->
    {0,[],{isolated,[{0,1575}, {220,1621}]}};
unicode_table(65160) ->
    {0,[],{final,[{0,1575}, {220,1621}]}};
unicode_table(65161) ->
    {0,[],{isolated,[{0,1610}, {230,1620}]}};
unicode_table(65162) ->
    {0,[],{final,[{0,1610}, {230,1620}]}};
unicode_table(65163) ->
    {0,[],{initial,[{0,1610}, {230,1620}]}};
unicode_table(65164) ->
    {0,[],{medial,[{0,1610}, {230,1620}]}};
unicode_table(65165) ->
    {0,[],{isolated,[{0,1575}]}};
unicode_table(65166) ->
    {0,[],{final,[{0,1575}]}};
unicode_table(65167) ->
    {0,[],{isolated,[{0,1576}]}};
unicode_table(65168) ->
    {0,[],{final,[{0,1576}]}};
unicode_table(65169) ->
    {0,[],{initial,[{0,1576}]}};
unicode_table(65170) ->
    {0,[],{medial,[{0,1576}]}};
unicode_table(65171) ->
    {0,[],{isolated,[{0,1577}]}};
unicode_table(65172) ->
    {0,[],{final,[{0,1577}]}};
unicode_table(65173) ->
    {0,[],{isolated,[{0,1578}]}};
unicode_table(65174) ->
    {0,[],{final,[{0,1578}]}};
unicode_table(65175) ->
    {0,[],{initial,[{0,1578}]}};
unicode_table(65176) ->
    {0,[],{medial,[{0,1578}]}};
unicode_table(65177) ->
    {0,[],{isolated,[{0,1579}]}};
unicode_table(65178) ->
    {0,[],{final,[{0,1579}]}};
unicode_table(65179) ->
    {0,[],{initial,[{0,1579}]}};
unicode_table(65180) ->
    {0,[],{medial,[{0,1579}]}};
unicode_table(65181) ->
    {0,[],{isolated,[{0,1580}]}};
unicode_table(65182) ->
    {0,[],{final,[{0,1580}]}};
unicode_table(65183) ->
    {0,[],{initial,[{0,1580}]}};
unicode_table(65184) ->
    {0,[],{medial,[{0,1580}]}};
unicode_table(65185) ->
    {0,[],{isolated,[{0,1581}]}};
unicode_table(65186) ->
    {0,[],{final,[{0,1581}]}};
unicode_table(65187) ->
    {0,[],{initial,[{0,1581}]}};
unicode_table(65188) ->
    {0,[],{medial,[{0,1581}]}};
unicode_table(65189) ->
    {0,[],{isolated,[{0,1582}]}};
unicode_table(65190) ->
    {0,[],{final,[{0,1582}]}};
unicode_table(65191) ->
    {0,[],{initial,[{0,1582}]}};
unicode_table(65192) ->
    {0,[],{medial,[{0,1582}]}};
unicode_table(65193) ->
    {0,[],{isolated,[{0,1583}]}};
unicode_table(65194) ->
    {0,[],{final,[{0,1583}]}};
unicode_table(65195) ->
    {0,[],{isolated,[{0,1584}]}};
unicode_table(65196) ->
    {0,[],{final,[{0,1584}]}};
unicode_table(65197) ->
    {0,[],{isolated,[{0,1585}]}};
unicode_table(65198) ->
    {0,[],{final,[{0,1585}]}};
unicode_table(65199) ->
    {0,[],{isolated,[{0,1586}]}};
unicode_table(65200) ->
    {0,[],{final,[{0,1586}]}};
unicode_table(65201) ->
    {0,[],{isolated,[{0,1587}]}};
unicode_table(65202) ->
    {0,[],{final,[{0,1587}]}};
unicode_table(65203) ->
    {0,[],{initial,[{0,1587}]}};
unicode_table(65204) ->
    {0,[],{medial,[{0,1587}]}};
unicode_table(65205) ->
    {0,[],{isolated,[{0,1588}]}};
unicode_table(65206) ->
    {0,[],{final,[{0,1588}]}};
unicode_table(65207) ->
    {0,[],{initial,[{0,1588}]}};
unicode_table(65208) ->
    {0,[],{medial,[{0,1588}]}};
unicode_table(65209) ->
    {0,[],{isolated,[{0,1589}]}};
unicode_table(65210) ->
    {0,[],{final,[{0,1589}]}};
unicode_table(65211) ->
    {0,[],{initial,[{0,1589}]}};
unicode_table(65212) ->
    {0,[],{medial,[{0,1589}]}};
unicode_table(65213) ->
    {0,[],{isolated,[{0,1590}]}};
unicode_table(65214) ->
    {0,[],{final,[{0,1590}]}};
unicode_table(65215) ->
    {0,[],{initial,[{0,1590}]}};
unicode_table(65216) ->
    {0,[],{medial,[{0,1590}]}};
unicode_table(65217) ->
    {0,[],{isolated,[{0,1591}]}};
unicode_table(65218) ->
    {0,[],{final,[{0,1591}]}};
unicode_table(65219) ->
    {0,[],{initial,[{0,1591}]}};
unicode_table(65220) ->
    {0,[],{medial,[{0,1591}]}};
unicode_table(65221) ->
    {0,[],{isolated,[{0,1592}]}};
unicode_table(65222) ->
    {0,[],{final,[{0,1592}]}};
unicode_table(65223) ->
    {0,[],{initial,[{0,1592}]}};
unicode_table(65224) ->
    {0,[],{medial,[{0,1592}]}};
unicode_table(65225) ->
    {0,[],{isolated,[{0,1593}]}};
unicode_table(65226) ->
    {0,[],{final,[{0,1593}]}};
unicode_table(65227) ->
    {0,[],{initial,[{0,1593}]}};
unicode_table(65228) ->
    {0,[],{medial,[{0,1593}]}};
unicode_table(65229) ->
    {0,[],{isolated,[{0,1594}]}};
unicode_table(65230) ->
    {0,[],{final,[{0,1594}]}};
unicode_table(65231) ->
    {0,[],{initial,[{0,1594}]}};
unicode_table(65232) ->
    {0,[],{medial,[{0,1594}]}};
unicode_table(65233) ->
    {0,[],{isolated,[{0,1601}]}};
unicode_table(65234) ->
    {0,[],{final,[{0,1601}]}};
unicode_table(65235) ->
    {0,[],{initial,[{0,1601}]}};
unicode_table(65236) ->
    {0,[],{medial,[{0,1601}]}};
unicode_table(65237) ->
    {0,[],{isolated,[{0,1602}]}};
unicode_table(65238) ->
    {0,[],{final,[{0,1602}]}};
unicode_table(65239) ->
    {0,[],{initial,[{0,1602}]}};
unicode_table(65240) ->
    {0,[],{medial,[{0,1602}]}};
unicode_table(65241) ->
    {0,[],{isolated,[{0,1603}]}};
unicode_table(65242) ->
    {0,[],{final,[{0,1603}]}};
unicode_table(65243) ->
    {0,[],{initial,[{0,1603}]}};
unicode_table(65244) ->
    {0,[],{medial,[{0,1603}]}};
unicode_table(65245) ->
    {0,[],{isolated,[{0,1604}]}};
unicode_table(65246) ->
    {0,[],{final,[{0,1604}]}};
unicode_table(65247) ->
    {0,[],{initial,[{0,1604}]}};
unicode_table(65248) ->
    {0,[],{medial,[{0,1604}]}};
unicode_table(65249) ->
    {0,[],{isolated,[{0,1605}]}};
unicode_table(65250) ->
    {0,[],{final,[{0,1605}]}};
unicode_table(65251) ->
    {0,[],{initial,[{0,1605}]}};
unicode_table(65252) ->
    {0,[],{medial,[{0,1605}]}};
unicode_table(65253) ->
    {0,[],{isolated,[{0,1606}]}};
unicode_table(65254) ->
    {0,[],{final,[{0,1606}]}};
unicode_table(65255) ->
    {0,[],{initial,[{0,1606}]}};
unicode_table(65256) ->
    {0,[],{medial,[{0,1606}]}};
unicode_table(65257) ->
    {0,[],{isolated,[{0,1607}]}};
unicode_table(65258) ->
    {0,[],{final,[{0,1607}]}};
unicode_table(65259) ->
    {0,[],{initial,[{0,1607}]}};
unicode_table(65260) ->
    {0,[],{medial,[{0,1607}]}};
unicode_table(65261) ->
    {0,[],{isolated,[{0,1608}]}};
unicode_table(65262) ->
    {0,[],{final,[{0,1608}]}};
unicode_table(65263) ->
    {0,[],{isolated,[{0,1609}]}};
unicode_table(65264) ->
    {0,[],{final,[{0,1609}]}};
unicode_table(65265) ->
    {0,[],{isolated,[{0,1610}]}};
unicode_table(65266) ->
    {0,[],{final,[{0,1610}]}};
unicode_table(65267) ->
    {0,[],{initial,[{0,1610}]}};
unicode_table(65268) ->
    {0,[],{medial,[{0,1610}]}};
unicode_table(65269) ->
    {0,[],{isolated,[{0,1604}, {0,1575}, {230,1619}]}};
unicode_table(65270) ->
    {0,[],{final,[{0,1604}, {0,1575}, {230,1619}]}};
unicode_table(65271) ->
    {0,[],{isolated,[{0,1604}, {0,1575}, {230,1620}]}};
unicode_table(65272) ->
    {0,[],{final,[{0,1604}, {0,1575}, {230,1620}]}};
unicode_table(65273) ->
    {0,[],{isolated,[{0,1604}, {0,1575}, {220,1621}]}};
unicode_table(65274) ->
    {0,[],{final,[{0,1604}, {0,1575}, {220,1621}]}};
unicode_table(65275) ->
    {0,[],{isolated,[{0,1604}, {0,1575}]}};
unicode_table(65276) ->
    {0,[],{final,[{0,1604}, {0,1575}]}};
unicode_table(65281) ->
    {0,[],{wide,[{0,33}]}};
unicode_table(65282) ->
    {0,[],{wide,[{0,34}]}};
unicode_table(65283) ->
    {0,[],{wide,[{0,35}]}};
unicode_table(65284) ->
    {0,[],{wide,[{0,36}]}};
unicode_table(65285) ->
    {0,[],{wide,[{0,37}]}};
unicode_table(65286) ->
    {0,[],{wide,[{0,38}]}};
unicode_table(65287) ->
    {0,[],{wide,[{0,39}]}};
unicode_table(65288) ->
    {0,[],{wide,[{0,40}]}};
unicode_table(65289) ->
    {0,[],{wide,[{0,41}]}};
unicode_table(65290) ->
    {0,[],{wide,[{0,42}]}};
unicode_table(65291) ->
    {0,[],{wide,[{0,43}]}};
unicode_table(65292) ->
    {0,[],{wide,[{0,44}]}};
unicode_table(65293) ->
    {0,[],{wide,[{0,45}]}};
unicode_table(65294) ->
    {0,[],{wide,[{0,46}]}};
unicode_table(65295) ->
    {0,[],{wide,[{0,47}]}};
unicode_table(65296) ->
    {0,[],{wide,[{0,48}]}};
unicode_table(65297) ->
    {0,[],{wide,[{0,49}]}};
unicode_table(65298) ->
    {0,[],{wide,[{0,50}]}};
unicode_table(65299) ->
    {0,[],{wide,[{0,51}]}};
unicode_table(65300) ->
    {0,[],{wide,[{0,52}]}};
unicode_table(65301) ->
    {0,[],{wide,[{0,53}]}};
unicode_table(65302) ->
    {0,[],{wide,[{0,54}]}};
unicode_table(65303) ->
    {0,[],{wide,[{0,55}]}};
unicode_table(65304) ->
    {0,[],{wide,[{0,56}]}};
unicode_table(65305) ->
    {0,[],{wide,[{0,57}]}};
unicode_table(65306) ->
    {0,[],{wide,[{0,58}]}};
unicode_table(65307) ->
    {0,[],{wide,[{0,59}]}};
unicode_table(65308) ->
    {0,[],{wide,[{0,60}]}};
unicode_table(65309) ->
    {0,[],{wide,[{0,61}]}};
unicode_table(65310) ->
    {0,[],{wide,[{0,62}]}};
unicode_table(65311) ->
    {0,[],{wide,[{0,63}]}};
unicode_table(65312) ->
    {0,[],{wide,[{0,64}]}};
unicode_table(65313) ->
    {0,[],{wide,[{0,65}]}};
unicode_table(65314) ->
    {0,[],{wide,[{0,66}]}};
unicode_table(65315) ->
    {0,[],{wide,[{0,67}]}};
unicode_table(65316) ->
    {0,[],{wide,[{0,68}]}};
unicode_table(65317) ->
    {0,[],{wide,[{0,69}]}};
unicode_table(65318) ->
    {0,[],{wide,[{0,70}]}};
unicode_table(65319) ->
    {0,[],{wide,[{0,71}]}};
unicode_table(65320) ->
    {0,[],{wide,[{0,72}]}};
unicode_table(65321) ->
    {0,[],{wide,[{0,73}]}};
unicode_table(65322) ->
    {0,[],{wide,[{0,74}]}};
unicode_table(65323) ->
    {0,[],{wide,[{0,75}]}};
unicode_table(65324) ->
    {0,[],{wide,[{0,76}]}};
unicode_table(65325) ->
    {0,[],{wide,[{0,77}]}};
unicode_table(65326) ->
    {0,[],{wide,[{0,78}]}};
unicode_table(65327) ->
    {0,[],{wide,[{0,79}]}};
unicode_table(65328) ->
    {0,[],{wide,[{0,80}]}};
unicode_table(65329) ->
    {0,[],{wide,[{0,81}]}};
unicode_table(65330) ->
    {0,[],{wide,[{0,82}]}};
unicode_table(65331) ->
    {0,[],{wide,[{0,83}]}};
unicode_table(65332) ->
    {0,[],{wide,[{0,84}]}};
unicode_table(65333) ->
    {0,[],{wide,[{0,85}]}};
unicode_table(65334) ->
    {0,[],{wide,[{0,86}]}};
unicode_table(65335) ->
    {0,[],{wide,[{0,87}]}};
unicode_table(65336) ->
    {0,[],{wide,[{0,88}]}};
unicode_table(65337) ->
    {0,[],{wide,[{0,89}]}};
unicode_table(65338) ->
    {0,[],{wide,[{0,90}]}};
unicode_table(65339) ->
    {0,[],{wide,[{0,91}]}};
unicode_table(65340) ->
    {0,[],{wide,[{0,92}]}};
unicode_table(65341) ->
    {0,[],{wide,[{0,93}]}};
unicode_table(65342) ->
    {0,[],{wide,[{0,94}]}};
unicode_table(65343) ->
    {0,[],{wide,[{0,95}]}};
unicode_table(65344) ->
    {0,[],{wide,[{0,96}]}};
unicode_table(65345) ->
    {0,[],{wide,[{0,97}]}};
unicode_table(65346) ->
    {0,[],{wide,[{0,98}]}};
unicode_table(65347) ->
    {0,[],{wide,[{0,99}]}};
unicode_table(65348) ->
    {0,[],{wide,[{0,100}]}};
unicode_table(65349) ->
    {0,[],{wide,[{0,101}]}};
unicode_table(65350) ->
    {0,[],{wide,[{0,102}]}};
unicode_table(65351) ->
    {0,[],{wide,[{0,103}]}};
unicode_table(65352) ->
    {0,[],{wide,[{0,104}]}};
unicode_table(65353) ->
    {0,[],{wide,[{0,105}]}};
unicode_table(65354) ->
    {0,[],{wide,[{0,106}]}};
unicode_table(65355) ->
    {0,[],{wide,[{0,107}]}};
unicode_table(65356) ->
    {0,[],{wide,[{0,108}]}};
unicode_table(65357) ->
    {0,[],{wide,[{0,109}]}};
unicode_table(65358) ->
    {0,[],{wide,[{0,110}]}};
unicode_table(65359) ->
    {0,[],{wide,[{0,111}]}};
unicode_table(65360) ->
    {0,[],{wide,[{0,112}]}};
unicode_table(65361) ->
    {0,[],{wide,[{0,113}]}};
unicode_table(65362) ->
    {0,[],{wide,[{0,114}]}};
unicode_table(65363) ->
    {0,[],{wide,[{0,115}]}};
unicode_table(65364) ->
    {0,[],{wide,[{0,116}]}};
unicode_table(65365) ->
    {0,[],{wide,[{0,117}]}};
unicode_table(65366) ->
    {0,[],{wide,[{0,118}]}};
unicode_table(65367) ->
    {0,[],{wide,[{0,119}]}};
unicode_table(65368) ->
    {0,[],{wide,[{0,120}]}};
unicode_table(65369) ->
    {0,[],{wide,[{0,121}]}};
unicode_table(65370) ->
    {0,[],{wide,[{0,122}]}};
unicode_table(65371) ->
    {0,[],{wide,[{0,123}]}};
unicode_table(65372) ->
    {0,[],{wide,[{0,124}]}};
unicode_table(65373) ->
    {0,[],{wide,[{0,125}]}};
unicode_table(65374) ->
    {0,[],{wide,[{0,126}]}};
unicode_table(65375) ->
    {0,[],{wide,[{0,10629}]}};
unicode_table(65376) ->
    {0,[],{wide,[{0,10630}]}};
unicode_table(65377) ->
    {0,[],{narrow,[{0,12290}]}};
unicode_table(65378) ->
    {0,[],{narrow,[{0,12300}]}};
unicode_table(65379) ->
    {0,[],{narrow,[{0,12301}]}};
unicode_table(65380) ->
    {0,[],{narrow,[{0,12289}]}};
unicode_table(65381) ->
    {0,[],{narrow,[{0,12539}]}};
unicode_table(65382) ->
    {0,[],{narrow,[{0,12530}]}};
unicode_table(65383) ->
    {0,[],{narrow,[{0,12449}]}};
unicode_table(65384) ->
    {0,[],{narrow,[{0,12451}]}};
unicode_table(65385) ->
    {0,[],{narrow,[{0,12453}]}};
unicode_table(65386) ->
    {0,[],{narrow,[{0,12455}]}};
unicode_table(65387) ->
    {0,[],{narrow,[{0,12457}]}};
unicode_table(65388) ->
    {0,[],{narrow,[{0,12515}]}};
unicode_table(65389) ->
    {0,[],{narrow,[{0,12517}]}};
unicode_table(65390) ->
    {0,[],{narrow,[{0,12519}]}};
unicode_table(65391) ->
    {0,[],{narrow,[{0,12483}]}};
unicode_table(65392) ->
    {0,[],{narrow,[{0,12540}]}};
unicode_table(65393) ->
    {0,[],{narrow,[{0,12450}]}};
unicode_table(65394) ->
    {0,[],{narrow,[{0,12452}]}};
unicode_table(65395) ->
    {0,[],{narrow,[{0,12454}]}};
unicode_table(65396) ->
    {0,[],{narrow,[{0,12456}]}};
unicode_table(65397) ->
    {0,[],{narrow,[{0,12458}]}};
unicode_table(65398) ->
    {0,[],{narrow,[{0,12459}]}};
unicode_table(65399) ->
    {0,[],{narrow,[{0,12461}]}};
unicode_table(65400) ->
    {0,[],{narrow,[{0,12463}]}};
unicode_table(65401) ->
    {0,[],{narrow,[{0,12465}]}};
unicode_table(65402) ->
    {0,[],{narrow,[{0,12467}]}};
unicode_table(65403) ->
    {0,[],{narrow,[{0,12469}]}};
unicode_table(65404) ->
    {0,[],{narrow,[{0,12471}]}};
unicode_table(65405) ->
    {0,[],{narrow,[{0,12473}]}};
unicode_table(65406) ->
    {0,[],{narrow,[{0,12475}]}};
unicode_table(65407) ->
    {0,[],{narrow,[{0,12477}]}};
unicode_table(65408) ->
    {0,[],{narrow,[{0,12479}]}};
unicode_table(65409) ->
    {0,[],{narrow,[{0,12481}]}};
unicode_table(65410) ->
    {0,[],{narrow,[{0,12484}]}};
unicode_table(65411) ->
    {0,[],{narrow,[{0,12486}]}};
unicode_table(65412) ->
    {0,[],{narrow,[{0,12488}]}};
unicode_table(65413) ->
    {0,[],{narrow,[{0,12490}]}};
unicode_table(65414) ->
    {0,[],{narrow,[{0,12491}]}};
unicode_table(65415) ->
    {0,[],{narrow,[{0,12492}]}};
unicode_table(65416) ->
    {0,[],{narrow,[{0,12493}]}};
unicode_table(65417) ->
    {0,[],{narrow,[{0,12494}]}};
unicode_table(65418) ->
    {0,[],{narrow,[{0,12495}]}};
unicode_table(65419) ->
    {0,[],{narrow,[{0,12498}]}};
unicode_table(65420) ->
    {0,[],{narrow,[{0,12501}]}};
unicode_table(65421) ->
    {0,[],{narrow,[{0,12504}]}};
unicode_table(65422) ->
    {0,[],{narrow,[{0,12507}]}};
unicode_table(65423) ->
    {0,[],{narrow,[{0,12510}]}};
unicode_table(65424) ->
    {0,[],{narrow,[{0,12511}]}};
unicode_table(65425) ->
    {0,[],{narrow,[{0,12512}]}};
unicode_table(65426) ->
    {0,[],{narrow,[{0,12513}]}};
unicode_table(65427) ->
    {0,[],{narrow,[{0,12514}]}};
unicode_table(65428) ->
    {0,[],{narrow,[{0,12516}]}};
unicode_table(65429) ->
    {0,[],{narrow,[{0,12518}]}};
unicode_table(65430) ->
    {0,[],{narrow,[{0,12520}]}};
unicode_table(65431) ->
    {0,[],{narrow,[{0,12521}]}};
unicode_table(65432) ->
    {0,[],{narrow,[{0,12522}]}};
unicode_table(65433) ->
    {0,[],{narrow,[{0,12523}]}};
unicode_table(65434) ->
    {0,[],{narrow,[{0,12524}]}};
unicode_table(65435) ->
    {0,[],{narrow,[{0,12525}]}};
unicode_table(65436) ->
    {0,[],{narrow,[{0,12527}]}};
unicode_table(65437) ->
    {0,[],{narrow,[{0,12531}]}};
unicode_table(65438) ->
    {0,[],{narrow,[{8,12441}]}};
unicode_table(65439) ->
    {0,[],{narrow,[{8,12442}]}};
unicode_table(65440) ->
    {0,[],{narrow,[{0,4448}]}};
unicode_table(65441) ->
    {0,[],{narrow,[{0,4352}]}};
unicode_table(65442) ->
    {0,[],{narrow,[{0,4353}]}};
unicode_table(65443) ->
    {0,[],{narrow,[{0,4522}]}};
unicode_table(65444) ->
    {0,[],{narrow,[{0,4354}]}};
unicode_table(65445) ->
    {0,[],{narrow,[{0,4524}]}};
unicode_table(65446) ->
    {0,[],{narrow,[{0,4525}]}};
unicode_table(65447) ->
    {0,[],{narrow,[{0,4355}]}};
unicode_table(65448) ->
    {0,[],{narrow,[{0,4356}]}};
unicode_table(65449) ->
    {0,[],{narrow,[{0,4357}]}};
unicode_table(65450) ->
    {0,[],{narrow,[{0,4528}]}};
unicode_table(65451) ->
    {0,[],{narrow,[{0,4529}]}};
unicode_table(65452) ->
    {0,[],{narrow,[{0,4530}]}};
unicode_table(65453) ->
    {0,[],{narrow,[{0,4531}]}};
unicode_table(65454) ->
    {0,[],{narrow,[{0,4532}]}};
unicode_table(65455) ->
    {0,[],{narrow,[{0,4533}]}};
unicode_table(65456) ->
    {0,[],{narrow,[{0,4378}]}};
unicode_table(65457) ->
    {0,[],{narrow,[{0,4358}]}};
unicode_table(65458) ->
    {0,[],{narrow,[{0,4359}]}};
unicode_table(65459) ->
    {0,[],{narrow,[{0,4360}]}};
unicode_table(65460) ->
    {0,[],{narrow,[{0,4385}]}};
unicode_table(65461) ->
    {0,[],{narrow,[{0,4361}]}};
unicode_table(65462) ->
    {0,[],{narrow,[{0,4362}]}};
unicode_table(65463) ->
    {0,[],{narrow,[{0,4363}]}};
unicode_table(65464) ->
    {0,[],{narrow,[{0,4364}]}};
unicode_table(65465) ->
    {0,[],{narrow,[{0,4365}]}};
unicode_table(65466) ->
    {0,[],{narrow,[{0,4366}]}};
unicode_table(65467) ->
    {0,[],{narrow,[{0,4367}]}};
unicode_table(65468) ->
    {0,[],{narrow,[{0,4368}]}};
unicode_table(65469) ->
    {0,[],{narrow,[{0,4369}]}};
unicode_table(65470) ->
    {0,[],{narrow,[{0,4370}]}};
unicode_table(65474) ->
    {0,[],{narrow,[{0,4449}]}};
unicode_table(65475) ->
    {0,[],{narrow,[{0,4450}]}};
unicode_table(65476) ->
    {0,[],{narrow,[{0,4451}]}};
unicode_table(65477) ->
    {0,[],{narrow,[{0,4452}]}};
unicode_table(65478) ->
    {0,[],{narrow,[{0,4453}]}};
unicode_table(65479) ->
    {0,[],{narrow,[{0,4454}]}};
unicode_table(65482) ->
    {0,[],{narrow,[{0,4455}]}};
unicode_table(65483) ->
    {0,[],{narrow,[{0,4456}]}};
unicode_table(65484) ->
    {0,[],{narrow,[{0,4457}]}};
unicode_table(65485) ->
    {0,[],{narrow,[{0,4458}]}};
unicode_table(65486) ->
    {0,[],{narrow,[{0,4459}]}};
unicode_table(65487) ->
    {0,[],{narrow,[{0,4460}]}};
unicode_table(65490) ->
    {0,[],{narrow,[{0,4461}]}};
unicode_table(65491) ->
    {0,[],{narrow,[{0,4462}]}};
unicode_table(65492) ->
    {0,[],{narrow,[{0,4463}]}};
unicode_table(65493) ->
    {0,[],{narrow,[{0,4464}]}};
unicode_table(65494) ->
    {0,[],{narrow,[{0,4465}]}};
unicode_table(65495) ->
    {0,[],{narrow,[{0,4466}]}};
unicode_table(65498) ->
    {0,[],{narrow,[{0,4467}]}};
unicode_table(65499) ->
    {0,[],{narrow,[{0,4468}]}};
unicode_table(65500) ->
    {0,[],{narrow,[{0,4469}]}};
unicode_table(65504) ->
    {0,[],{wide,[{0,162}]}};
unicode_table(65505) ->
    {0,[],{wide,[{0,163}]}};
unicode_table(65506) ->
    {0,[],{wide,[{0,172}]}};
unicode_table(65507) ->
    {0,[],{wide,[{0,32}, {230,772}]}};
unicode_table(65508) ->
    {0,[],{wide,[{0,166}]}};
unicode_table(65509) ->
    {0,[],{wide,[{0,165}]}};
unicode_table(65510) ->
    {0,[],{wide,[{0,8361}]}};
unicode_table(65512) ->
    {0,[],{narrow,[{0,9474}]}};
unicode_table(65513) ->
    {0,[],{narrow,[{0,8592}]}};
unicode_table(65514) ->
    {0,[],{narrow,[{0,8593}]}};
unicode_table(65515) ->
    {0,[],{narrow,[{0,8594}]}};
unicode_table(65516) ->
    {0,[],{narrow,[{0,8595}]}};
unicode_table(65517) ->
    {0,[],{narrow,[{0,9632}]}};
unicode_table(65518) ->
    {0,[],{narrow,[{0,9675}]}};
unicode_table(66045) ->
    {220,[],[]};
unicode_table(66272) ->
    {220,[],[]};
unicode_table(66422) ->
    {230,[],[]};
unicode_table(66423) ->
    {230,[],[]};
unicode_table(66424) ->
    {230,[],[]};
unicode_table(66425) ->
    {230,[],[]};
unicode_table(66426) ->
    {230,[],[]};
unicode_table(68109) ->
    {220,[],[]};
unicode_table(68111) ->
    {230,[],[]};
unicode_table(68152) ->
    {230,[],[]};
unicode_table(68153) ->
    {1,[],[]};
unicode_table(68154) ->
    {220,[],[]};
unicode_table(68159) ->
    {9,[],[]};
unicode_table(68325) ->
    {230,[],[]};
unicode_table(68326) ->
    {220,[],[]};
unicode_table(68900) ->
    {230,[],[]};
unicode_table(68901) ->
    {230,[],[]};
unicode_table(68902) ->
    {230,[],[]};
unicode_table(68903) ->
    {230,[],[]};
unicode_table(69446) ->
    {220,[],[]};
unicode_table(69447) ->
    {220,[],[]};
unicode_table(69448) ->
    {230,[],[]};
unicode_table(69449) ->
    {230,[],[]};
unicode_table(69450) ->
    {230,[],[]};
unicode_table(69451) ->
    {220,[],[]};
unicode_table(69452) ->
    {230,[],[]};
unicode_table(69453) ->
    {220,[],[]};
unicode_table(69454) ->
    {220,[],[]};
unicode_table(69455) ->
    {220,[],[]};
unicode_table(69456) ->
    {220,[],[]};
unicode_table(69702) ->
    {9,[],[]};
unicode_table(69759) ->
    {9,[],[]};
unicode_table(69786) ->
    {0,[{0,69785}, {7,69818}],[]};
unicode_table(69788) ->
    {0,[{0,69787}, {7,69818}],[]};
unicode_table(69803) ->
    {0,[{0,69797}, {7,69818}],[]};
unicode_table(69817) ->
    {9,[],[]};
unicode_table(69818) ->
    {7,[],[]};
unicode_table(69888) ->
    {230,[],[]};
unicode_table(69889) ->
    {230,[],[]};
unicode_table(69890) ->
    {230,[],[]};
unicode_table(69934) ->
    {0,[{0,69937}, {0,69927}],[]};
unicode_table(69935) ->
    {0,[{0,69938}, {0,69927}],[]};
unicode_table(69939) ->
    {9,[],[]};
unicode_table(69940) ->
    {9,[],[]};
unicode_table(70003) ->
    {7,[],[]};
unicode_table(70080) ->
    {9,[],[]};
unicode_table(70090) ->
    {7,[],[]};
unicode_table(70197) ->
    {9,[],[]};
unicode_table(70198) ->
    {7,[],[]};
unicode_table(70377) ->
    {7,[],[]};
unicode_table(70378) ->
    {9,[],[]};
unicode_table(70459) ->
    {7,[],[]};
unicode_table(70460) ->
    {7,[],[]};
unicode_table(70475) ->
    {0,[{0,70471}, {0,70462}],[]};
unicode_table(70476) ->
    {0,[{0,70471}, {0,70487}],[]};
unicode_table(70477) ->
    {9,[],[]};
unicode_table(70502) ->
    {230,[],[]};
unicode_table(70503) ->
    {230,[],[]};
unicode_table(70504) ->
    {230,[],[]};
unicode_table(70505) ->
    {230,[],[]};
unicode_table(70506) ->
    {230,[],[]};
unicode_table(70507) ->
    {230,[],[]};
unicode_table(70508) ->
    {230,[],[]};
unicode_table(70512) ->
    {230,[],[]};
unicode_table(70513) ->
    {230,[],[]};
unicode_table(70514) ->
    {230,[],[]};
unicode_table(70515) ->
    {230,[],[]};
unicode_table(70516) ->
    {230,[],[]};
unicode_table(70722) ->
    {9,[],[]};
unicode_table(70726) ->
    {7,[],[]};
unicode_table(70750) ->
    {230,[],[]};
unicode_table(70843) ->
    {0,[{0,70841}, {0,70842}],[]};
unicode_table(70844) ->
    {0,[{0,70841}, {0,70832}],[]};
unicode_table(70846) ->
    {0,[{0,70841}, {0,70845}],[]};
unicode_table(70850) ->
    {9,[],[]};
unicode_table(70851) ->
    {7,[],[]};
unicode_table(71098) ->
    {0,[{0,71096}, {0,71087}],[]};
unicode_table(71099) ->
    {0,[{0,71097}, {0,71087}],[]};
unicode_table(71103) ->
    {9,[],[]};
unicode_table(71104) ->
    {7,[],[]};
unicode_table(71231) ->
    {9,[],[]};
unicode_table(71350) ->
    {9,[],[]};
unicode_table(71351) ->
    {7,[],[]};
unicode_table(71467) ->
    {9,[],[]};
unicode_table(71737) ->
    {9,[],[]};
unicode_table(71738) ->
    {7,[],[]};
unicode_table(72160) ->
    {9,[],[]};
unicode_table(72244) ->
    {9,[],[]};
unicode_table(72263) ->
    {9,[],[]};
unicode_table(72345) ->
    {9,[],[]};
unicode_table(72767) ->
    {9,[],[]};
unicode_table(73026) ->
    {7,[],[]};
unicode_table(73028) ->
    {9,[],[]};
unicode_table(73029) ->
    {9,[],[]};
unicode_table(73111) ->
    {9,[],[]};
unicode_table(92912) ->
    {1,[],[]};
unicode_table(92913) ->
    {1,[],[]};
unicode_table(92914) ->
    {1,[],[]};
unicode_table(92915) ->
    {1,[],[]};
unicode_table(92916) ->
    {1,[],[]};
unicode_table(92976) ->
    {230,[],[]};
unicode_table(92977) ->
    {230,[],[]};
unicode_table(92978) ->
    {230,[],[]};
unicode_table(92979) ->
    {230,[],[]};
unicode_table(92980) ->
    {230,[],[]};
unicode_table(92981) ->
    {230,[],[]};
unicode_table(92982) ->
    {230,[],[]};
unicode_table(113822) ->
    {1,[],[]};
unicode_table(119134) ->
    {0,[{0,119127}, {216,119141}],[]};
unicode_table(119135) ->
    {0,[{0,119128}, {216,119141}],[]};
unicode_table(119136) ->
    {0,[{0,119128}, {216,119141}, {216,119150}],[]};
unicode_table(119137) ->
    {0,[{0,119128}, {216,119141}, {216,119151}],[]};
unicode_table(119138) ->
    {0,[{0,119128}, {216,119141}, {216,119152}],[]};
unicode_table(119139) ->
    {0,[{0,119128}, {216,119141}, {216,119153}],[]};
unicode_table(119140) ->
    {0,[{0,119128}, {216,119141}, {216,119154}],[]};
unicode_table(119141) ->
    {216,[],[]};
unicode_table(119142) ->
    {216,[],[]};
unicode_table(119143) ->
    {1,[],[]};
unicode_table(119144) ->
    {1,[],[]};
unicode_table(119145) ->
    {1,[],[]};
unicode_table(119149) ->
    {226,[],[]};
unicode_table(119150) ->
    {216,[],[]};
unicode_table(119151) ->
    {216,[],[]};
unicode_table(119152) ->
    {216,[],[]};
unicode_table(119153) ->
    {216,[],[]};
unicode_table(119154) ->
    {216,[],[]};
unicode_table(119163) ->
    {220,[],[]};
unicode_table(119164) ->
    {220,[],[]};
unicode_table(119165) ->
    {220,[],[]};
unicode_table(119166) ->
    {220,[],[]};
unicode_table(119167) ->
    {220,[],[]};
unicode_table(119168) ->
    {220,[],[]};
unicode_table(119169) ->
    {220,[],[]};
unicode_table(119170) ->
    {220,[],[]};
unicode_table(119173) ->
    {230,[],[]};
unicode_table(119174) ->
    {230,[],[]};
unicode_table(119175) ->
    {230,[],[]};
unicode_table(119176) ->
    {230,[],[]};
unicode_table(119177) ->
    {230,[],[]};
unicode_table(119178) ->
    {220,[],[]};
unicode_table(119179) ->
    {220,[],[]};
unicode_table(119210) ->
    {230,[],[]};
unicode_table(119211) ->
    {230,[],[]};
unicode_table(119212) ->
    {230,[],[]};
unicode_table(119213) ->
    {230,[],[]};
unicode_table(119227) ->
    {0,[{0,119225}, {216,119141}],[]};
unicode_table(119228) ->
    {0,[{0,119226}, {216,119141}],[]};
unicode_table(119229) ->
    {0,[{0,119225}, {216,119141}, {216,119150}],[]};
unicode_table(119230) ->
    {0,[{0,119226}, {216,119141}, {216,119150}],[]};
unicode_table(119231) ->
    {0,[{0,119225}, {216,119141}, {216,119151}],[]};
unicode_table(119232) ->
    {0,[{0,119226}, {216,119141}, {216,119151}],[]};
unicode_table(119362) ->
    {230,[],[]};
unicode_table(119363) ->
    {230,[],[]};
unicode_table(119364) ->
    {230,[],[]};
unicode_table(119808) ->
    {0,[],{font,[{0,65}]}};
unicode_table(119809) ->
    {0,[],{font,[{0,66}]}};
unicode_table(119810) ->
    {0,[],{font,[{0,67}]}};
unicode_table(119811) ->
    {0,[],{font,[{0,68}]}};
unicode_table(119812) ->
    {0,[],{font,[{0,69}]}};
unicode_table(119813) ->
    {0,[],{font,[{0,70}]}};
unicode_table(119814) ->
    {0,[],{font,[{0,71}]}};
unicode_table(119815) ->
    {0,[],{font,[{0,72}]}};
unicode_table(119816) ->
    {0,[],{font,[{0,73}]}};
unicode_table(119817) ->
    {0,[],{font,[{0,74}]}};
unicode_table(119818) ->
    {0,[],{font,[{0,75}]}};
unicode_table(119819) ->
    {0,[],{font,[{0,76}]}};
unicode_table(119820) ->
    {0,[],{font,[{0,77}]}};
unicode_table(119821) ->
    {0,[],{font,[{0,78}]}};
unicode_table(119822) ->
    {0,[],{font,[{0,79}]}};
unicode_table(119823) ->
    {0,[],{font,[{0,80}]}};
unicode_table(119824) ->
    {0,[],{font,[{0,81}]}};
unicode_table(119825) ->
    {0,[],{font,[{0,82}]}};
unicode_table(119826) ->
    {0,[],{font,[{0,83}]}};
unicode_table(119827) ->
    {0,[],{font,[{0,84}]}};
unicode_table(119828) ->
    {0,[],{font,[{0,85}]}};
unicode_table(119829) ->
    {0,[],{font,[{0,86}]}};
unicode_table(119830) ->
    {0,[],{font,[{0,87}]}};
unicode_table(119831) ->
    {0,[],{font,[{0,88}]}};
unicode_table(119832) ->
    {0,[],{font,[{0,89}]}};
unicode_table(119833) ->
    {0,[],{font,[{0,90}]}};
unicode_table(119834) ->
    {0,[],{font,[{0,97}]}};
unicode_table(119835) ->
    {0,[],{font,[{0,98}]}};
unicode_table(119836) ->
    {0,[],{font,[{0,99}]}};
unicode_table(119837) ->
    {0,[],{font,[{0,100}]}};
unicode_table(119838) ->
    {0,[],{font,[{0,101}]}};
unicode_table(119839) ->
    {0,[],{font,[{0,102}]}};
unicode_table(119840) ->
    {0,[],{font,[{0,103}]}};
unicode_table(119841) ->
    {0,[],{font,[{0,104}]}};
unicode_table(119842) ->
    {0,[],{font,[{0,105}]}};
unicode_table(119843) ->
    {0,[],{font,[{0,106}]}};
unicode_table(119844) ->
    {0,[],{font,[{0,107}]}};
unicode_table(119845) ->
    {0,[],{font,[{0,108}]}};
unicode_table(119846) ->
    {0,[],{font,[{0,109}]}};
unicode_table(119847) ->
    {0,[],{font,[{0,110}]}};
unicode_table(119848) ->
    {0,[],{font,[{0,111}]}};
unicode_table(119849) ->
    {0,[],{font,[{0,112}]}};
unicode_table(119850) ->
    {0,[],{font,[{0,113}]}};
unicode_table(119851) ->
    {0,[],{font,[{0,114}]}};
unicode_table(119852) ->
    {0,[],{font,[{0,115}]}};
unicode_table(119853) ->
    {0,[],{font,[{0,116}]}};
unicode_table(119854) ->
    {0,[],{font,[{0,117}]}};
unicode_table(119855) ->
    {0,[],{font,[{0,118}]}};
unicode_table(119856) ->
    {0,[],{font,[{0,119}]}};
unicode_table(119857) ->
    {0,[],{font,[{0,120}]}};
unicode_table(119858) ->
    {0,[],{font,[{0,121}]}};
unicode_table(119859) ->
    {0,[],{font,[{0,122}]}};
unicode_table(119860) ->
    {0,[],{font,[{0,65}]}};
unicode_table(119861) ->
    {0,[],{font,[{0,66}]}};
unicode_table(119862) ->
    {0,[],{font,[{0,67}]}};
unicode_table(119863) ->
    {0,[],{font,[{0,68}]}};
unicode_table(119864) ->
    {0,[],{font,[{0,69}]}};
unicode_table(119865) ->
    {0,[],{font,[{0,70}]}};
unicode_table(119866) ->
    {0,[],{font,[{0,71}]}};
unicode_table(119867) ->
    {0,[],{font,[{0,72}]}};
unicode_table(119868) ->
    {0,[],{font,[{0,73}]}};
unicode_table(119869) ->
    {0,[],{font,[{0,74}]}};
unicode_table(119870) ->
    {0,[],{font,[{0,75}]}};
unicode_table(119871) ->
    {0,[],{font,[{0,76}]}};
unicode_table(119872) ->
    {0,[],{font,[{0,77}]}};
unicode_table(119873) ->
    {0,[],{font,[{0,78}]}};
unicode_table(119874) ->
    {0,[],{font,[{0,79}]}};
unicode_table(119875) ->
    {0,[],{font,[{0,80}]}};
unicode_table(119876) ->
    {0,[],{font,[{0,81}]}};
unicode_table(119877) ->
    {0,[],{font,[{0,82}]}};
unicode_table(119878) ->
    {0,[],{font,[{0,83}]}};
unicode_table(119879) ->
    {0,[],{font,[{0,84}]}};
unicode_table(119880) ->
    {0,[],{font,[{0,85}]}};
unicode_table(119881) ->
    {0,[],{font,[{0,86}]}};
unicode_table(119882) ->
    {0,[],{font,[{0,87}]}};
unicode_table(119883) ->
    {0,[],{font,[{0,88}]}};
unicode_table(119884) ->
    {0,[],{font,[{0,89}]}};
unicode_table(119885) ->
    {0,[],{font,[{0,90}]}};
unicode_table(119886) ->
    {0,[],{font,[{0,97}]}};
unicode_table(119887) ->
    {0,[],{font,[{0,98}]}};
unicode_table(119888) ->
    {0,[],{font,[{0,99}]}};
unicode_table(119889) ->
    {0,[],{font,[{0,100}]}};
unicode_table(119890) ->
    {0,[],{font,[{0,101}]}};
unicode_table(119891) ->
    {0,[],{font,[{0,102}]}};
unicode_table(119892) ->
    {0,[],{font,[{0,103}]}};
unicode_table(119894) ->
    {0,[],{font,[{0,105}]}};
unicode_table(119895) ->
    {0,[],{font,[{0,106}]}};
unicode_table(119896) ->
    {0,[],{font,[{0,107}]}};
unicode_table(119897) ->
    {0,[],{font,[{0,108}]}};
unicode_table(119898) ->
    {0,[],{font,[{0,109}]}};
unicode_table(119899) ->
    {0,[],{font,[{0,110}]}};
unicode_table(119900) ->
    {0,[],{font,[{0,111}]}};
unicode_table(119901) ->
    {0,[],{font,[{0,112}]}};
unicode_table(119902) ->
    {0,[],{font,[{0,113}]}};
unicode_table(119903) ->
    {0,[],{font,[{0,114}]}};
unicode_table(119904) ->
    {0,[],{font,[{0,115}]}};
unicode_table(119905) ->
    {0,[],{font,[{0,116}]}};
unicode_table(119906) ->
    {0,[],{font,[{0,117}]}};
unicode_table(119907) ->
    {0,[],{font,[{0,118}]}};
unicode_table(119908) ->
    {0,[],{font,[{0,119}]}};
unicode_table(119909) ->
    {0,[],{font,[{0,120}]}};
unicode_table(119910) ->
    {0,[],{font,[{0,121}]}};
unicode_table(119911) ->
    {0,[],{font,[{0,122}]}};
unicode_table(119912) ->
    {0,[],{font,[{0,65}]}};
unicode_table(119913) ->
    {0,[],{font,[{0,66}]}};
unicode_table(119914) ->
    {0,[],{font,[{0,67}]}};
unicode_table(119915) ->
    {0,[],{font,[{0,68}]}};
unicode_table(119916) ->
    {0,[],{font,[{0,69}]}};
unicode_table(119917) ->
    {0,[],{font,[{0,70}]}};
unicode_table(119918) ->
    {0,[],{font,[{0,71}]}};
unicode_table(119919) ->
    {0,[],{font,[{0,72}]}};
unicode_table(119920) ->
    {0,[],{font,[{0,73}]}};
unicode_table(119921) ->
    {0,[],{font,[{0,74}]}};
unicode_table(119922) ->
    {0,[],{font,[{0,75}]}};
unicode_table(119923) ->
    {0,[],{font,[{0,76}]}};
unicode_table(119924) ->
    {0,[],{font,[{0,77}]}};
unicode_table(119925) ->
    {0,[],{font,[{0,78}]}};
unicode_table(119926) ->
    {0,[],{font,[{0,79}]}};
unicode_table(119927) ->
    {0,[],{font,[{0,80}]}};
unicode_table(119928) ->
    {0,[],{font,[{0,81}]}};
unicode_table(119929) ->
    {0,[],{font,[{0,82}]}};
unicode_table(119930) ->
    {0,[],{font,[{0,83}]}};
unicode_table(119931) ->
    {0,[],{font,[{0,84}]}};
unicode_table(119932) ->
    {0,[],{font,[{0,85}]}};
unicode_table(119933) ->
    {0,[],{font,[{0,86}]}};
unicode_table(119934) ->
    {0,[],{font,[{0,87}]}};
unicode_table(119935) ->
    {0,[],{font,[{0,88}]}};
unicode_table(119936) ->
    {0,[],{font,[{0,89}]}};
unicode_table(119937) ->
    {0,[],{font,[{0,90}]}};
unicode_table(119938) ->
    {0,[],{font,[{0,97}]}};
unicode_table(119939) ->
    {0,[],{font,[{0,98}]}};
unicode_table(119940) ->
    {0,[],{font,[{0,99}]}};
unicode_table(119941) ->
    {0,[],{font,[{0,100}]}};
unicode_table(119942) ->
    {0,[],{font,[{0,101}]}};
unicode_table(119943) ->
    {0,[],{font,[{0,102}]}};
unicode_table(119944) ->
    {0,[],{font,[{0,103}]}};
unicode_table(119945) ->
    {0,[],{font,[{0,104}]}};
unicode_table(119946) ->
    {0,[],{font,[{0,105}]}};
unicode_table(119947) ->
    {0,[],{font,[{0,106}]}};
unicode_table(119948) ->
    {0,[],{font,[{0,107}]}};
unicode_table(119949) ->
    {0,[],{font,[{0,108}]}};
unicode_table(119950) ->
    {0,[],{font,[{0,109}]}};
unicode_table(119951) ->
    {0,[],{font,[{0,110}]}};
unicode_table(119952) ->
    {0,[],{font,[{0,111}]}};
unicode_table(119953) ->
    {0,[],{font,[{0,112}]}};
unicode_table(119954) ->
    {0,[],{font,[{0,113}]}};
unicode_table(119955) ->
    {0,[],{font,[{0,114}]}};
unicode_table(119956) ->
    {0,[],{font,[{0,115}]}};
unicode_table(119957) ->
    {0,[],{font,[{0,116}]}};
unicode_table(119958) ->
    {0,[],{font,[{0,117}]}};
unicode_table(119959) ->
    {0,[],{font,[{0,118}]}};
unicode_table(119960) ->
    {0,[],{font,[{0,119}]}};
unicode_table(119961) ->
    {0,[],{font,[{0,120}]}};
unicode_table(119962) ->
    {0,[],{font,[{0,121}]}};
unicode_table(119963) ->
    {0,[],{font,[{0,122}]}};
unicode_table(119964) ->
    {0,[],{font,[{0,65}]}};
unicode_table(119966) ->
    {0,[],{font,[{0,67}]}};
unicode_table(119967) ->
    {0,[],{font,[{0,68}]}};
unicode_table(119970) ->
    {0,[],{font,[{0,71}]}};
unicode_table(119973) ->
    {0,[],{font,[{0,74}]}};
unicode_table(119974) ->
    {0,[],{font,[{0,75}]}};
unicode_table(119977) ->
    {0,[],{font,[{0,78}]}};
unicode_table(119978) ->
    {0,[],{font,[{0,79}]}};
unicode_table(119979) ->
    {0,[],{font,[{0,80}]}};
unicode_table(119980) ->
    {0,[],{font,[{0,81}]}};
unicode_table(119982) ->
    {0,[],{font,[{0,83}]}};
unicode_table(119983) ->
    {0,[],{font,[{0,84}]}};
unicode_table(119984) ->
    {0,[],{font,[{0,85}]}};
unicode_table(119985) ->
    {0,[],{font,[{0,86}]}};
unicode_table(119986) ->
    {0,[],{font,[{0,87}]}};
unicode_table(119987) ->
    {0,[],{font,[{0,88}]}};
unicode_table(119988) ->
    {0,[],{font,[{0,89}]}};
unicode_table(119989) ->
    {0,[],{font,[{0,90}]}};
unicode_table(119990) ->
    {0,[],{font,[{0,97}]}};
unicode_table(119991) ->
    {0,[],{font,[{0,98}]}};
unicode_table(119992) ->
    {0,[],{font,[{0,99}]}};
unicode_table(119993) ->
    {0,[],{font,[{0,100}]}};
unicode_table(119995) ->
    {0,[],{font,[{0,102}]}};
unicode_table(119997) ->
    {0,[],{font,[{0,104}]}};
unicode_table(119998) ->
    {0,[],{font,[{0,105}]}};
unicode_table(119999) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120000) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120001) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120002) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120003) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120005) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120006) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120007) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120008) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120009) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120010) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120011) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120012) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120013) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120014) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120015) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120016) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120017) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120018) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120019) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120020) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120021) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120022) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120023) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120024) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120025) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120026) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120027) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120028) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120029) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120030) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120031) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120032) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120033) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120034) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120035) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120036) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120037) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120038) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120039) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120040) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120041) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120042) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120043) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120044) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120045) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120046) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120047) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120048) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120049) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120050) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120051) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120052) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120053) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120054) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120055) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120056) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120057) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120058) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120059) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120060) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120061) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120062) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120063) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120064) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120065) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120066) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120067) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120068) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120069) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120071) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120072) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120073) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120074) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120077) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120078) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120079) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120080) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120081) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120082) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120083) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120084) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120086) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120087) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120088) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120089) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120090) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120091) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120092) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120094) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120095) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120096) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120097) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120098) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120099) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120100) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120101) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120102) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120103) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120104) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120105) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120106) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120107) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120108) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120109) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120110) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120111) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120112) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120113) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120114) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120115) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120116) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120117) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120118) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120119) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120120) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120121) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120123) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120124) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120125) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120126) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120128) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120129) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120130) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120131) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120132) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120134) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120138) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120139) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120140) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120141) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120142) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120143) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120144) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120146) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120147) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120148) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120149) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120150) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120151) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120152) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120153) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120154) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120155) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120156) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120157) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120158) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120159) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120160) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120161) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120162) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120163) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120164) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120165) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120166) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120167) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120168) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120169) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120170) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120171) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120172) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120173) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120174) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120175) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120176) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120177) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120178) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120179) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120180) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120181) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120182) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120183) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120184) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120185) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120186) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120187) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120188) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120189) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120190) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120191) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120192) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120193) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120194) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120195) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120196) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120197) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120198) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120199) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120200) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120201) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120202) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120203) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120204) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120205) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120206) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120207) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120208) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120209) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120210) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120211) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120212) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120213) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120214) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120215) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120216) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120217) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120218) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120219) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120220) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120221) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120222) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120223) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120224) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120225) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120226) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120227) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120228) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120229) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120230) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120231) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120232) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120233) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120234) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120235) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120236) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120237) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120238) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120239) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120240) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120241) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120242) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120243) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120244) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120245) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120246) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120247) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120248) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120249) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120250) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120251) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120252) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120253) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120254) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120255) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120256) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120257) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120258) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120259) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120260) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120261) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120262) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120263) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120264) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120265) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120266) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120267) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120268) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120269) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120270) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120271) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120272) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120273) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120274) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120275) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120276) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120277) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120278) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120279) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120280) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120281) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120282) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120283) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120284) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120285) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120286) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120287) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120288) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120289) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120290) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120291) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120292) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120293) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120294) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120295) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120296) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120297) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120298) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120299) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120300) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120301) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120302) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120303) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120304) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120305) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120306) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120307) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120308) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120309) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120310) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120311) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120312) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120313) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120314) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120315) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120316) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120317) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120318) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120319) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120320) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120321) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120322) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120323) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120324) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120325) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120326) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120327) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120328) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120329) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120330) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120331) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120332) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120333) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120334) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120335) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120336) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120337) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120338) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120339) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120340) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120341) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120342) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120343) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120344) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120345) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120346) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120347) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120348) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120349) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120350) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120351) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120352) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120353) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120354) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120355) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120356) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120357) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120358) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120359) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120360) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120361) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120362) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120363) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120364) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120365) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120366) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120367) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120368) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120369) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120370) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120371) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120372) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120373) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120374) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120375) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120376) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120377) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120378) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120379) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120380) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120381) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120382) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120383) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120384) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120385) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120386) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120387) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120388) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120389) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120390) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120391) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120392) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120393) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120394) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120395) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120396) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120397) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120398) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120399) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120400) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120401) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120402) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120403) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120404) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120405) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120406) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120407) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120408) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120409) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120410) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120411) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120412) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120413) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120414) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120415) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120416) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120417) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120418) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120419) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120420) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120421) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120422) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120423) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120424) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120425) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120426) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120427) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120428) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120429) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120430) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120431) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120432) ->
    {0,[],{font,[{0,65}]}};
unicode_table(120433) ->
    {0,[],{font,[{0,66}]}};
unicode_table(120434) ->
    {0,[],{font,[{0,67}]}};
unicode_table(120435) ->
    {0,[],{font,[{0,68}]}};
unicode_table(120436) ->
    {0,[],{font,[{0,69}]}};
unicode_table(120437) ->
    {0,[],{font,[{0,70}]}};
unicode_table(120438) ->
    {0,[],{font,[{0,71}]}};
unicode_table(120439) ->
    {0,[],{font,[{0,72}]}};
unicode_table(120440) ->
    {0,[],{font,[{0,73}]}};
unicode_table(120441) ->
    {0,[],{font,[{0,74}]}};
unicode_table(120442) ->
    {0,[],{font,[{0,75}]}};
unicode_table(120443) ->
    {0,[],{font,[{0,76}]}};
unicode_table(120444) ->
    {0,[],{font,[{0,77}]}};
unicode_table(120445) ->
    {0,[],{font,[{0,78}]}};
unicode_table(120446) ->
    {0,[],{font,[{0,79}]}};
unicode_table(120447) ->
    {0,[],{font,[{0,80}]}};
unicode_table(120448) ->
    {0,[],{font,[{0,81}]}};
unicode_table(120449) ->
    {0,[],{font,[{0,82}]}};
unicode_table(120450) ->
    {0,[],{font,[{0,83}]}};
unicode_table(120451) ->
    {0,[],{font,[{0,84}]}};
unicode_table(120452) ->
    {0,[],{font,[{0,85}]}};
unicode_table(120453) ->
    {0,[],{font,[{0,86}]}};
unicode_table(120454) ->
    {0,[],{font,[{0,87}]}};
unicode_table(120455) ->
    {0,[],{font,[{0,88}]}};
unicode_table(120456) ->
    {0,[],{font,[{0,89}]}};
unicode_table(120457) ->
    {0,[],{font,[{0,90}]}};
unicode_table(120458) ->
    {0,[],{font,[{0,97}]}};
unicode_table(120459) ->
    {0,[],{font,[{0,98}]}};
unicode_table(120460) ->
    {0,[],{font,[{0,99}]}};
unicode_table(120461) ->
    {0,[],{font,[{0,100}]}};
unicode_table(120462) ->
    {0,[],{font,[{0,101}]}};
unicode_table(120463) ->
    {0,[],{font,[{0,102}]}};
unicode_table(120464) ->
    {0,[],{font,[{0,103}]}};
unicode_table(120465) ->
    {0,[],{font,[{0,104}]}};
unicode_table(120466) ->
    {0,[],{font,[{0,105}]}};
unicode_table(120467) ->
    {0,[],{font,[{0,106}]}};
unicode_table(120468) ->
    {0,[],{font,[{0,107}]}};
unicode_table(120469) ->
    {0,[],{font,[{0,108}]}};
unicode_table(120470) ->
    {0,[],{font,[{0,109}]}};
unicode_table(120471) ->
    {0,[],{font,[{0,110}]}};
unicode_table(120472) ->
    {0,[],{font,[{0,111}]}};
unicode_table(120473) ->
    {0,[],{font,[{0,112}]}};
unicode_table(120474) ->
    {0,[],{font,[{0,113}]}};
unicode_table(120475) ->
    {0,[],{font,[{0,114}]}};
unicode_table(120476) ->
    {0,[],{font,[{0,115}]}};
unicode_table(120477) ->
    {0,[],{font,[{0,116}]}};
unicode_table(120478) ->
    {0,[],{font,[{0,117}]}};
unicode_table(120479) ->
    {0,[],{font,[{0,118}]}};
unicode_table(120480) ->
    {0,[],{font,[{0,119}]}};
unicode_table(120481) ->
    {0,[],{font,[{0,120}]}};
unicode_table(120482) ->
    {0,[],{font,[{0,121}]}};
unicode_table(120483) ->
    {0,[],{font,[{0,122}]}};
unicode_table(120484) ->
    {0,[],{font,[{0,305}]}};
unicode_table(120485) ->
    {0,[],{font,[{0,567}]}};
unicode_table(120488) ->
    {0,[],{font,[{0,913}]}};
unicode_table(120489) ->
    {0,[],{font,[{0,914}]}};
unicode_table(120490) ->
    {0,[],{font,[{0,915}]}};
unicode_table(120491) ->
    {0,[],{font,[{0,916}]}};
unicode_table(120492) ->
    {0,[],{font,[{0,917}]}};
unicode_table(120493) ->
    {0,[],{font,[{0,918}]}};
unicode_table(120494) ->
    {0,[],{font,[{0,919}]}};
unicode_table(120495) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120496) ->
    {0,[],{font,[{0,921}]}};
unicode_table(120497) ->
    {0,[],{font,[{0,922}]}};
unicode_table(120498) ->
    {0,[],{font,[{0,923}]}};
unicode_table(120499) ->
    {0,[],{font,[{0,924}]}};
unicode_table(120500) ->
    {0,[],{font,[{0,925}]}};
unicode_table(120501) ->
    {0,[],{font,[{0,926}]}};
unicode_table(120502) ->
    {0,[],{font,[{0,927}]}};
unicode_table(120503) ->
    {0,[],{font,[{0,928}]}};
unicode_table(120504) ->
    {0,[],{font,[{0,929}]}};
unicode_table(120505) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120506) ->
    {0,[],{font,[{0,931}]}};
unicode_table(120507) ->
    {0,[],{font,[{0,932}]}};
unicode_table(120508) ->
    {0,[],{font,[{0,933}]}};
unicode_table(120509) ->
    {0,[],{font,[{0,934}]}};
unicode_table(120510) ->
    {0,[],{font,[{0,935}]}};
unicode_table(120511) ->
    {0,[],{font,[{0,936}]}};
unicode_table(120512) ->
    {0,[],{font,[{0,937}]}};
unicode_table(120513) ->
    {0,[],{font,[{0,8711}]}};
unicode_table(120514) ->
    {0,[],{font,[{0,945}]}};
unicode_table(120515) ->
    {0,[],{font,[{0,946}]}};
unicode_table(120516) ->
    {0,[],{font,[{0,947}]}};
unicode_table(120517) ->
    {0,[],{font,[{0,948}]}};
unicode_table(120518) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120519) ->
    {0,[],{font,[{0,950}]}};
unicode_table(120520) ->
    {0,[],{font,[{0,951}]}};
unicode_table(120521) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120522) ->
    {0,[],{font,[{0,953}]}};
unicode_table(120523) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120524) ->
    {0,[],{font,[{0,955}]}};
unicode_table(120525) ->
    {0,[],{font,[{0,956}]}};
unicode_table(120526) ->
    {0,[],{font,[{0,957}]}};
unicode_table(120527) ->
    {0,[],{font,[{0,958}]}};
unicode_table(120528) ->
    {0,[],{font,[{0,959}]}};
unicode_table(120529) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120530) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120531) ->
    {0,[],{font,[{0,962}]}};
unicode_table(120532) ->
    {0,[],{font,[{0,963}]}};
unicode_table(120533) ->
    {0,[],{font,[{0,964}]}};
unicode_table(120534) ->
    {0,[],{font,[{0,965}]}};
unicode_table(120535) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120536) ->
    {0,[],{font,[{0,967}]}};
unicode_table(120537) ->
    {0,[],{font,[{0,968}]}};
unicode_table(120538) ->
    {0,[],{font,[{0,969}]}};
unicode_table(120539) ->
    {0,[],{font,[{0,8706}]}};
unicode_table(120540) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120541) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120542) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120543) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120544) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120545) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120546) ->
    {0,[],{font,[{0,913}]}};
unicode_table(120547) ->
    {0,[],{font,[{0,914}]}};
unicode_table(120548) ->
    {0,[],{font,[{0,915}]}};
unicode_table(120549) ->
    {0,[],{font,[{0,916}]}};
unicode_table(120550) ->
    {0,[],{font,[{0,917}]}};
unicode_table(120551) ->
    {0,[],{font,[{0,918}]}};
unicode_table(120552) ->
    {0,[],{font,[{0,919}]}};
unicode_table(120553) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120554) ->
    {0,[],{font,[{0,921}]}};
unicode_table(120555) ->
    {0,[],{font,[{0,922}]}};
unicode_table(120556) ->
    {0,[],{font,[{0,923}]}};
unicode_table(120557) ->
    {0,[],{font,[{0,924}]}};
unicode_table(120558) ->
    {0,[],{font,[{0,925}]}};
unicode_table(120559) ->
    {0,[],{font,[{0,926}]}};
unicode_table(120560) ->
    {0,[],{font,[{0,927}]}};
unicode_table(120561) ->
    {0,[],{font,[{0,928}]}};
unicode_table(120562) ->
    {0,[],{font,[{0,929}]}};
unicode_table(120563) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120564) ->
    {0,[],{font,[{0,931}]}};
unicode_table(120565) ->
    {0,[],{font,[{0,932}]}};
unicode_table(120566) ->
    {0,[],{font,[{0,933}]}};
unicode_table(120567) ->
    {0,[],{font,[{0,934}]}};
unicode_table(120568) ->
    {0,[],{font,[{0,935}]}};
unicode_table(120569) ->
    {0,[],{font,[{0,936}]}};
unicode_table(120570) ->
    {0,[],{font,[{0,937}]}};
unicode_table(120571) ->
    {0,[],{font,[{0,8711}]}};
unicode_table(120572) ->
    {0,[],{font,[{0,945}]}};
unicode_table(120573) ->
    {0,[],{font,[{0,946}]}};
unicode_table(120574) ->
    {0,[],{font,[{0,947}]}};
unicode_table(120575) ->
    {0,[],{font,[{0,948}]}};
unicode_table(120576) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120577) ->
    {0,[],{font,[{0,950}]}};
unicode_table(120578) ->
    {0,[],{font,[{0,951}]}};
unicode_table(120579) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120580) ->
    {0,[],{font,[{0,953}]}};
unicode_table(120581) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120582) ->
    {0,[],{font,[{0,955}]}};
unicode_table(120583) ->
    {0,[],{font,[{0,956}]}};
unicode_table(120584) ->
    {0,[],{font,[{0,957}]}};
unicode_table(120585) ->
    {0,[],{font,[{0,958}]}};
unicode_table(120586) ->
    {0,[],{font,[{0,959}]}};
unicode_table(120587) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120588) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120589) ->
    {0,[],{font,[{0,962}]}};
unicode_table(120590) ->
    {0,[],{font,[{0,963}]}};
unicode_table(120591) ->
    {0,[],{font,[{0,964}]}};
unicode_table(120592) ->
    {0,[],{font,[{0,965}]}};
unicode_table(120593) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120594) ->
    {0,[],{font,[{0,967}]}};
unicode_table(120595) ->
    {0,[],{font,[{0,968}]}};
unicode_table(120596) ->
    {0,[],{font,[{0,969}]}};
unicode_table(120597) ->
    {0,[],{font,[{0,8706}]}};
unicode_table(120598) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120599) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120600) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120601) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120602) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120603) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120604) ->
    {0,[],{font,[{0,913}]}};
unicode_table(120605) ->
    {0,[],{font,[{0,914}]}};
unicode_table(120606) ->
    {0,[],{font,[{0,915}]}};
unicode_table(120607) ->
    {0,[],{font,[{0,916}]}};
unicode_table(120608) ->
    {0,[],{font,[{0,917}]}};
unicode_table(120609) ->
    {0,[],{font,[{0,918}]}};
unicode_table(120610) ->
    {0,[],{font,[{0,919}]}};
unicode_table(120611) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120612) ->
    {0,[],{font,[{0,921}]}};
unicode_table(120613) ->
    {0,[],{font,[{0,922}]}};
unicode_table(120614) ->
    {0,[],{font,[{0,923}]}};
unicode_table(120615) ->
    {0,[],{font,[{0,924}]}};
unicode_table(120616) ->
    {0,[],{font,[{0,925}]}};
unicode_table(120617) ->
    {0,[],{font,[{0,926}]}};
unicode_table(120618) ->
    {0,[],{font,[{0,927}]}};
unicode_table(120619) ->
    {0,[],{font,[{0,928}]}};
unicode_table(120620) ->
    {0,[],{font,[{0,929}]}};
unicode_table(120621) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120622) ->
    {0,[],{font,[{0,931}]}};
unicode_table(120623) ->
    {0,[],{font,[{0,932}]}};
unicode_table(120624) ->
    {0,[],{font,[{0,933}]}};
unicode_table(120625) ->
    {0,[],{font,[{0,934}]}};
unicode_table(120626) ->
    {0,[],{font,[{0,935}]}};
unicode_table(120627) ->
    {0,[],{font,[{0,936}]}};
unicode_table(120628) ->
    {0,[],{font,[{0,937}]}};
unicode_table(120629) ->
    {0,[],{font,[{0,8711}]}};
unicode_table(120630) ->
    {0,[],{font,[{0,945}]}};
unicode_table(120631) ->
    {0,[],{font,[{0,946}]}};
unicode_table(120632) ->
    {0,[],{font,[{0,947}]}};
unicode_table(120633) ->
    {0,[],{font,[{0,948}]}};
unicode_table(120634) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120635) ->
    {0,[],{font,[{0,950}]}};
unicode_table(120636) ->
    {0,[],{font,[{0,951}]}};
unicode_table(120637) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120638) ->
    {0,[],{font,[{0,953}]}};
unicode_table(120639) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120640) ->
    {0,[],{font,[{0,955}]}};
unicode_table(120641) ->
    {0,[],{font,[{0,956}]}};
unicode_table(120642) ->
    {0,[],{font,[{0,957}]}};
unicode_table(120643) ->
    {0,[],{font,[{0,958}]}};
unicode_table(120644) ->
    {0,[],{font,[{0,959}]}};
unicode_table(120645) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120646) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120647) ->
    {0,[],{font,[{0,962}]}};
unicode_table(120648) ->
    {0,[],{font,[{0,963}]}};
unicode_table(120649) ->
    {0,[],{font,[{0,964}]}};
unicode_table(120650) ->
    {0,[],{font,[{0,965}]}};
unicode_table(120651) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120652) ->
    {0,[],{font,[{0,967}]}};
unicode_table(120653) ->
    {0,[],{font,[{0,968}]}};
unicode_table(120654) ->
    {0,[],{font,[{0,969}]}};
unicode_table(120655) ->
    {0,[],{font,[{0,8706}]}};
unicode_table(120656) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120657) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120658) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120659) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120660) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120661) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120662) ->
    {0,[],{font,[{0,913}]}};
unicode_table(120663) ->
    {0,[],{font,[{0,914}]}};
unicode_table(120664) ->
    {0,[],{font,[{0,915}]}};
unicode_table(120665) ->
    {0,[],{font,[{0,916}]}};
unicode_table(120666) ->
    {0,[],{font,[{0,917}]}};
unicode_table(120667) ->
    {0,[],{font,[{0,918}]}};
unicode_table(120668) ->
    {0,[],{font,[{0,919}]}};
unicode_table(120669) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120670) ->
    {0,[],{font,[{0,921}]}};
unicode_table(120671) ->
    {0,[],{font,[{0,922}]}};
unicode_table(120672) ->
    {0,[],{font,[{0,923}]}};
unicode_table(120673) ->
    {0,[],{font,[{0,924}]}};
unicode_table(120674) ->
    {0,[],{font,[{0,925}]}};
unicode_table(120675) ->
    {0,[],{font,[{0,926}]}};
unicode_table(120676) ->
    {0,[],{font,[{0,927}]}};
unicode_table(120677) ->
    {0,[],{font,[{0,928}]}};
unicode_table(120678) ->
    {0,[],{font,[{0,929}]}};
unicode_table(120679) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120680) ->
    {0,[],{font,[{0,931}]}};
unicode_table(120681) ->
    {0,[],{font,[{0,932}]}};
unicode_table(120682) ->
    {0,[],{font,[{0,933}]}};
unicode_table(120683) ->
    {0,[],{font,[{0,934}]}};
unicode_table(120684) ->
    {0,[],{font,[{0,935}]}};
unicode_table(120685) ->
    {0,[],{font,[{0,936}]}};
unicode_table(120686) ->
    {0,[],{font,[{0,937}]}};
unicode_table(120687) ->
    {0,[],{font,[{0,8711}]}};
unicode_table(120688) ->
    {0,[],{font,[{0,945}]}};
unicode_table(120689) ->
    {0,[],{font,[{0,946}]}};
unicode_table(120690) ->
    {0,[],{font,[{0,947}]}};
unicode_table(120691) ->
    {0,[],{font,[{0,948}]}};
unicode_table(120692) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120693) ->
    {0,[],{font,[{0,950}]}};
unicode_table(120694) ->
    {0,[],{font,[{0,951}]}};
unicode_table(120695) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120696) ->
    {0,[],{font,[{0,953}]}};
unicode_table(120697) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120698) ->
    {0,[],{font,[{0,955}]}};
unicode_table(120699) ->
    {0,[],{font,[{0,956}]}};
unicode_table(120700) ->
    {0,[],{font,[{0,957}]}};
unicode_table(120701) ->
    {0,[],{font,[{0,958}]}};
unicode_table(120702) ->
    {0,[],{font,[{0,959}]}};
unicode_table(120703) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120704) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120705) ->
    {0,[],{font,[{0,962}]}};
unicode_table(120706) ->
    {0,[],{font,[{0,963}]}};
unicode_table(120707) ->
    {0,[],{font,[{0,964}]}};
unicode_table(120708) ->
    {0,[],{font,[{0,965}]}};
unicode_table(120709) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120710) ->
    {0,[],{font,[{0,967}]}};
unicode_table(120711) ->
    {0,[],{font,[{0,968}]}};
unicode_table(120712) ->
    {0,[],{font,[{0,969}]}};
unicode_table(120713) ->
    {0,[],{font,[{0,8706}]}};
unicode_table(120714) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120715) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120716) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120717) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120718) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120719) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120720) ->
    {0,[],{font,[{0,913}]}};
unicode_table(120721) ->
    {0,[],{font,[{0,914}]}};
unicode_table(120722) ->
    {0,[],{font,[{0,915}]}};
unicode_table(120723) ->
    {0,[],{font,[{0,916}]}};
unicode_table(120724) ->
    {0,[],{font,[{0,917}]}};
unicode_table(120725) ->
    {0,[],{font,[{0,918}]}};
unicode_table(120726) ->
    {0,[],{font,[{0,919}]}};
unicode_table(120727) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120728) ->
    {0,[],{font,[{0,921}]}};
unicode_table(120729) ->
    {0,[],{font,[{0,922}]}};
unicode_table(120730) ->
    {0,[],{font,[{0,923}]}};
unicode_table(120731) ->
    {0,[],{font,[{0,924}]}};
unicode_table(120732) ->
    {0,[],{font,[{0,925}]}};
unicode_table(120733) ->
    {0,[],{font,[{0,926}]}};
unicode_table(120734) ->
    {0,[],{font,[{0,927}]}};
unicode_table(120735) ->
    {0,[],{font,[{0,928}]}};
unicode_table(120736) ->
    {0,[],{font,[{0,929}]}};
unicode_table(120737) ->
    {0,[],{font,[{0,920}]}};
unicode_table(120738) ->
    {0,[],{font,[{0,931}]}};
unicode_table(120739) ->
    {0,[],{font,[{0,932}]}};
unicode_table(120740) ->
    {0,[],{font,[{0,933}]}};
unicode_table(120741) ->
    {0,[],{font,[{0,934}]}};
unicode_table(120742) ->
    {0,[],{font,[{0,935}]}};
unicode_table(120743) ->
    {0,[],{font,[{0,936}]}};
unicode_table(120744) ->
    {0,[],{font,[{0,937}]}};
unicode_table(120745) ->
    {0,[],{font,[{0,8711}]}};
unicode_table(120746) ->
    {0,[],{font,[{0,945}]}};
unicode_table(120747) ->
    {0,[],{font,[{0,946}]}};
unicode_table(120748) ->
    {0,[],{font,[{0,947}]}};
unicode_table(120749) ->
    {0,[],{font,[{0,948}]}};
unicode_table(120750) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120751) ->
    {0,[],{font,[{0,950}]}};
unicode_table(120752) ->
    {0,[],{font,[{0,951}]}};
unicode_table(120753) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120754) ->
    {0,[],{font,[{0,953}]}};
unicode_table(120755) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120756) ->
    {0,[],{font,[{0,955}]}};
unicode_table(120757) ->
    {0,[],{font,[{0,956}]}};
unicode_table(120758) ->
    {0,[],{font,[{0,957}]}};
unicode_table(120759) ->
    {0,[],{font,[{0,958}]}};
unicode_table(120760) ->
    {0,[],{font,[{0,959}]}};
unicode_table(120761) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120762) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120763) ->
    {0,[],{font,[{0,962}]}};
unicode_table(120764) ->
    {0,[],{font,[{0,963}]}};
unicode_table(120765) ->
    {0,[],{font,[{0,964}]}};
unicode_table(120766) ->
    {0,[],{font,[{0,965}]}};
unicode_table(120767) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120768) ->
    {0,[],{font,[{0,967}]}};
unicode_table(120769) ->
    {0,[],{font,[{0,968}]}};
unicode_table(120770) ->
    {0,[],{font,[{0,969}]}};
unicode_table(120771) ->
    {0,[],{font,[{0,8706}]}};
unicode_table(120772) ->
    {0,[],{font,[{0,949}]}};
unicode_table(120773) ->
    {0,[],{font,[{0,952}]}};
unicode_table(120774) ->
    {0,[],{font,[{0,954}]}};
unicode_table(120775) ->
    {0,[],{font,[{0,966}]}};
unicode_table(120776) ->
    {0,[],{font,[{0,961}]}};
unicode_table(120777) ->
    {0,[],{font,[{0,960}]}};
unicode_table(120778) ->
    {0,[],{font,[{0,988}]}};
unicode_table(120779) ->
    {0,[],{font,[{0,989}]}};
unicode_table(120782) ->
    {0,[],{font,[{0,48}]}};
unicode_table(120783) ->
    {0,[],{font,[{0,49}]}};
unicode_table(120784) ->
    {0,[],{font,[{0,50}]}};
unicode_table(120785) ->
    {0,[],{font,[{0,51}]}};
unicode_table(120786) ->
    {0,[],{font,[{0,52}]}};
unicode_table(120787) ->
    {0,[],{font,[{0,53}]}};
unicode_table(120788) ->
    {0,[],{font,[{0,54}]}};
unicode_table(120789) ->
    {0,[],{font,[{0,55}]}};
unicode_table(120790) ->
    {0,[],{font,[{0,56}]}};
unicode_table(120791) ->
    {0,[],{font,[{0,57}]}};
unicode_table(120792) ->
    {0,[],{font,[{0,48}]}};
unicode_table(120793) ->
    {0,[],{font,[{0,49}]}};
unicode_table(120794) ->
    {0,[],{font,[{0,50}]}};
unicode_table(120795) ->
    {0,[],{font,[{0,51}]}};
unicode_table(120796) ->
    {0,[],{font,[{0,52}]}};
unicode_table(120797) ->
    {0,[],{font,[{0,53}]}};
unicode_table(120798) ->
    {0,[],{font,[{0,54}]}};
unicode_table(120799) ->
    {0,[],{font,[{0,55}]}};
unicode_table(120800) ->
    {0,[],{font,[{0,56}]}};
unicode_table(120801) ->
    {0,[],{font,[{0,57}]}};
unicode_table(120802) ->
    {0,[],{font,[{0,48}]}};
unicode_table(120803) ->
    {0,[],{font,[{0,49}]}};
unicode_table(120804) ->
    {0,[],{font,[{0,50}]}};
unicode_table(120805) ->
    {0,[],{font,[{0,51}]}};
unicode_table(120806) ->
    {0,[],{font,[{0,52}]}};
unicode_table(120807) ->
    {0,[],{font,[{0,53}]}};
unicode_table(120808) ->
    {0,[],{font,[{0,54}]}};
unicode_table(120809) ->
    {0,[],{font,[{0,55}]}};
unicode_table(120810) ->
    {0,[],{font,[{0,56}]}};
unicode_table(120811) ->
    {0,[],{font,[{0,57}]}};
unicode_table(120812) ->
    {0,[],{font,[{0,48}]}};
unicode_table(120813) ->
    {0,[],{font,[{0,49}]}};
unicode_table(120814) ->
    {0,[],{font,[{0,50}]}};
unicode_table(120815) ->
    {0,[],{font,[{0,51}]}};
unicode_table(120816) ->
    {0,[],{font,[{0,52}]}};
unicode_table(120817) ->
    {0,[],{font,[{0,53}]}};
unicode_table(120818) ->
    {0,[],{font,[{0,54}]}};
unicode_table(120819) ->
    {0,[],{font,[{0,55}]}};
unicode_table(120820) ->
    {0,[],{font,[{0,56}]}};
unicode_table(120821) ->
    {0,[],{font,[{0,57}]}};
unicode_table(120822) ->
    {0,[],{font,[{0,48}]}};
unicode_table(120823) ->
    {0,[],{font,[{0,49}]}};
unicode_table(120824) ->
    {0,[],{font,[{0,50}]}};
unicode_table(120825) ->
    {0,[],{font,[{0,51}]}};
unicode_table(120826) ->
    {0,[],{font,[{0,52}]}};
unicode_table(120827) ->
    {0,[],{font,[{0,53}]}};
unicode_table(120828) ->
    {0,[],{font,[{0,54}]}};
unicode_table(120829) ->
    {0,[],{font,[{0,55}]}};
unicode_table(120830) ->
    {0,[],{font,[{0,56}]}};
unicode_table(120831) ->
    {0,[],{font,[{0,57}]}};
unicode_table(122880) ->
    {230,[],[]};
unicode_table(122881) ->
    {230,[],[]};
unicode_table(122882) ->
    {230,[],[]};
unicode_table(122883) ->
    {230,[],[]};
unicode_table(122884) ->
    {230,[],[]};
unicode_table(122885) ->
    {230,[],[]};
unicode_table(122886) ->
    {230,[],[]};
unicode_table(122888) ->
    {230,[],[]};
unicode_table(122889) ->
    {230,[],[]};
unicode_table(122890) ->
    {230,[],[]};
unicode_table(122891) ->
    {230,[],[]};
unicode_table(122892) ->
    {230,[],[]};
unicode_table(122893) ->
    {230,[],[]};
unicode_table(122894) ->
    {230,[],[]};
unicode_table(122895) ->
    {230,[],[]};
unicode_table(122896) ->
    {230,[],[]};
unicode_table(122897) ->
    {230,[],[]};
unicode_table(122898) ->
    {230,[],[]};
unicode_table(122899) ->
    {230,[],[]};
unicode_table(122900) ->
    {230,[],[]};
unicode_table(122901) ->
    {230,[],[]};
unicode_table(122902) ->
    {230,[],[]};
unicode_table(122903) ->
    {230,[],[]};
unicode_table(122904) ->
    {230,[],[]};
unicode_table(122907) ->
    {230,[],[]};
unicode_table(122908) ->
    {230,[],[]};
unicode_table(122909) ->
    {230,[],[]};
unicode_table(122910) ->
    {230,[],[]};
unicode_table(122911) ->
    {230,[],[]};
unicode_table(122912) ->
    {230,[],[]};
unicode_table(122913) ->
    {230,[],[]};
unicode_table(122915) ->
    {230,[],[]};
unicode_table(122916) ->
    {230,[],[]};
unicode_table(122918) ->
    {230,[],[]};
unicode_table(122919) ->
    {230,[],[]};
unicode_table(122920) ->
    {230,[],[]};
unicode_table(122921) ->
    {230,[],[]};
unicode_table(122922) ->
    {230,[],[]};
unicode_table(123184) ->
    {230,[],[]};
unicode_table(123185) ->
    {230,[],[]};
unicode_table(123186) ->
    {230,[],[]};
unicode_table(123187) ->
    {230,[],[]};
unicode_table(123188) ->
    {230,[],[]};
unicode_table(123189) ->
    {230,[],[]};
unicode_table(123190) ->
    {230,[],[]};
unicode_table(123628) ->
    {230,[],[]};
unicode_table(123629) ->
    {230,[],[]};
unicode_table(123630) ->
    {230,[],[]};
unicode_table(123631) ->
    {230,[],[]};
unicode_table(125136) ->
    {220,[],[]};
unicode_table(125137) ->
    {220,[],[]};
unicode_table(125138) ->
    {220,[],[]};
unicode_table(125139) ->
    {220,[],[]};
unicode_table(125140) ->
    {220,[],[]};
unicode_table(125141) ->
    {220,[],[]};
unicode_table(125142) ->
    {220,[],[]};
unicode_table(125252) ->
    {230,[],[]};
unicode_table(125253) ->
    {230,[],[]};
unicode_table(125254) ->
    {230,[],[]};
unicode_table(125255) ->
    {230,[],[]};
unicode_table(125256) ->
    {230,[],[]};
unicode_table(125257) ->
    {230,[],[]};
unicode_table(125258) ->
    {7,[],[]};
unicode_table(126464) ->
    {0,[],{font,[{0,1575}]}};
unicode_table(126465) ->
    {0,[],{font,[{0,1576}]}};
unicode_table(126466) ->
    {0,[],{font,[{0,1580}]}};
unicode_table(126467) ->
    {0,[],{font,[{0,1583}]}};
unicode_table(126469) ->
    {0,[],{font,[{0,1608}]}};
unicode_table(126470) ->
    {0,[],{font,[{0,1586}]}};
unicode_table(126471) ->
    {0,[],{font,[{0,1581}]}};
unicode_table(126472) ->
    {0,[],{font,[{0,1591}]}};
unicode_table(126473) ->
    {0,[],{font,[{0,1610}]}};
unicode_table(126474) ->
    {0,[],{font,[{0,1603}]}};
unicode_table(126475) ->
    {0,[],{font,[{0,1604}]}};
unicode_table(126476) ->
    {0,[],{font,[{0,1605}]}};
unicode_table(126477) ->
    {0,[],{font,[{0,1606}]}};
unicode_table(126478) ->
    {0,[],{font,[{0,1587}]}};
unicode_table(126479) ->
    {0,[],{font,[{0,1593}]}};
unicode_table(126480) ->
    {0,[],{font,[{0,1601}]}};
unicode_table(126481) ->
    {0,[],{font,[{0,1589}]}};
unicode_table(126482) ->
    {0,[],{font,[{0,1602}]}};
unicode_table(126483) ->
    {0,[],{font,[{0,1585}]}};
unicode_table(126484) ->
    {0,[],{font,[{0,1588}]}};
unicode_table(126485) ->
    {0,[],{font,[{0,1578}]}};
unicode_table(126486) ->
    {0,[],{font,[{0,1579}]}};
unicode_table(126487) ->
    {0,[],{font,[{0,1582}]}};
unicode_table(126488) ->
    {0,[],{font,[{0,1584}]}};
unicode_table(126489) ->
    {0,[],{font,[{0,1590}]}};
unicode_table(126490) ->
    {0,[],{font,[{0,1592}]}};
unicode_table(126491) ->
    {0,[],{font,[{0,1594}]}};
unicode_table(126492) ->
    {0,[],{font,[{0,1646}]}};
unicode_table(126493) ->
    {0,[],{font,[{0,1722}]}};
unicode_table(126494) ->
    {0,[],{font,[{0,1697}]}};
unicode_table(126495) ->
    {0,[],{font,[{0,1647}]}};
unicode_table(126497) ->
    {0,[],{font,[{0,1576}]}};
unicode_table(126498) ->
    {0,[],{font,[{0,1580}]}};
unicode_table(126500) ->
    {0,[],{font,[{0,1607}]}};
unicode_table(126503) ->
    {0,[],{font,[{0,1581}]}};
unicode_table(126505) ->
    {0,[],{font,[{0,1610}]}};
unicode_table(126506) ->
    {0,[],{font,[{0,1603}]}};
unicode_table(126507) ->
    {0,[],{font,[{0,1604}]}};
unicode_table(126508) ->
    {0,[],{font,[{0,1605}]}};
unicode_table(126509) ->
    {0,[],{font,[{0,1606}]}};
unicode_table(126510) ->
    {0,[],{font,[{0,1587}]}};
unicode_table(126511) ->
    {0,[],{font,[{0,1593}]}};
unicode_table(126512) ->
    {0,[],{font,[{0,1601}]}};
unicode_table(126513) ->
    {0,[],{font,[{0,1589}]}};
unicode_table(126514) ->
    {0,[],{font,[{0,1602}]}};
unicode_table(126516) ->
    {0,[],{font,[{0,1588}]}};
unicode_table(126517) ->
    {0,[],{font,[{0,1578}]}};
unicode_table(126518) ->
    {0,[],{font,[{0,1579}]}};
unicode_table(126519) ->
    {0,[],{font,[{0,1582}]}};
unicode_table(126521) ->
    {0,[],{font,[{0,1590}]}};
unicode_table(126523) ->
    {0,[],{font,[{0,1594}]}};
unicode_table(126530) ->
    {0,[],{font,[{0,1580}]}};
unicode_table(126535) ->
    {0,[],{font,[{0,1581}]}};
unicode_table(126537) ->
    {0,[],{font,[{0,1610}]}};
unicode_table(126539) ->
    {0,[],{font,[{0,1604}]}};
unicode_table(126541) ->
    {0,[],{font,[{0,1606}]}};
unicode_table(126542) ->
    {0,[],{font,[{0,1587}]}};
unicode_table(126543) ->
    {0,[],{font,[{0,1593}]}};
unicode_table(126545) ->
    {0,[],{font,[{0,1589}]}};
unicode_table(126546) ->
    {0,[],{font,[{0,1602}]}};
unicode_table(126548) ->
    {0,[],{font,[{0,1588}]}};
unicode_table(126551) ->
    {0,[],{font,[{0,1582}]}};
unicode_table(126553) ->
    {0,[],{font,[{0,1590}]}};
unicode_table(126555) ->
    {0,[],{font,[{0,1594}]}};
unicode_table(126557) ->
    {0,[],{font,[{0,1722}]}};
unicode_table(126559) ->
    {0,[],{font,[{0,1647}]}};
unicode_table(126561) ->
    {0,[],{font,[{0,1576}]}};
unicode_table(126562) ->
    {0,[],{font,[{0,1580}]}};
unicode_table(126564) ->
    {0,[],{font,[{0,1607}]}};
unicode_table(126567) ->
    {0,[],{font,[{0,1581}]}};
unicode_table(126568) ->
    {0,[],{font,[{0,1591}]}};
unicode_table(126569) ->
    {0,[],{font,[{0,1610}]}};
unicode_table(126570) ->
    {0,[],{font,[{0,1603}]}};
unicode_table(126572) ->
    {0,[],{font,[{0,1605}]}};
unicode_table(126573) ->
    {0,[],{font,[{0,1606}]}};
unicode_table(126574) ->
    {0,[],{font,[{0,1587}]}};
unicode_table(126575) ->
    {0,[],{font,[{0,1593}]}};
unicode_table(126576) ->
    {0,[],{font,[{0,1601}]}};
unicode_table(126577) ->
    {0,[],{font,[{0,1589}]}};
unicode_table(126578) ->
    {0,[],{font,[{0,1602}]}};
unicode_table(126580) ->
    {0,[],{font,[{0,1588}]}};
unicode_table(126581) ->
    {0,[],{font,[{0,1578}]}};
unicode_table(126582) ->
    {0,[],{font,[{0,1579}]}};
unicode_table(126583) ->
    {0,[],{font,[{0,1582}]}};
unicode_table(126585) ->
    {0,[],{font,[{0,1590}]}};
unicode_table(126586) ->
    {0,[],{font,[{0,1592}]}};
unicode_table(126587) ->
    {0,[],{font,[{0,1594}]}};
unicode_table(126588) ->
    {0,[],{font,[{0,1646}]}};
unicode_table(126590) ->
    {0,[],{font,[{0,1697}]}};
unicode_table(126592) ->
    {0,[],{font,[{0,1575}]}};
unicode_table(126593) ->
    {0,[],{font,[{0,1576}]}};
unicode_table(126594) ->
    {0,[],{font,[{0,1580}]}};
unicode_table(126595) ->
    {0,[],{font,[{0,1583}]}};
unicode_table(126596) ->
    {0,[],{font,[{0,1607}]}};
unicode_table(126597) ->
    {0,[],{font,[{0,1608}]}};
unicode_table(126598) ->
    {0,[],{font,[{0,1586}]}};
unicode_table(126599) ->
    {0,[],{font,[{0,1581}]}};
unicode_table(126600) ->
    {0,[],{font,[{0,1591}]}};
unicode_table(126601) ->
    {0,[],{font,[{0,1610}]}};
unicode_table(126603) ->
    {0,[],{font,[{0,1604}]}};
unicode_table(126604) ->
    {0,[],{font,[{0,1605}]}};
unicode_table(126605) ->
    {0,[],{font,[{0,1606}]}};
unicode_table(126606) ->
    {0,[],{font,[{0,1587}]}};
unicode_table(126607) ->
    {0,[],{font,[{0,1593}]}};
unicode_table(126608) ->
    {0,[],{font,[{0,1601}]}};
unicode_table(126609) ->
    {0,[],{font,[{0,1589}]}};
unicode_table(126610) ->
    {0,[],{font,[{0,1602}]}};
unicode_table(126611) ->
    {0,[],{font,[{0,1585}]}};
unicode_table(126612) ->
    {0,[],{font,[{0,1588}]}};
unicode_table(126613) ->
    {0,[],{font,[{0,1578}]}};
unicode_table(126614) ->
    {0,[],{font,[{0,1579}]}};
unicode_table(126615) ->
    {0,[],{font,[{0,1582}]}};
unicode_table(126616) ->
    {0,[],{font,[{0,1584}]}};
unicode_table(126617) ->
    {0,[],{font,[{0,1590}]}};
unicode_table(126618) ->
    {0,[],{font,[{0,1592}]}};
unicode_table(126619) ->
    {0,[],{font,[{0,1594}]}};
unicode_table(126625) ->
    {0,[],{font,[{0,1576}]}};
unicode_table(126626) ->
    {0,[],{font,[{0,1580}]}};
unicode_table(126627) ->
    {0,[],{font,[{0,1583}]}};
unicode_table(126629) ->
    {0,[],{font,[{0,1608}]}};
unicode_table(126630) ->
    {0,[],{font,[{0,1586}]}};
unicode_table(126631) ->
    {0,[],{font,[{0,1581}]}};
unicode_table(126632) ->
    {0,[],{font,[{0,1591}]}};
unicode_table(126633) ->
    {0,[],{font,[{0,1610}]}};
unicode_table(126635) ->
    {0,[],{font,[{0,1604}]}};
unicode_table(126636) ->
    {0,[],{font,[{0,1605}]}};
unicode_table(126637) ->
    {0,[],{font,[{0,1606}]}};
unicode_table(126638) ->
    {0,[],{font,[{0,1587}]}};
unicode_table(126639) ->
    {0,[],{font,[{0,1593}]}};
unicode_table(126640) ->
    {0,[],{font,[{0,1601}]}};
unicode_table(126641) ->
    {0,[],{font,[{0,1589}]}};
unicode_table(126642) ->
    {0,[],{font,[{0,1602}]}};
unicode_table(126643) ->
    {0,[],{font,[{0,1585}]}};
unicode_table(126644) ->
    {0,[],{font,[{0,1588}]}};
unicode_table(126645) ->
    {0,[],{font,[{0,1578}]}};
unicode_table(126646) ->
    {0,[],{font,[{0,1579}]}};
unicode_table(126647) ->
    {0,[],{font,[{0,1582}]}};
unicode_table(126648) ->
    {0,[],{font,[{0,1584}]}};
unicode_table(126649) ->
    {0,[],{font,[{0,1590}]}};
unicode_table(126650) ->
    {0,[],{font,[{0,1592}]}};
unicode_table(126651) ->
    {0,[],{font,[{0,1594}]}};
unicode_table(127232) ->
    {0,[],{compat,[{0,48}, {0,46}]}};
unicode_table(127233) ->
    {0,[],{compat,[{0,48}, {0,44}]}};
unicode_table(127234) ->
    {0,[],{compat,[{0,49}, {0,44}]}};
unicode_table(127235) ->
    {0,[],{compat,[{0,50}, {0,44}]}};
unicode_table(127236) ->
    {0,[],{compat,[{0,51}, {0,44}]}};
unicode_table(127237) ->
    {0,[],{compat,[{0,52}, {0,44}]}};
unicode_table(127238) ->
    {0,[],{compat,[{0,53}, {0,44}]}};
unicode_table(127239) ->
    {0,[],{compat,[{0,54}, {0,44}]}};
unicode_table(127240) ->
    {0,[],{compat,[{0,55}, {0,44}]}};
unicode_table(127241) ->
    {0,[],{compat,[{0,56}, {0,44}]}};
unicode_table(127242) ->
    {0,[],{compat,[{0,57}, {0,44}]}};
unicode_table(127248) ->
    {0,[],{compat,[{0,40}, {0,65}, {0,41}]}};
unicode_table(127249) ->
    {0,[],{compat,[{0,40}, {0,66}, {0,41}]}};
unicode_table(127250) ->
    {0,[],{compat,[{0,40}, {0,67}, {0,41}]}};
unicode_table(127251) ->
    {0,[],{compat,[{0,40}, {0,68}, {0,41}]}};
unicode_table(127252) ->
    {0,[],{compat,[{0,40}, {0,69}, {0,41}]}};
unicode_table(127253) ->
    {0,[],{compat,[{0,40}, {0,70}, {0,41}]}};
unicode_table(127254) ->
    {0,[],{compat,[{0,40}, {0,71}, {0,41}]}};
unicode_table(127255) ->
    {0,[],{compat,[{0,40}, {0,72}, {0,41}]}};
unicode_table(127256) ->
    {0,[],{compat,[{0,40}, {0,73}, {0,41}]}};
unicode_table(127257) ->
    {0,[],{compat,[{0,40}, {0,74}, {0,41}]}};
unicode_table(127258) ->
    {0,[],{compat,[{0,40}, {0,75}, {0,41}]}};
unicode_table(127259) ->
    {0,[],{compat,[{0,40}, {0,76}, {0,41}]}};
unicode_table(127260) ->
    {0,[],{compat,[{0,40}, {0,77}, {0,41}]}};
unicode_table(127261) ->
    {0,[],{compat,[{0,40}, {0,78}, {0,41}]}};
unicode_table(127262) ->
    {0,[],{compat,[{0,40}, {0,79}, {0,41}]}};
unicode_table(127263) ->
    {0,[],{compat,[{0,40}, {0,80}, {0,41}]}};
unicode_table(127264) ->
    {0,[],{compat,[{0,40}, {0,81}, {0,41}]}};
unicode_table(127265) ->
    {0,[],{compat,[{0,40}, {0,82}, {0,41}]}};
unicode_table(127266) ->
    {0,[],{compat,[{0,40}, {0,83}, {0,41}]}};
unicode_table(127267) ->
    {0,[],{compat,[{0,40}, {0,84}, {0,41}]}};
unicode_table(127268) ->
    {0,[],{compat,[{0,40}, {0,85}, {0,41}]}};
unicode_table(127269) ->
    {0,[],{compat,[{0,40}, {0,86}, {0,41}]}};
unicode_table(127270) ->
    {0,[],{compat,[{0,40}, {0,87}, {0,41}]}};
unicode_table(127271) ->
    {0,[],{compat,[{0,40}, {0,88}, {0,41}]}};
unicode_table(127272) ->
    {0,[],{compat,[{0,40}, {0,89}, {0,41}]}};
unicode_table(127273) ->
    {0,[],{compat,[{0,40}, {0,90}, {0,41}]}};
unicode_table(127274) ->
    {0,[],{compat,[{0,12308}, {0,83}, {0,12309}]}};
unicode_table(127275) ->
    {0,[],{circle,[{0,67}]}};
unicode_table(127276) ->
    {0,[],{circle,[{0,82}]}};
unicode_table(127277) ->
    {0,[],{circle,[{0,67}, {0,68}]}};
unicode_table(127278) ->
    {0,[],{circle,[{0,87}, {0,90}]}};
unicode_table(127280) ->
    {0,[],{square,[{0,65}]}};
unicode_table(127281) ->
    {0,[],{square,[{0,66}]}};
unicode_table(127282) ->
    {0,[],{square,[{0,67}]}};
unicode_table(127283) ->
    {0,[],{square,[{0,68}]}};
unicode_table(127284) ->
    {0,[],{square,[{0,69}]}};
unicode_table(127285) ->
    {0,[],{square,[{0,70}]}};
unicode_table(127286) ->
    {0,[],{square,[{0,71}]}};
unicode_table(127287) ->
    {0,[],{square,[{0,72}]}};
unicode_table(127288) ->
    {0,[],{square,[{0,73}]}};
unicode_table(127289) ->
    {0,[],{square,[{0,74}]}};
unicode_table(127290) ->
    {0,[],{square,[{0,75}]}};
unicode_table(127291) ->
    {0,[],{square,[{0,76}]}};
unicode_table(127292) ->
    {0,[],{square,[{0,77}]}};
unicode_table(127293) ->
    {0,[],{square,[{0,78}]}};
unicode_table(127294) ->
    {0,[],{square,[{0,79}]}};
unicode_table(127295) ->
    {0,[],{square,[{0,80}]}};
unicode_table(127296) ->
    {0,[],{square,[{0,81}]}};
unicode_table(127297) ->
    {0,[],{square,[{0,82}]}};
unicode_table(127298) ->
    {0,[],{square,[{0,83}]}};
unicode_table(127299) ->
    {0,[],{square,[{0,84}]}};
unicode_table(127300) ->
    {0,[],{square,[{0,85}]}};
unicode_table(127301) ->
    {0,[],{square,[{0,86}]}};
unicode_table(127302) ->
    {0,[],{square,[{0,87}]}};
unicode_table(127303) ->
    {0,[],{square,[{0,88}]}};
unicode_table(127304) ->
    {0,[],{square,[{0,89}]}};
unicode_table(127305) ->
    {0,[],{square,[{0,90}]}};
unicode_table(127306) ->
    {0,[],{square,[{0,72}, {0,86}]}};
unicode_table(127307) ->
    {0,[],{square,[{0,77}, {0,86}]}};
unicode_table(127308) ->
    {0,[],{square,[{0,83}, {0,68}]}};
unicode_table(127309) ->
    {0,[],{square,[{0,83}, {0,83}]}};
unicode_table(127310) ->
    {0,[],{square,[{0,80}, {0,80}, {0,86}]}};
unicode_table(127311) ->
    {0,[],{square,[{0,87}, {0,67}]}};
unicode_table(127338) ->
    {0,[],{super,[{0,77}, {0,67}]}};
unicode_table(127339) ->
    {0,[],{super,[{0,77}, {0,68}]}};
unicode_table(127340) ->
    {0,[],{super,[{0,77}, {0,82}]}};
unicode_table(127376) ->
    {0,[],{square,[{0,68}, {0,74}]}};
unicode_table(127488) ->
    {0,[],{square,[{0,12411}, {0,12363}]}};
unicode_table(127489) ->
    {0,[],{square,[{0,12467}, {0,12467}]}};
unicode_table(127490) ->
    {0,[],{square,[{0,12469}]}};
unicode_table(127504) ->
    {0,[],{square,[{0,25163}]}};
unicode_table(127505) ->
    {0,[],{square,[{0,23383}]}};
unicode_table(127506) ->
    {0,[],{square,[{0,21452}]}};
unicode_table(127507) ->
    {0,[],{square,[{0,12486}, {8,12441}]}};
unicode_table(127508) ->
    {0,[],{square,[{0,20108}]}};
unicode_table(127509) ->
    {0,[],{square,[{0,22810}]}};
unicode_table(127510) ->
    {0,[],{square,[{0,35299}]}};
unicode_table(127511) ->
    {0,[],{square,[{0,22825}]}};
unicode_table(127512) ->
    {0,[],{square,[{0,20132}]}};
unicode_table(127513) ->
    {0,[],{square,[{0,26144}]}};
unicode_table(127514) ->
    {0,[],{square,[{0,28961}]}};
unicode_table(127515) ->
    {0,[],{square,[{0,26009}]}};
unicode_table(127516) ->
    {0,[],{square,[{0,21069}]}};
unicode_table(127517) ->
    {0,[],{square,[{0,24460}]}};
unicode_table(127518) ->
    {0,[],{square,[{0,20877}]}};
unicode_table(127519) ->
    {0,[],{square,[{0,26032}]}};
unicode_table(127520) ->
    {0,[],{square,[{0,21021}]}};
unicode_table(127521) ->
    {0,[],{square,[{0,32066}]}};
unicode_table(127522) ->
    {0,[],{square,[{0,29983}]}};
unicode_table(127523) ->
    {0,[],{square,[{0,36009}]}};
unicode_table(127524) ->
    {0,[],{square,[{0,22768}]}};
unicode_table(127525) ->
    {0,[],{square,[{0,21561}]}};
unicode_table(127526) ->
    {0,[],{square,[{0,28436}]}};
unicode_table(127527) ->
    {0,[],{square,[{0,25237}]}};
unicode_table(127528) ->
    {0,[],{square,[{0,25429}]}};
unicode_table(127529) ->
    {0,[],{square,[{0,19968}]}};
unicode_table(127530) ->
    {0,[],{square,[{0,19977}]}};
unicode_table(127531) ->
    {0,[],{square,[{0,36938}]}};
unicode_table(127532) ->
    {0,[],{square,[{0,24038}]}};
unicode_table(127533) ->
    {0,[],{square,[{0,20013}]}};
unicode_table(127534) ->
    {0,[],{square,[{0,21491}]}};
unicode_table(127535) ->
    {0,[],{square,[{0,25351}]}};
unicode_table(127536) ->
    {0,[],{square,[{0,36208}]}};
unicode_table(127537) ->
    {0,[],{square,[{0,25171}]}};
unicode_table(127538) ->
    {0,[],{square,[{0,31105}]}};
unicode_table(127539) ->
    {0,[],{square,[{0,31354}]}};
unicode_table(127540) ->
    {0,[],{square,[{0,21512}]}};
unicode_table(127541) ->
    {0,[],{square,[{0,28288}]}};
unicode_table(127542) ->
    {0,[],{square,[{0,26377}]}};
unicode_table(127543) ->
    {0,[],{square,[{0,26376}]}};
unicode_table(127544) ->
    {0,[],{square,[{0,30003}]}};
unicode_table(127545) ->
    {0,[],{square,[{0,21106}]}};
unicode_table(127546) ->
    {0,[],{square,[{0,21942}]}};
unicode_table(127547) ->
    {0,[],{square,[{0,37197}]}};
unicode_table(127552) ->
    {0,[],{compat,[{0,12308}, {0,26412}, {0,12309}]}};
unicode_table(127553) ->
    {0,[],{compat,[{0,12308}, {0,19977}, {0,12309}]}};
unicode_table(127554) ->
    {0,[],{compat,[{0,12308}, {0,20108}, {0,12309}]}};
unicode_table(127555) ->
    {0,[],{compat,[{0,12308}, {0,23433}, {0,12309}]}};
unicode_table(127556) ->
    {0,[],{compat,[{0,12308}, {0,28857}, {0,12309}]}};
unicode_table(127557) ->
    {0,[],{compat,[{0,12308}, {0,25171}, {0,12309}]}};
unicode_table(127558) ->
    {0,[],{compat,[{0,12308}, {0,30423}, {0,12309}]}};
unicode_table(127559) ->
    {0,[],{compat,[{0,12308}, {0,21213}, {0,12309}]}};
unicode_table(127560) ->
    {0,[],{compat,[{0,12308}, {0,25943}, {0,12309}]}};
unicode_table(127568) ->
    {0,[],{circle,[{0,24471}]}};
unicode_table(127569) ->
    {0,[],{circle,[{0,21487}]}};
unicode_table(194560) ->
    {0,[{0,20029}],[]};
unicode_table(194561) ->
    {0,[{0,20024}],[]};
unicode_table(194562) ->
    {0,[{0,20033}],[]};
unicode_table(194563) ->
    {0,[{0,131362}],[]};
unicode_table(194564) ->
    {0,[{0,20320}],[]};
unicode_table(194565) ->
    {0,[{0,20398}],[]};
unicode_table(194566) ->
    {0,[{0,20411}],[]};
unicode_table(194567) ->
    {0,[{0,20482}],[]};
unicode_table(194568) ->
    {0,[{0,20602}],[]};
unicode_table(194569) ->
    {0,[{0,20633}],[]};
unicode_table(194570) ->
    {0,[{0,20711}],[]};
unicode_table(194571) ->
    {0,[{0,20687}],[]};
unicode_table(194572) ->
    {0,[{0,13470}],[]};
unicode_table(194573) ->
    {0,[{0,132666}],[]};
unicode_table(194574) ->
    {0,[{0,20813}],[]};
unicode_table(194575) ->
    {0,[{0,20820}],[]};
unicode_table(194576) ->
    {0,[{0,20836}],[]};
unicode_table(194577) ->
    {0,[{0,20855}],[]};
unicode_table(194578) ->
    {0,[{0,132380}],[]};
unicode_table(194579) ->
    {0,[{0,13497}],[]};
unicode_table(194580) ->
    {0,[{0,20839}],[]};
unicode_table(194581) ->
    {0,[{0,20877}],[]};
unicode_table(194582) ->
    {0,[{0,132427}],[]};
unicode_table(194583) ->
    {0,[{0,20887}],[]};
unicode_table(194584) ->
    {0,[{0,20900}],[]};
unicode_table(194585) ->
    {0,[{0,20172}],[]};
unicode_table(194586) ->
    {0,[{0,20908}],[]};
unicode_table(194587) ->
    {0,[{0,20917}],[]};
unicode_table(194588) ->
    {0,[{0,168415}],[]};
unicode_table(194589) ->
    {0,[{0,20981}],[]};
unicode_table(194590) ->
    {0,[{0,20995}],[]};
unicode_table(194591) ->
    {0,[{0,13535}],[]};
unicode_table(194592) ->
    {0,[{0,21051}],[]};
unicode_table(194593) ->
    {0,[{0,21062}],[]};
unicode_table(194594) ->
    {0,[{0,21106}],[]};
unicode_table(194595) ->
    {0,[{0,21111}],[]};
unicode_table(194596) ->
    {0,[{0,13589}],[]};
unicode_table(194597) ->
    {0,[{0,21191}],[]};
unicode_table(194598) ->
    {0,[{0,21193}],[]};
unicode_table(194599) ->
    {0,[{0,21220}],[]};
unicode_table(194600) ->
    {0,[{0,21242}],[]};
unicode_table(194601) ->
    {0,[{0,21253}],[]};
unicode_table(194602) ->
    {0,[{0,21254}],[]};
unicode_table(194603) ->
    {0,[{0,21271}],[]};
unicode_table(194604) ->
    {0,[{0,21321}],[]};
unicode_table(194605) ->
    {0,[{0,21329}],[]};
unicode_table(194606) ->
    {0,[{0,21338}],[]};
unicode_table(194607) ->
    {0,[{0,21363}],[]};
unicode_table(194608) ->
    {0,[{0,21373}],[]};
unicode_table(194609) ->
    {0,[{0,21375}],[]};
unicode_table(194610) ->
    {0,[{0,21375}],[]};
unicode_table(194611) ->
    {0,[{0,21375}],[]};
unicode_table(194612) ->
    {0,[{0,133676}],[]};
unicode_table(194613) ->
    {0,[{0,28784}],[]};
unicode_table(194614) ->
    {0,[{0,21450}],[]};
unicode_table(194615) ->
    {0,[{0,21471}],[]};
unicode_table(194616) ->
    {0,[{0,133987}],[]};
unicode_table(194617) ->
    {0,[{0,21483}],[]};
unicode_table(194618) ->
    {0,[{0,21489}],[]};
unicode_table(194619) ->
    {0,[{0,21510}],[]};
unicode_table(194620) ->
    {0,[{0,21662}],[]};
unicode_table(194621) ->
    {0,[{0,21560}],[]};
unicode_table(194622) ->
    {0,[{0,21576}],[]};
unicode_table(194623) ->
    {0,[{0,21608}],[]};
unicode_table(194624) ->
    {0,[{0,21666}],[]};
unicode_table(194625) ->
    {0,[{0,21750}],[]};
unicode_table(194626) ->
    {0,[{0,21776}],[]};
unicode_table(194627) ->
    {0,[{0,21843}],[]};
unicode_table(194628) ->
    {0,[{0,21859}],[]};
unicode_table(194629) ->
    {0,[{0,21892}],[]};
unicode_table(194630) ->
    {0,[{0,21892}],[]};
unicode_table(194631) ->
    {0,[{0,21913}],[]};
unicode_table(194632) ->
    {0,[{0,21931}],[]};
unicode_table(194633) ->
    {0,[{0,21939}],[]};
unicode_table(194634) ->
    {0,[{0,21954}],[]};
unicode_table(194635) ->
    {0,[{0,22294}],[]};
unicode_table(194636) ->
    {0,[{0,22022}],[]};
unicode_table(194637) ->
    {0,[{0,22295}],[]};
unicode_table(194638) ->
    {0,[{0,22097}],[]};
unicode_table(194639) ->
    {0,[{0,22132}],[]};
unicode_table(194640) ->
    {0,[{0,20999}],[]};
unicode_table(194641) ->
    {0,[{0,22766}],[]};
unicode_table(194642) ->
    {0,[{0,22478}],[]};
unicode_table(194643) ->
    {0,[{0,22516}],[]};
unicode_table(194644) ->
    {0,[{0,22541}],[]};
unicode_table(194645) ->
    {0,[{0,22411}],[]};
unicode_table(194646) ->
    {0,[{0,22578}],[]};
unicode_table(194647) ->
    {0,[{0,22577}],[]};
unicode_table(194648) ->
    {0,[{0,22700}],[]};
unicode_table(194649) ->
    {0,[{0,136420}],[]};
unicode_table(194650) ->
    {0,[{0,22770}],[]};
unicode_table(194651) ->
    {0,[{0,22775}],[]};
unicode_table(194652) ->
    {0,[{0,22790}],[]};
unicode_table(194653) ->
    {0,[{0,22810}],[]};
unicode_table(194654) ->
    {0,[{0,22818}],[]};
unicode_table(194655) ->
    {0,[{0,22882}],[]};
unicode_table(194656) ->
    {0,[{0,136872}],[]};
unicode_table(194657) ->
    {0,[{0,136938}],[]};
unicode_table(194658) ->
    {0,[{0,23020}],[]};
unicode_table(194659) ->
    {0,[{0,23067}],[]};
unicode_table(194660) ->
    {0,[{0,23079}],[]};
unicode_table(194661) ->
    {0,[{0,23000}],[]};
unicode_table(194662) ->
    {0,[{0,23142}],[]};
unicode_table(194663) ->
    {0,[{0,14062}],[]};
unicode_table(194664) ->
    {0,[{0,14076}],[]};
unicode_table(194665) ->
    {0,[{0,23304}],[]};
unicode_table(194666) ->
    {0,[{0,23358}],[]};
unicode_table(194667) ->
    {0,[{0,23358}],[]};
unicode_table(194668) ->
    {0,[{0,137672}],[]};
unicode_table(194669) ->
    {0,[{0,23491}],[]};
unicode_table(194670) ->
    {0,[{0,23512}],[]};
unicode_table(194671) ->
    {0,[{0,23527}],[]};
unicode_table(194672) ->
    {0,[{0,23539}],[]};
unicode_table(194673) ->
    {0,[{0,138008}],[]};
unicode_table(194674) ->
    {0,[{0,23551}],[]};
unicode_table(194675) ->
    {0,[{0,23558}],[]};
unicode_table(194676) ->
    {0,[{0,24403}],[]};
unicode_table(194677) ->
    {0,[{0,23586}],[]};
unicode_table(194678) ->
    {0,[{0,14209}],[]};
unicode_table(194679) ->
    {0,[{0,23648}],[]};
unicode_table(194680) ->
    {0,[{0,23662}],[]};
unicode_table(194681) ->
    {0,[{0,23744}],[]};
unicode_table(194682) ->
    {0,[{0,23693}],[]};
unicode_table(194683) ->
    {0,[{0,138724}],[]};
unicode_table(194684) ->
    {0,[{0,23875}],[]};
unicode_table(194685) ->
    {0,[{0,138726}],[]};
unicode_table(194686) ->
    {0,[{0,23918}],[]};
unicode_table(194687) ->
    {0,[{0,23915}],[]};
unicode_table(194688) ->
    {0,[{0,23932}],[]};
unicode_table(194689) ->
    {0,[{0,24033}],[]};
unicode_table(194690) ->
    {0,[{0,24034}],[]};
unicode_table(194691) ->
    {0,[{0,14383}],[]};
unicode_table(194692) ->
    {0,[{0,24061}],[]};
unicode_table(194693) ->
    {0,[{0,24104}],[]};
unicode_table(194694) ->
    {0,[{0,24125}],[]};
unicode_table(194695) ->
    {0,[{0,24169}],[]};
unicode_table(194696) ->
    {0,[{0,14434}],[]};
unicode_table(194697) ->
    {0,[{0,139651}],[]};
unicode_table(194698) ->
    {0,[{0,14460}],[]};
unicode_table(194699) ->
    {0,[{0,24240}],[]};
unicode_table(194700) ->
    {0,[{0,24243}],[]};
unicode_table(194701) ->
    {0,[{0,24246}],[]};
unicode_table(194702) ->
    {0,[{0,24266}],[]};
unicode_table(194703) ->
    {0,[{0,172946}],[]};
unicode_table(194704) ->
    {0,[{0,24318}],[]};
unicode_table(194705) ->
    {0,[{0,140081}],[]};
unicode_table(194706) ->
    {0,[{0,140081}],[]};
unicode_table(194707) ->
    {0,[{0,33281}],[]};
unicode_table(194708) ->
    {0,[{0,24354}],[]};
unicode_table(194709) ->
    {0,[{0,24354}],[]};
unicode_table(194710) ->
    {0,[{0,14535}],[]};
unicode_table(194711) ->
    {0,[{0,144056}],[]};
unicode_table(194712) ->
    {0,[{0,156122}],[]};
unicode_table(194713) ->
    {0,[{0,24418}],[]};
unicode_table(194714) ->
    {0,[{0,24427}],[]};
unicode_table(194715) ->
    {0,[{0,14563}],[]};
unicode_table(194716) ->
    {0,[{0,24474}],[]};
unicode_table(194717) ->
    {0,[{0,24525}],[]};
unicode_table(194718) ->
    {0,[{0,24535}],[]};
unicode_table(194719) ->
    {0,[{0,24569}],[]};
unicode_table(194720) ->
    {0,[{0,24705}],[]};
unicode_table(194721) ->
    {0,[{0,14650}],[]};
unicode_table(194722) ->
    {0,[{0,14620}],[]};
unicode_table(194723) ->
    {0,[{0,24724}],[]};
unicode_table(194724) ->
    {0,[{0,141012}],[]};
unicode_table(194725) ->
    {0,[{0,24775}],[]};
unicode_table(194726) ->
    {0,[{0,24904}],[]};
unicode_table(194727) ->
    {0,[{0,24908}],[]};
unicode_table(194728) ->
    {0,[{0,24910}],[]};
unicode_table(194729) ->
    {0,[{0,24908}],[]};
unicode_table(194730) ->
    {0,[{0,24954}],[]};
unicode_table(194731) ->
    {0,[{0,24974}],[]};
unicode_table(194732) ->
    {0,[{0,25010}],[]};
unicode_table(194733) ->
    {0,[{0,24996}],[]};
unicode_table(194734) ->
    {0,[{0,25007}],[]};
unicode_table(194735) ->
    {0,[{0,25054}],[]};
unicode_table(194736) ->
    {0,[{0,25074}],[]};
unicode_table(194737) ->
    {0,[{0,25078}],[]};
unicode_table(194738) ->
    {0,[{0,25104}],[]};
unicode_table(194739) ->
    {0,[{0,25115}],[]};
unicode_table(194740) ->
    {0,[{0,25181}],[]};
unicode_table(194741) ->
    {0,[{0,25265}],[]};
unicode_table(194742) ->
    {0,[{0,25300}],[]};
unicode_table(194743) ->
    {0,[{0,25424}],[]};
unicode_table(194744) ->
    {0,[{0,142092}],[]};
unicode_table(194745) ->
    {0,[{0,25405}],[]};
unicode_table(194746) ->
    {0,[{0,25340}],[]};
unicode_table(194747) ->
    {0,[{0,25448}],[]};
unicode_table(194748) ->
    {0,[{0,25475}],[]};
unicode_table(194749) ->
    {0,[{0,25572}],[]};
unicode_table(194750) ->
    {0,[{0,142321}],[]};
unicode_table(194751) ->
    {0,[{0,25634}],[]};
unicode_table(194752) ->
    {0,[{0,25541}],[]};
unicode_table(194753) ->
    {0,[{0,25513}],[]};
unicode_table(194754) ->
    {0,[{0,14894}],[]};
unicode_table(194755) ->
    {0,[{0,25705}],[]};
unicode_table(194756) ->
    {0,[{0,25726}],[]};
unicode_table(194757) ->
    {0,[{0,25757}],[]};
unicode_table(194758) ->
    {0,[{0,25719}],[]};
unicode_table(194759) ->
    {0,[{0,14956}],[]};
unicode_table(194760) ->
    {0,[{0,25935}],[]};
unicode_table(194761) ->
    {0,[{0,25964}],[]};
unicode_table(194762) ->
    {0,[{0,143370}],[]};
unicode_table(194763) ->
    {0,[{0,26083}],[]};
unicode_table(194764) ->
    {0,[{0,26360}],[]};
unicode_table(194765) ->
    {0,[{0,26185}],[]};
unicode_table(194766) ->
    {0,[{0,15129}],[]};
unicode_table(194767) ->
    {0,[{0,26257}],[]};
unicode_table(194768) ->
    {0,[{0,15112}],[]};
unicode_table(194769) ->
    {0,[{0,15076}],[]};
unicode_table(194770) ->
    {0,[{0,20882}],[]};
unicode_table(194771) ->
    {0,[{0,20885}],[]};
unicode_table(194772) ->
    {0,[{0,26368}],[]};
unicode_table(194773) ->
    {0,[{0,26268}],[]};
unicode_table(194774) ->
    {0,[{0,32941}],[]};
unicode_table(194775) ->
    {0,[{0,17369}],[]};
unicode_table(194776) ->
    {0,[{0,26391}],[]};
unicode_table(194777) ->
    {0,[{0,26395}],[]};
unicode_table(194778) ->
    {0,[{0,26401}],[]};
unicode_table(194779) ->
    {0,[{0,26462}],[]};
unicode_table(194780) ->
    {0,[{0,26451}],[]};
unicode_table(194781) ->
    {0,[{0,144323}],[]};
unicode_table(194782) ->
    {0,[{0,15177}],[]};
unicode_table(194783) ->
    {0,[{0,26618}],[]};
unicode_table(194784) ->
    {0,[{0,26501}],[]};
unicode_table(194785) ->
    {0,[{0,26706}],[]};
unicode_table(194786) ->
    {0,[{0,26757}],[]};
unicode_table(194787) ->
    {0,[{0,144493}],[]};
unicode_table(194788) ->
    {0,[{0,26766}],[]};
unicode_table(194789) ->
    {0,[{0,26655}],[]};
unicode_table(194790) ->
    {0,[{0,26900}],[]};
unicode_table(194791) ->
    {0,[{0,15261}],[]};
unicode_table(194792) ->
    {0,[{0,26946}],[]};
unicode_table(194793) ->
    {0,[{0,27043}],[]};
unicode_table(194794) ->
    {0,[{0,27114}],[]};
unicode_table(194795) ->
    {0,[{0,27304}],[]};
unicode_table(194796) ->
    {0,[{0,145059}],[]};
unicode_table(194797) ->
    {0,[{0,27355}],[]};
unicode_table(194798) ->
    {0,[{0,15384}],[]};
unicode_table(194799) ->
    {0,[{0,27425}],[]};
unicode_table(194800) ->
    {0,[{0,145575}],[]};
unicode_table(194801) ->
    {0,[{0,27476}],[]};
unicode_table(194802) ->
    {0,[{0,15438}],[]};
unicode_table(194803) ->
    {0,[{0,27506}],[]};
unicode_table(194804) ->
    {0,[{0,27551}],[]};
unicode_table(194805) ->
    {0,[{0,27578}],[]};
unicode_table(194806) ->
    {0,[{0,27579}],[]};
unicode_table(194807) ->
    {0,[{0,146061}],[]};
unicode_table(194808) ->
    {0,[{0,138507}],[]};
unicode_table(194809) ->
    {0,[{0,146170}],[]};
unicode_table(194810) ->
    {0,[{0,27726}],[]};
unicode_table(194811) ->
    {0,[{0,146620}],[]};
unicode_table(194812) ->
    {0,[{0,27839}],[]};
unicode_table(194813) ->
    {0,[{0,27853}],[]};
unicode_table(194814) ->
    {0,[{0,27751}],[]};
unicode_table(194815) ->
    {0,[{0,27926}],[]};
unicode_table(194816) ->
    {0,[{0,27966}],[]};
unicode_table(194817) ->
    {0,[{0,28023}],[]};
unicode_table(194818) ->
    {0,[{0,27969}],[]};
unicode_table(194819) ->
    {0,[{0,28009}],[]};
unicode_table(194820) ->
    {0,[{0,28024}],[]};
unicode_table(194821) ->
    {0,[{0,28037}],[]};
unicode_table(194822) ->
    {0,[{0,146718}],[]};
unicode_table(194823) ->
    {0,[{0,27956}],[]};
unicode_table(194824) ->
    {0,[{0,28207}],[]};
unicode_table(194825) ->
    {0,[{0,28270}],[]};
unicode_table(194826) ->
    {0,[{0,15667}],[]};
unicode_table(194827) ->
    {0,[{0,28363}],[]};
unicode_table(194828) ->
    {0,[{0,28359}],[]};
unicode_table(194829) ->
    {0,[{0,147153}],[]};
unicode_table(194830) ->
    {0,[{0,28153}],[]};
unicode_table(194831) ->
    {0,[{0,28526}],[]};
unicode_table(194832) ->
    {0,[{0,147294}],[]};
unicode_table(194833) ->
    {0,[{0,147342}],[]};
unicode_table(194834) ->
    {0,[{0,28614}],[]};
unicode_table(194835) ->
    {0,[{0,28729}],[]};
unicode_table(194836) ->
    {0,[{0,28702}],[]};
unicode_table(194837) ->
    {0,[{0,28699}],[]};
unicode_table(194838) ->
    {0,[{0,15766}],[]};
unicode_table(194839) ->
    {0,[{0,28746}],[]};
unicode_table(194840) ->
    {0,[{0,28797}],[]};
unicode_table(194841) ->
    {0,[{0,28791}],[]};
unicode_table(194842) ->
    {0,[{0,28845}],[]};
unicode_table(194843) ->
    {0,[{0,132389}],[]};
unicode_table(194844) ->
    {0,[{0,28997}],[]};
unicode_table(194845) ->
    {0,[{0,148067}],[]};
unicode_table(194846) ->
    {0,[{0,29084}],[]};
unicode_table(194847) ->
    {0,[{0,148395}],[]};
unicode_table(194848) ->
    {0,[{0,29224}],[]};
unicode_table(194849) ->
    {0,[{0,29237}],[]};
unicode_table(194850) ->
    {0,[{0,29264}],[]};
unicode_table(194851) ->
    {0,[{0,149000}],[]};
unicode_table(194852) ->
    {0,[{0,29312}],[]};
unicode_table(194853) ->
    {0,[{0,29333}],[]};
unicode_table(194854) ->
    {0,[{0,149301}],[]};
unicode_table(194855) ->
    {0,[{0,149524}],[]};
unicode_table(194856) ->
    {0,[{0,29562}],[]};
unicode_table(194857) ->
    {0,[{0,29579}],[]};
unicode_table(194858) ->
    {0,[{0,16044}],[]};
unicode_table(194859) ->
    {0,[{0,29605}],[]};
unicode_table(194860) ->
    {0,[{0,16056}],[]};
unicode_table(194861) ->
    {0,[{0,16056}],[]};
unicode_table(194862) ->
    {0,[{0,29767}],[]};
unicode_table(194863) ->
    {0,[{0,29788}],[]};
unicode_table(194864) ->
    {0,[{0,29809}],[]};
unicode_table(194865) ->
    {0,[{0,29829}],[]};
unicode_table(194866) ->
    {0,[{0,29898}],[]};
unicode_table(194867) ->
    {0,[{0,16155}],[]};
unicode_table(194868) ->
    {0,[{0,29988}],[]};
unicode_table(194869) ->
    {0,[{0,150582}],[]};
unicode_table(194870) ->
    {0,[{0,30014}],[]};
unicode_table(194871) ->
    {0,[{0,150674}],[]};
unicode_table(194872) ->
    {0,[{0,30064}],[]};
unicode_table(194873) ->
    {0,[{0,139679}],[]};
unicode_table(194874) ->
    {0,[{0,30224}],[]};
unicode_table(194875) ->
    {0,[{0,151457}],[]};
unicode_table(194876) ->
    {0,[{0,151480}],[]};
unicode_table(194877) ->
    {0,[{0,151620}],[]};
unicode_table(194878) ->
    {0,[{0,16380}],[]};
unicode_table(194879) ->
    {0,[{0,16392}],[]};
unicode_table(194880) ->
    {0,[{0,30452}],[]};
unicode_table(194881) ->
    {0,[{0,151795}],[]};
unicode_table(194882) ->
    {0,[{0,151794}],[]};
unicode_table(194883) ->
    {0,[{0,151833}],[]};
unicode_table(194884) ->
    {0,[{0,151859}],[]};
unicode_table(194885) ->
    {0,[{0,30494}],[]};
unicode_table(194886) ->
    {0,[{0,30495}],[]};
unicode_table(194887) ->
    {0,[{0,30495}],[]};
unicode_table(194888) ->
    {0,[{0,30538}],[]};
unicode_table(194889) ->
    {0,[{0,16441}],[]};
unicode_table(194890) ->
    {0,[{0,30603}],[]};
unicode_table(194891) ->
    {0,[{0,16454}],[]};
unicode_table(194892) ->
    {0,[{0,16534}],[]};
unicode_table(194893) ->
    {0,[{0,152605}],[]};
unicode_table(194894) ->
    {0,[{0,30798}],[]};
unicode_table(194895) ->
    {0,[{0,30860}],[]};
unicode_table(194896) ->
    {0,[{0,30924}],[]};
unicode_table(194897) ->
    {0,[{0,16611}],[]};
unicode_table(194898) ->
    {0,[{0,153126}],[]};
unicode_table(194899) ->
    {0,[{0,31062}],[]};
unicode_table(194900) ->
    {0,[{0,153242}],[]};
unicode_table(194901) ->
    {0,[{0,153285}],[]};
unicode_table(194902) ->
    {0,[{0,31119}],[]};
unicode_table(194903) ->
    {0,[{0,31211}],[]};
unicode_table(194904) ->
    {0,[{0,16687}],[]};
unicode_table(194905) ->
    {0,[{0,31296}],[]};
unicode_table(194906) ->
    {0,[{0,31306}],[]};
unicode_table(194907) ->
    {0,[{0,31311}],[]};
unicode_table(194908) ->
    {0,[{0,153980}],[]};
unicode_table(194909) ->
    {0,[{0,154279}],[]};
unicode_table(194910) ->
    {0,[{0,154279}],[]};
unicode_table(194911) ->
    {0,[{0,31470}],[]};
unicode_table(194912) ->
    {0,[{0,16898}],[]};
unicode_table(194913) ->
    {0,[{0,154539}],[]};
unicode_table(194914) ->
    {0,[{0,31686}],[]};
unicode_table(194915) ->
    {0,[{0,31689}],[]};
unicode_table(194916) ->
    {0,[{0,16935}],[]};
unicode_table(194917) ->
    {0,[{0,154752}],[]};
unicode_table(194918) ->
    {0,[{0,31954}],[]};
unicode_table(194919) ->
    {0,[{0,17056}],[]};
unicode_table(194920) ->
    {0,[{0,31976}],[]};
unicode_table(194921) ->
    {0,[{0,31971}],[]};
unicode_table(194922) ->
    {0,[{0,32000}],[]};
unicode_table(194923) ->
    {0,[{0,155526}],[]};
unicode_table(194924) ->
    {0,[{0,32099}],[]};
unicode_table(194925) ->
    {0,[{0,17153}],[]};
unicode_table(194926) ->
    {0,[{0,32199}],[]};
unicode_table(194927) ->
    {0,[{0,32258}],[]};
unicode_table(194928) ->
    {0,[{0,32325}],[]};
unicode_table(194929) ->
    {0,[{0,17204}],[]};
unicode_table(194930) ->
    {0,[{0,156200}],[]};
unicode_table(194931) ->
    {0,[{0,156231}],[]};
unicode_table(194932) ->
    {0,[{0,17241}],[]};
unicode_table(194933) ->
    {0,[{0,156377}],[]};
unicode_table(194934) ->
    {0,[{0,32634}],[]};
unicode_table(194935) ->
    {0,[{0,156478}],[]};
unicode_table(194936) ->
    {0,[{0,32661}],[]};
unicode_table(194937) ->
    {0,[{0,32762}],[]};
unicode_table(194938) ->
    {0,[{0,32773}],[]};
unicode_table(194939) ->
    {0,[{0,156890}],[]};
unicode_table(194940) ->
    {0,[{0,156963}],[]};
unicode_table(194941) ->
    {0,[{0,32864}],[]};
unicode_table(194942) ->
    {0,[{0,157096}],[]};
unicode_table(194943) ->
    {0,[{0,32880}],[]};
unicode_table(194944) ->
    {0,[{0,144223}],[]};
unicode_table(194945) ->
    {0,[{0,17365}],[]};
unicode_table(194946) ->
    {0,[{0,32946}],[]};
unicode_table(194947) ->
    {0,[{0,33027}],[]};
unicode_table(194948) ->
    {0,[{0,17419}],[]};
unicode_table(194949) ->
    {0,[{0,33086}],[]};
unicode_table(194950) ->
    {0,[{0,23221}],[]};
unicode_table(194951) ->
    {0,[{0,157607}],[]};
unicode_table(194952) ->
    {0,[{0,157621}],[]};
unicode_table(194953) ->
    {0,[{0,144275}],[]};
unicode_table(194954) ->
    {0,[{0,144284}],[]};
unicode_table(194955) ->
    {0,[{0,33281}],[]};
unicode_table(194956) ->
    {0,[{0,33284}],[]};
unicode_table(194957) ->
    {0,[{0,36766}],[]};
unicode_table(194958) ->
    {0,[{0,17515}],[]};
unicode_table(194959) ->
    {0,[{0,33425}],[]};
unicode_table(194960) ->
    {0,[{0,33419}],[]};
unicode_table(194961) ->
    {0,[{0,33437}],[]};
unicode_table(194962) ->
    {0,[{0,21171}],[]};
unicode_table(194963) ->
    {0,[{0,33457}],[]};
unicode_table(194964) ->
    {0,[{0,33459}],[]};
unicode_table(194965) ->
    {0,[{0,33469}],[]};
unicode_table(194966) ->
    {0,[{0,33510}],[]};
unicode_table(194967) ->
    {0,[{0,158524}],[]};
unicode_table(194968) ->
    {0,[{0,33509}],[]};
unicode_table(194969) ->
    {0,[{0,33565}],[]};
unicode_table(194970) ->
    {0,[{0,33635}],[]};
unicode_table(194971) ->
    {0,[{0,33709}],[]};
unicode_table(194972) ->
    {0,[{0,33571}],[]};
unicode_table(194973) ->
    {0,[{0,33725}],[]};
unicode_table(194974) ->
    {0,[{0,33767}],[]};
unicode_table(194975) ->
    {0,[{0,33879}],[]};
unicode_table(194976) ->
    {0,[{0,33619}],[]};
unicode_table(194977) ->
    {0,[{0,33738}],[]};
unicode_table(194978) ->
    {0,[{0,33740}],[]};
unicode_table(194979) ->
    {0,[{0,33756}],[]};
unicode_table(194980) ->
    {0,[{0,158774}],[]};
unicode_table(194981) ->
    {0,[{0,159083}],[]};
unicode_table(194982) ->
    {0,[{0,158933}],[]};
unicode_table(194983) ->
    {0,[{0,17707}],[]};
unicode_table(194984) ->
    {0,[{0,34033}],[]};
unicode_table(194985) ->
    {0,[{0,34035}],[]};
unicode_table(194986) ->
    {0,[{0,34070}],[]};
unicode_table(194987) ->
    {0,[{0,160714}],[]};
unicode_table(194988) ->
    {0,[{0,34148}],[]};
unicode_table(194989) ->
    {0,[{0,159532}],[]};
unicode_table(194990) ->
    {0,[{0,17757}],[]};
unicode_table(194991) ->
    {0,[{0,17761}],[]};
unicode_table(194992) ->
    {0,[{0,159665}],[]};
unicode_table(194993) ->
    {0,[{0,159954}],[]};
unicode_table(194994) ->
    {0,[{0,17771}],[]};
unicode_table(194995) ->
    {0,[{0,34384}],[]};
unicode_table(194996) ->
    {0,[{0,34396}],[]};
unicode_table(194997) ->
    {0,[{0,34407}],[]};
unicode_table(194998) ->
    {0,[{0,34409}],[]};
unicode_table(194999) ->
    {0,[{0,34473}],[]};
unicode_table(195000) ->
    {0,[{0,34440}],[]};
unicode_table(195001) ->
    {0,[{0,34574}],[]};
unicode_table(195002) ->
    {0,[{0,34530}],[]};
unicode_table(195003) ->
    {0,[{0,34681}],[]};
unicode_table(195004) ->
    {0,[{0,34600}],[]};
unicode_table(195005) ->
    {0,[{0,34667}],[]};
unicode_table(195006) ->
    {0,[{0,34694}],[]};
unicode_table(195007) ->
    {0,[{0,17879}],[]};
unicode_table(195008) ->
    {0,[{0,34785}],[]};
unicode_table(195009) ->
    {0,[{0,34817}],[]};
unicode_table(195010) ->
    {0,[{0,17913}],[]};
unicode_table(195011) ->
    {0,[{0,34912}],[]};
unicode_table(195012) ->
    {0,[{0,34915}],[]};
unicode_table(195013) ->
    {0,[{0,161383}],[]};
unicode_table(195014) ->
    {0,[{0,35031}],[]};
unicode_table(195015) ->
    {0,[{0,35038}],[]};
unicode_table(195016) ->
    {0,[{0,17973}],[]};
unicode_table(195017) ->
    {0,[{0,35066}],[]};
unicode_table(195018) ->
    {0,[{0,13499}],[]};
unicode_table(195019) ->
    {0,[{0,161966}],[]};
unicode_table(195020) ->
    {0,[{0,162150}],[]};
unicode_table(195021) ->
    {0,[{0,18110}],[]};
unicode_table(195022) ->
    {0,[{0,18119}],[]};
unicode_table(195023) ->
    {0,[{0,35488}],[]};
unicode_table(195024) ->
    {0,[{0,35565}],[]};
unicode_table(195025) ->
    {0,[{0,35722}],[]};
unicode_table(195026) ->
    {0,[{0,35925}],[]};
unicode_table(195027) ->
    {0,[{0,162984}],[]};
unicode_table(195028) ->
    {0,[{0,36011}],[]};
unicode_table(195029) ->
    {0,[{0,36033}],[]};
unicode_table(195030) ->
    {0,[{0,36123}],[]};
unicode_table(195031) ->
    {0,[{0,36215}],[]};
unicode_table(195032) ->
    {0,[{0,163631}],[]};
unicode_table(195033) ->
    {0,[{0,133124}],[]};
unicode_table(195034) ->
    {0,[{0,36299}],[]};
unicode_table(195035) ->
    {0,[{0,36284}],[]};
unicode_table(195036) ->
    {0,[{0,36336}],[]};
unicode_table(195037) ->
    {0,[{0,133342}],[]};
unicode_table(195038) ->
    {0,[{0,36564}],[]};
unicode_table(195039) ->
    {0,[{0,36664}],[]};
unicode_table(195040) ->
    {0,[{0,165330}],[]};
unicode_table(195041) ->
    {0,[{0,165357}],[]};
unicode_table(195042) ->
    {0,[{0,37012}],[]};
unicode_table(195043) ->
    {0,[{0,37105}],[]};
unicode_table(195044) ->
    {0,[{0,37137}],[]};
unicode_table(195045) ->
    {0,[{0,165678}],[]};
unicode_table(195046) ->
    {0,[{0,37147}],[]};
unicode_table(195047) ->
    {0,[{0,37432}],[]};
unicode_table(195048) ->
    {0,[{0,37591}],[]};
unicode_table(195049) ->
    {0,[{0,37592}],[]};
unicode_table(195050) ->
    {0,[{0,37500}],[]};
unicode_table(195051) ->
    {0,[{0,37881}],[]};
unicode_table(195052) ->
    {0,[{0,37909}],[]};
unicode_table(195053) ->
    {0,[{0,166906}],[]};
unicode_table(195054) ->
    {0,[{0,38283}],[]};
unicode_table(195055) ->
    {0,[{0,18837}],[]};
unicode_table(195056) ->
    {0,[{0,38327}],[]};
unicode_table(195057) ->
    {0,[{0,167287}],[]};
unicode_table(195058) ->
    {0,[{0,18918}],[]};
unicode_table(195059) ->
    {0,[{0,38595}],[]};
unicode_table(195060) ->
    {0,[{0,23986}],[]};
unicode_table(195061) ->
    {0,[{0,38691}],[]};
unicode_table(195062) ->
    {0,[{0,168261}],[]};
unicode_table(195063) ->
    {0,[{0,168474}],[]};
unicode_table(195064) ->
    {0,[{0,19054}],[]};
unicode_table(195065) ->
    {0,[{0,19062}],[]};
unicode_table(195066) ->
    {0,[{0,38880}],[]};
unicode_table(195067) ->
    {0,[{0,168970}],[]};
unicode_table(195068) ->
    {0,[{0,19122}],[]};
unicode_table(195069) ->
    {0,[{0,169110}],[]};
unicode_table(195070) ->
    {0,[{0,38923}],[]};
unicode_table(195071) ->
    {0,[{0,38923}],[]};
unicode_table(195072) ->
    {0,[{0,38953}],[]};
unicode_table(195073) ->
    {0,[{0,169398}],[]};
unicode_table(195074) ->
    {0,[{0,39138}],[]};
unicode_table(195075) ->
    {0,[{0,19251}],[]};
unicode_table(195076) ->
    {0,[{0,39209}],[]};
unicode_table(195077) ->
    {0,[{0,39335}],[]};
unicode_table(195078) ->
    {0,[{0,39362}],[]};
unicode_table(195079) ->
    {0,[{0,39422}],[]};
unicode_table(195080) ->
    {0,[{0,19406}],[]};
unicode_table(195081) ->
    {0,[{0,170800}],[]};
unicode_table(195082) ->
    {0,[{0,39698}],[]};
unicode_table(195083) ->
    {0,[{0,40000}],[]};
unicode_table(195084) ->
    {0,[{0,40189}],[]};
unicode_table(195085) ->
    {0,[{0,19662}],[]};
unicode_table(195086) ->
    {0,[{0,19693}],[]};
unicode_table(195087) ->
    {0,[{0,40295}],[]};
unicode_table(195088) ->
    {0,[{0,172238}],[]};
unicode_table(195089) ->
    {0,[{0,19704}],[]};
unicode_table(195090) ->
    {0,[{0,172293}],[]};
unicode_table(195091) ->
    {0,[{0,172558}],[]};
unicode_table(195092) ->
    {0,[{0,172689}],[]};
unicode_table(195093) ->
    {0,[{0,40635}],[]};
unicode_table(195094) ->
    {0,[{0,19798}],[]};
unicode_table(195095) ->
    {0,[{0,40697}],[]};
unicode_table(195096) ->
    {0,[{0,40702}],[]};
unicode_table(195097) ->
    {0,[{0,40709}],[]};
unicode_table(195098) ->
    {0,[{0,40719}],[]};
unicode_table(195099) ->
    {0,[{0,40726}],[]};
unicode_table(195100) ->
    {0,[{0,40763}],[]};
unicode_table(195101) ->
    {0,[{0,173568}],[]};
unicode_table(_) ->
    {0,[],[]}.