-file("shell_docs.erl", 1).

-module(shell_docs).

-file("/usr/lib/erlang/lib/kernel-7.2/include/eep48.hrl", 1).

-record(docs_v1, {anno,beam_language = erlang,format = <<"application/erlang+html">>,module_doc,metadata = #{otp_doc_vsn=>{1,0,0}},docs}).

-record(docs_v1_entry, {kind_name_arity,anno,signature,doc,metadata}).

-file("shell_docs.erl", 23).

-export([render/2, render/3, render/4, render/5]).

-export([render_type/2, render_type/3, render_type/4, render_type/5]).

-export([render_callback/2, render_callback/3, render_callback/4, render_callback/5]).

-export([validate/1, normalize/1]).

-export([get_doc/1, get_doc/3, get_type_doc/3, get_callback_doc/3]).

-record(config, {docs,encoding,ansi,io_opts = io:getopts(),columns}).

-type(docs_v1()::#docs_v1{}).

-type(config()::#{encoding => unicode|latin1,columns => pos_integer(),ansi => boolean()}).

-type(chunk_elements()::[chunk_element()]).

-type(chunk_element()::{chunk_element_type(),chunk_element_attrs(),chunk_elements()}|binary()).

-type(chunk_element_attrs()::[chunk_element_attr()]).

-type(chunk_element_attr()::{atom(),unicode:chardata()}).

-type(chunk_element_type()::chunk_element_inline_type()|chunk_element_block_type()).

-type(chunk_element_inline_type()::a|code|em|i).

-type(chunk_element_block_type()::p|'div'|br|pre|ul|ol|li|dl|dt|dd|h1|h2|h3).

-spec(validate(Module) -> ok when Module::module()|docs_v1()).

validate(Module)
    when is_atom(Module)->
    {ok,Doc} = code:get_doc(Module),
    validate(Doc);
validate(#docs_v1{module_doc = MDocs,docs = AllDocs}) ->
    AE = lists:sort([a, p, 'div', br, h1, h2, h3, i, em, pre, code, ul, ol, li, dl, dt, dd]),
    AE = lists:sort([i, em, code, a] ++ [p, 'div', pre, br, ul, ol, li, dl, dt, dd, h1, h2, h3]),
    true = lists:all(fun (Elem)->
        Elem =:= a orelse Elem =:= code orelse Elem =:= i orelse Elem =:= em end,[i, em, code, a]),
    true = lists:all(fun (Elem)->
         not (Elem =:= a orelse Elem =:= code orelse Elem =:= i orelse Elem =:= em) end,[p, 'div', pre, br, ul, ol, li, dl, dt, dd, h1, h2, h3]),
    _ = validate_docs(MDocs),
    lists:foreach(fun ({_,_Anno,Sig,Docs,_Meta})->
        case lists:all(fun erlang:is_binary/1,Sig) of
            false->
                throw({invalid_signature,Sig});
            true->
                ok
        end,
        validate_docs(Docs) end,AllDocs),
    ok.

validate_docs(hidden) ->
    ok;
validate_docs(none) ->
    ok;
validate_docs(#{} = MDocs) ->
    _ = maps:map(fun (_Key,MDoc)->
        validate_docs(MDoc,[]) end,MDocs),
    ok.

validate_docs([H| T],Path)
    when is_tuple(H)->
    _ = validate_docs(H,Path),
    validate_docs(T,Path);
validate_docs({br,Attr,Content} = Br,Path) ->
    if Attr =:= [],
    Content =:= [] ->
        ok;true ->
        throw({content_to_allowed_in_br,Br,Path}) end;
validate_docs({Tag,Attr,Content},Path) ->
    case Tag =/= li andalso length(Path) > 0 andalso (hd(Path) =:= ul orelse hd(Path) =:= ol) of
        true->
            throw({only_li_allowed_within_ul_or_ol,Tag,Path});
        _->
            ok
    end,
    case Tag =/= dd andalso Tag =/= dt andalso length(Path) > 0 andalso hd(Path) =:= dl of
        true->
            throw({only_dd_or_dt_allowed_within_dl,Tag,Path});
        _->
            ok
    end,
    case Tag =:= p andalso lists:member(p,Path) of
        true->
            throw({nested_p_not_allowed,Tag,Path});
        false->
            ok
    end,
    case lists:member(pre,Path) or lists:member(h1,Path) or lists:member(h2,Path) or lists:member(h3,Path) of
        true
            when  not (Tag =:= a orelse Tag =:= code orelse Tag =:= i orelse Tag =:= em)->
            throw({cannot_put_block_tag_within_pre,Tag,Path});
        _->
            ok
    end,
    case lists:member(Tag,[p, 'div', pre, br, ul, ol, li, dl, dt, dd, h1, h2, h3]) of
        true->
            case lists:any(fun (P)->
                P =:= a orelse P =:= code orelse P =:= i orelse P =:= em end,Path) of
                true->
                    throw({cannot_put_inline_tag_outside_block,Tag,Path});
                false->
                    ok
            end;
        false->
            ok
    end,
    case lists:member(Tag,[a, p, 'div', br, h1, h2, h3, i, em, pre, code, ul, ol, li, dl, dt, dd]) of
        false->
            throw({invalid_tag,Tag,Path});
        true->
            ok
    end,
    case lists:all(fun ({Key,Val})->
        is_atom(Key) andalso is_binary(Val) end,Attr) of
        true->
            ok;
        false->
            throw({invalid_attribute,{Tag,Attr}})
    end,
    validate_docs(Content,[Tag| Path]);
validate_docs([Chars| T],Path)
    when is_binary(Chars)->
    validate_docs(T,Path);
validate_docs([],_) ->
    ok.

-spec(normalize(Docs) -> NormalizedDocs when Docs::chunk_elements(),NormalizedDocs::chunk_elements()).

normalize(Docs) ->
    Trimmed = normalize_trim(Docs,true),
    normalize_space(Trimmed).

normalize_trim(Bin,true)
    when is_binary(Bin)->
    NoSpace = re:replace(Bin,"[^\\S\n]*\n+[^\\S\n]*","\n",[unicode, global]),
    NoTab = re:replace(NoSpace,"\t"," ",[unicode, global]),
    NoNewLine = re:replace(NoTab,"\\v"," ",[unicode, global]),
    re:replace(NoNewLine,"\\s+"," ",[unicode, global, {return,binary}]);
normalize_trim(Bin,false)
    when is_binary(Bin)->
    Bin;
normalize_trim([{pre,Attr,Content}| T],Trim) ->
    [{pre,Attr,normalize_trim(Content,false)}| normalize_trim(T,Trim)];
normalize_trim([{Tag,Attr,Content}| T],Trim) ->
    [{Tag,Attr,normalize_trim(Content,Trim)}| normalize_trim(T,Trim)];
normalize_trim([<<>>| T],Trim) ->
    normalize_trim(T,Trim);
normalize_trim([B1, B2| T],Trim)
    when is_binary(B1),
    is_binary(B2)->
    normalize_trim([<<B1/binary,B2/binary>>| T],Trim);
normalize_trim([H| T],Trim) ->
    [normalize_trim(H,Trim)| normalize_trim(T,Trim)];
normalize_trim([],_Trim) ->
    [].

normalize_space([{Pre,Attr,Content}| T])
    when Pre =:= pre->
    [{Pre,Attr,trim_first_and_last(Content,$\n)}| normalize_space(T)];
normalize_space([{Block,Attr,Content}| T])
    when  not (Block =:= a orelse Block =:= code orelse Block =:= i orelse Block =:= em)->
    [{Block,Attr,normalize_space(Content)}| normalize_space(T)];
normalize_space([]) ->
    [];
normalize_space(Elems) ->
    {InlineElems,T} = lists:splitwith(fun (E)->
        is_binary(E) orelse is_tuple(E) andalso (element(1,E) =:= a orelse element(1,E) =:= code orelse element(1,E) =:= i orelse element(1,E) =:= em) end,Elems),
    trim_inline(InlineElems) ++ normalize_space(T).

trim_inline(Content) ->
    {NewContent,_} = trim_inline(Content,false),
    trim_first_and_last(NewContent,$ ).

trim_inline([Bin| T],false)
    when is_binary(Bin)->
    LastElem = binary:at(Bin,byte_size(Bin) - 1),
    case trim_inline(T,LastElem =:= $ ) of
        {[B2| NewT],NewState}
            when is_binary(B2)->
            {[<<Bin/binary,B2/binary>>| NewT],NewState};
        {NewT,NewState}->
            {[Bin| NewT],NewState}
    end;
trim_inline([<<" ">>| T],true) ->
    trim_inline(T,true);
trim_inline([<<" ",Bin/binary>>| T],true)
    when is_binary(Bin)->
    trim_inline([Bin| T],true);
trim_inline([Bin| T],true)
    when is_binary(Bin)->
    trim_inline([Bin| T],false);
trim_inline([{Elem,Attr,Content}| T],TrimSpace) ->
    {NewContent,ContentTrimSpace} = trim_inline(Content,TrimSpace),
    {NewT,TTrimSpace} = trim_inline(T,ContentTrimSpace),
    IsAnchor = Elem =:= a andalso proplists:is_defined(id,Attr),
    if NewContent == [] andalso  not IsAnchor ->
        {NewT,TTrimSpace};true ->
        {[{Elem,Attr,NewContent}| NewT],TTrimSpace} end;
trim_inline([],TrimSpace) ->
    {[],TrimSpace}.

trim_first_and_last(Content,What)
    when What < 256->
    {FirstTrimmed,_} = trim_first(Content,What),
    {LastTrimmed,_} = trim_last(FirstTrimmed,What),
    LastTrimmed.

trim_first([Bin| T],What)
    when is_binary(Bin)->
    case Bin of
        <<What>>->
            {T,true};
        <<What,NewBin/binary>>->
            {[NewBin| T],true};
        Bin->
            {[Bin| T],true}
    end;
trim_first([{Elem,Attr,Content} = Tag| T],What) ->
    case trim_first(Content,What) of
        {[],true}->
            {T,true};
        {NewContent,true}->
            {[{Elem,Attr,NewContent}| T],true};
        {Content,false}->
            {NewT,NewState} = trim_first(T,What),
            {[Tag| NewT],NewState}
    end;
trim_first([],_What) ->
    {[],false}.

trim_last([Bin| T],What)
    when is_binary(Bin)->
    case trim_last(T,What) of
        {NewT,true}->
            {[Bin| NewT],true};
        {T,false}->
            PreSz = byte_size(Bin) - 1,
            case Bin of
                <<What>>->
                    {T,true};
                <<NewBin:PreSz/binary,What>>->
                    {[NewBin| T],true};
                Bin->
                    {[Bin| T],true}
            end
    end;
trim_last([{Elem,Attr,Content} = Tag| T],What) ->
    case trim_last(T,What) of
        {NewT,true}->
            {[Tag| NewT],true};
        {T,false}->
            case trim_last(Content,What) of
                {[],true}->
                    {[],true};
                {NewContent,NewState}->
                    {[{Elem,Attr,NewContent}| T],NewState}
            end
    end;
trim_last([],_What) ->
    {[],false}.

-spec(get_doc(Module::module()) -> chunk_elements()).

get_doc(Module) ->
    {ok,#docs_v1{module_doc = ModuleDoc}} = code:get_doc(Module),
    get_local_doc(Module,ModuleDoc).

-spec(get_doc(Module::module(),Function,Arity) -> [{{Function,Arity},Anno,Signature,chunk_elements(),Metadata}] when Function::atom(),Arity::arity(),Anno::erl_anno:anno(),Signature::[binary()],Metadata::#{}).

get_doc(Module,Function,Arity) ->
    {ok,#docs_v1{docs = Docs}} = code:get_doc(Module),
    FnFunctions = lists:filter(fun ({{function,F,A},_Anno,_Sig,_Doc,_Meta})->
        F =:= Function andalso A =:= Arity;(_)->
        false end,Docs),
    [{F,A,S,get_local_doc({F,A},D),M} || {F,A,S,D,M} <- FnFunctions].

-spec(render(Module,Docs) -> unicode:chardata() when Module::module(),Docs::docs_v1()).

render(Module,#docs_v1{} = D)
    when is_atom(Module)->
    render(Module,D,#{}).

-spec(render(Module,Docs,Config) -> unicode:chardata() when Module::module(),Docs::docs_v1(),Config::config();(Module,Function,Docs) -> Res when Module::module(),Function::atom(),Docs::docs_v1(),Res::unicode:chardata()|{error,function_missing}).

render(Module,#docs_v1{module_doc = ModuleDoc} = D,Config)
    when is_atom(Module),
    is_map(Config)->
    render_headers_and_docs([[{h2,[],[<<"\t",(atom_to_binary(Module))/binary>>]}]],get_local_doc(Module,ModuleDoc),D,Config);
render(_Module,Function,#docs_v1{} = D) ->
    render(_Module,Function,D,#{}).

-spec(render(Module,Function,Docs,Config) -> Res when Module::module(),Function::atom(),Docs::docs_v1(),Config::config(),Res::unicode:chardata()|{error,function_missing};(Module,Function,Arity,Docs) -> Res when Module::module(),Function::atom(),Arity::arity(),Docs::docs_v1(),Res::unicode:chardata()|{error,function_missing}).

render(Module,Function,#docs_v1{docs = Docs} = D,Config)
    when is_atom(Module),
    is_atom(Function),
    is_map(Config)->
    render_function(lists:filter(fun ({{function,F,_},_Anno,_Sig,_Doc,_Meta})->
        F =:= Function;(_)->
        false end,Docs),D,Config);
render(_Module,Function,Arity,#docs_v1{} = D) ->
    render(_Module,Function,Arity,D,#{}).

-spec(render(Module,Function,Arity,Docs,Config) -> Res when Module::module(),Function::atom(),Arity::arity(),Docs::docs_v1(),Config::config(),Res::unicode:chardata()|{error,function_missing}).

render(Module,Function,Arity,#docs_v1{docs = Docs} = D,Config)
    when is_atom(Module),
    is_atom(Function),
    is_integer(Arity),
    is_map(Config)->
    render_function(lists:filter(fun ({{function,F,A},_Anno,_Sig,_Doc,_Meta})->
        F =:= Function andalso A =:= Arity;(_)->
        false end,Docs),D,Config).

-spec(get_type_doc(Module::module(),Type::atom(),Arity::arity()) -> [{{Type,Arity},Anno,Signature,chunk_elements(),Metadata}] when Type::atom(),Arity::arity(),Anno::erl_anno:anno(),Signature::[binary()],Metadata::#{}).

get_type_doc(Module,Type,Arity) ->
    {ok,#docs_v1{docs = Docs}} = code:get_doc(Module),
    FnFunctions = lists:filter(fun ({{type,T,A},_Anno,_Sig,_Doc,_Meta})->
        T =:= Type andalso A =:= Arity;(_)->
        false end,Docs),
    [{F,A,S,get_local_doc(F,D),M} || {F,A,S,D,M} <- FnFunctions].

-spec(render_type(Module,Docs) -> unicode:chardata() when Module::module(),Docs::docs_v1()).

render_type(Module,D) ->
    render_type(Module,D,#{}).

-spec(render_type(Module,Docs,Config) -> unicode:chardata() when Module::module(),Docs::docs_v1(),Config::config();(Module,Type,Docs) -> Res when Module::module(),Type::atom(),Docs::docs_v1(),Res::unicode:chardata()|{error,type_missing}).

render_type(Module,D = #docs_v1{},Config) ->
    render_signature_listing(Module,type,D,Config);
render_type(Module,Type,D = #docs_v1{}) ->
    render_type(Module,Type,D,#{}).

-spec(render_type(Module,Type,Docs,Config) -> Res when Module::module(),Type::atom(),Docs::docs_v1(),Config::config(),Res::unicode:chardata()|{error,type_missing};(Module,Type,Arity,Docs) -> Res when Module::module(),Type::atom(),Arity::arity(),Docs::docs_v1(),Res::unicode:chardata()|{error,type_missing}).

render_type(_Module,Type,#docs_v1{docs = Docs} = D,Config) ->
    render_typecb_docs(lists:filter(fun ({{type,T,_},_Anno,_Sig,_Doc,_Meta})->
        T =:= Type;(_)->
        false end,Docs),D,Config);
render_type(_Module,Type,Arity,#docs_v1{} = D) ->
    render_type(_Module,Type,Arity,D,#{}).

-spec(render_type(Module,Type,Arity,Docs,Config) -> Res when Module::module(),Type::atom(),Arity::arity(),Docs::docs_v1(),Config::config(),Res::unicode:chardata()|{error,type_missing}).

render_type(_Module,Type,Arity,#docs_v1{docs = Docs} = D,Config) ->
    render_typecb_docs(lists:filter(fun ({{type,T,A},_Anno,_Sig,_Doc,_Meta})->
        T =:= Type andalso A =:= Arity;(_)->
        false end,Docs),D,Config).

-spec(get_callback_doc(Module::module(),Callback::atom(),Arity::arity()) -> [{{Callback,Arity},Anno,Signature,chunk_elements(),Metadata}] when Callback::atom(),Arity::arity(),Anno::erl_anno:anno(),Signature::[binary()],Metadata::#{}).

get_callback_doc(Module,Callback,Arity) ->
    {ok,#docs_v1{docs = Docs}} = code:get_doc(Module),
    FnFunctions = lists:filter(fun ({{callback,T,A},_Anno,_Sig,_Doc,_Meta})->
        T =:= Callback andalso A =:= Arity;(_)->
        false end,Docs),
    [{F,A,S,get_local_doc(F,D),M} || {F,A,S,D,M} <- FnFunctions].

-spec(render_callback(Module,Docs) -> unicode:chardata() when Module::module(),Docs::docs_v1()).

render_callback(Module,D) ->
    render_callback(Module,D,#{}).

-spec(render_callback(Module,Docs,Config) -> unicode:chardata() when Module::module(),Docs::docs_v1(),Config::config();(Module,Callback,Docs) -> Res when Module::module(),Callback::atom(),Docs::docs_v1(),Res::unicode:chardata()|{error,callback_missing}).

render_callback(_Module,Callback,#docs_v1{} = D) ->
    render_callback(_Module,Callback,D,#{});
render_callback(Module,D,Config) ->
    render_signature_listing(Module,callback,D,Config).

-spec(render_callback(Module,Callback,Docs,Config) -> Res when Module::module(),Callback::atom(),Docs::docs_v1(),Config::config(),Res::unicode:chardata()|{error,callback_missing};(Module,Callback,Arity,Docs) -> Res when Module::module(),Callback::atom(),Arity::arity(),Docs::docs_v1(),Res::unicode:chardata()|{error,callback_missing}).

render_callback(_Module,Callback,Arity,#docs_v1{} = D) ->
    render_callback(_Module,Callback,Arity,D,#{});
render_callback(_Module,Callback,#docs_v1{docs = Docs} = D,Config) ->
    render_typecb_docs(lists:filter(fun ({{callback,T,_},_Anno,_Sig,_Doc,_Meta})->
        T =:= Callback;(_)->
        false end,Docs),D,Config).

-spec(render_callback(Module,Callback,Arity,Docs,Config) -> Res when Module::module(),Callback::atom(),Arity::arity(),Docs::docs_v1(),Config::config(),Res::unicode:chardata()|{error,callback_missing}).

render_callback(_Module,Callback,Arity,#docs_v1{docs = Docs} = D,Config) ->
    render_typecb_docs(lists:filter(fun ({{callback,T,A},_Anno,_Sig,_Doc,_Meta})->
        T =:= Callback andalso A =:= Arity;(_)->
        false end,Docs),D,Config).

get_local_doc(MissingMod,Docs)
    when is_atom(MissingMod)->
    get_local_doc(atom_to_binary(MissingMod),Docs);
get_local_doc({F,A},Docs) ->
    get_local_doc(unicode:characters_to_binary(io_lib:format("~tp/~p",[F, A])),Docs);
get_local_doc(_Missing,#{<<"en">>:=Docs}) ->
    normalize(Docs);
get_local_doc(_Missing,ModuleDoc)
    when map_size(ModuleDoc) > 0->
    normalize(maps:get(hd(maps:keys(ModuleDoc)),ModuleDoc));
get_local_doc(Missing,hidden) ->
    [{p,[],[<<"The documentation for ">>, Missing, <<" is hidden. This probably means that it is internal and not t" "o be used by other applications.">>]}];
get_local_doc(Missing,None)
    when None =:= none;
    None =:= #{}->
    [{p,[],[<<"There is no documentation for ">>, Missing]}].

render_function([],_D,_Config) ->
    {error,function_missing};
render_function(FDocs,#docs_v1{docs = Docs} = D,Config) ->
    Grouping = lists:foldl(fun ({_Group,_Anno,_Sig,_Doc,#{equiv:=Group}} = Func,Acc)->
        Members = maps:get(Group,Acc,[]),
        Acc#{Group=>[Func| Members]};({Group,_Anno,_Sig,_Doc,_Meta} = Func,Acc)->
        Members = maps:get(Group,Acc,[]),
        Acc#{Group=>[Func| Members]} end,#{},lists:sort(FDocs)),
    lists:map(fun ({{_,F,A} = Group,Members})->
        Signatures = lists:flatmap(fun render_signature/1,lists:reverse(Members)),
        case lists:search(fun ({_,_,_,Doc,_})->
            Doc =/= #{} end,Members) of
            {value,{_,_,_,Doc,_Meta}}->
                render_headers_and_docs(Signatures,get_local_doc({F,A},Doc),D,Config);
            false->
                case lists:keyfind(Group,1,Docs) of
                    false->
                        render_headers_and_docs(Signatures,get_local_doc({F,A},none),D,Config);
                    {_,_,_,Doc,_}->
                        render_headers_and_docs(Signatures,get_local_doc({F,A},Doc),D,Config)
                end
        end end,maps:to_list(Grouping)).

render_signature({{_Type,_F,_A},_Anno,_Sigs,_Docs,#{signature:=Specs} = Meta}) ->
    lists:flatmap(fun (ASTSpec)->
        PPSpec = erl_pp:attribute(ASTSpec,[{encoding,utf8}]),
        Spec = case ASTSpec of
            {_Attribute,_Line,opaque,_}->
                hd(string:split(PPSpec,"::"));
            _->
                PPSpec
        end,
        BinSpec = unicode:characters_to_binary(string:trim(Spec,trailing,"\n")),
        [{pre,[],[{em,[],BinSpec}]}| render_meta(Meta)] end,Specs);
render_signature({{_Type,_F,_A},_Anno,Sigs,_Docs,Meta}) ->
    lists:flatmap(fun (Sig)->
        [{h2,[],[<<"  "/utf8,Sig/binary>>]}| render_meta(Meta)] end,Sigs).

render_meta(M) ->
    case render_meta_(M) of
        []->
            [];
        Meta->
            [[{dl,[],Meta}]]
    end.

render_meta_(#{since:=Vsn} = M) ->
    [{dt,[],<<"Since">>}, {dd,[],[Vsn]}| render_meta_(maps:remove(since,M))];
render_meta_(#{deprecated:=Depr} = M) ->
    [{dt,[],<<"Deprecated">>}, {dd,[],[Depr]}| render_meta_(maps:remove(deprecated,M))];
render_meta_(_) ->
    [].

render_headers_and_docs(Headers,DocContents,D,Config) ->
    render_headers_and_docs(Headers,DocContents,init_config(D,Config)).

render_headers_and_docs(Headers,DocContents,#config{} = Config) ->
    ["\n", render_docs(lists:flatmap(fun (Header)->
        [{br,[],[]}, Header] end,Headers),Config), "\n", render_docs(DocContents,2,Config)].

render_signature_listing(Module,Type,#docs_v1{docs = Docs} = D,Config) ->
    Slogan = [{h2,[],[<<"\t",(atom_to_binary(Module))/binary>>]}, {br,[],[]}],
    case lists:filter(fun ({{T,_,_},_Anno,_Sig,_Doc,_Meta})->
        Type =:= T end,Docs) of
        []->
            render_docs(Slogan ++ [<<"There are no ",(atom_to_binary(Type))/binary,"s in this module">>],D,Config);
        Headers->
            Hdr = lists:flatmap(fun (Header)->
                [{br,[],[]}, render_signature(Header)] end,Headers),
            render_docs(Slogan ++ [{p,[],[<<"These ",(atom_to_binary(Type))/binary,"s are documented in this module:">>]}, {br,[],[]}, Hdr],D,Config)
    end.

render_typecb_docs([],_D) ->
    {error,type_missing};
render_typecb_docs(TypeCBs,#config{} = D)
    when is_list(TypeCBs)->
    [(render_typecb_docs(TypeCB,D)) || TypeCB <- TypeCBs];
render_typecb_docs({{_,F,A},_,_Sig,Docs,_Meta} = TypeCB,#config{} = D) ->
    render_headers_and_docs(render_signature(TypeCB),get_local_doc({F,A},Docs),D).

render_typecb_docs(Docs,D,Config) ->
    render_typecb_docs(Docs,init_config(D,Config)).

render_docs(DocContents,#config{} = Config) ->
    render_docs(DocContents,0,Config).

render_docs(DocContents,D,Config)
    when is_map(Config)->
    render_docs(DocContents,0,init_config(D,Config));
render_docs(DocContents,Ind,D = #config{})
    when is_integer(Ind)->
    init_ansi(D),
    try {Doc,_} = trimnl(render_docs(DocContents,[],0,Ind,D)),
    Doc
        after clean_ansi() end.

init_config(D,Config) ->
    DefaultOpts = io:getopts(),
    DefaultEncoding = proplists:get_value(encoding,DefaultOpts,latin1),
    Columns = case maps:find(columns,Config) of
        error->
            case io:columns() of
                {ok,C}->
                    C;
                _->
                    80
            end;
        {ok,C}->
            C
    end,
    #config{docs = D,encoding = maps:get(encoding,Config,DefaultEncoding),ansi = maps:get(ansi,Config,undefined),columns = Columns}.

render_docs(Elems,State,Pos,Ind,D)
    when is_list(Elems)->
    lists:mapfoldl(fun (Elem,P)->
        render_docs(Elem,State,P,Ind,D) end,Pos,Elems);
render_docs(Elem,State,Pos,Ind,D) ->
    render_element(Elem,State,Pos,Ind,D).

-spec(render_element(Elem::chunk_element(),Stack::[chunk_element_type()],Pos::non_neg_integer(),Indent::non_neg_integer(),Config::#config{}) -> {unicode:chardata(),Pos::non_neg_integer()}).

render_element({IgnoreMe,_,Content},State,Pos,Ind,D)
    when IgnoreMe =:= a->
    render_docs(Content,State,Pos,Ind,D);
render_element({h1,_,Content},State,0 = Pos,_Ind,D) ->
    trimnlnl(render_element({code,[],[{em,[],Content}]},State,Pos,0,D));
render_element({h2,_,Content},State,0 = Pos,_Ind,D) ->
    trimnlnl(render_element({em,[],Content},State,Pos,0,D));
render_element({h3,_,Content},State,Pos,_Ind,D)
    when Pos =< 2->
    trimnlnl(render_element({code,[],Content},State,Pos,2,D));
render_element({pre,_Attr,_Content} = E,State,Pos,Ind,D)
    when Pos > Ind->
    {Docs,NewPos} = render_element(E,State,0,Ind,D),
    {["\n\n", Docs],NewPos};
render_element({Elem,_Attr,_Content} = E,State,Pos,Ind,D)
    when Pos > Ind,
     not (Elem =:= a orelse Elem =:= code orelse Elem =:= i orelse Elem =:= em)->
    {Docs,NewPos} = render_element(E,State,0,Ind,D),
    {["\n", Docs],NewPos};
render_element({'div',[{class,What}],Content},State,Pos,Ind,D) ->
    {Docs,_} = render_docs(Content,['div'| State],0,Ind + 2,D),
    trimnlnl([pad(Ind - Pos), string:titlecase(What), ":\n", Docs]);
render_element({Tag,_,Content},State,Pos,Ind,D)
    when Tag =:= p;
    Tag =:= 'div'->
    trimnlnl(render_docs(Content,[Tag| State],Pos,Ind,D));
render_element(Elem,State,Pos,Ind,D)
    when Pos < Ind->
    {Docs,NewPos} = render_element(Elem,State,Ind,Ind,D),
    {[pad(Ind - Pos), Docs],NewPos};
render_element({code,_,Content},[pre| _] = State,Pos,Ind,D) ->
    render_docs(Content,[code| State],Pos,Ind,D);
render_element({code,_,Content},State,Pos,Ind,D) ->
    Underline = sansi(underline),
    {Docs,NewPos} = render_docs(Content,[code| State],Pos,Ind,D),
    {[Underline, Docs, ransi(underline)],NewPos};
render_element({i,_,Content},State,Pos,Ind,D) ->
    render_docs(Content,State,Pos,Ind,D);
render_element({br,[],[]},_State,Pos,_Ind,_D) ->
    {"",Pos};
render_element({em,_,Content},State,Pos,Ind,D) ->
    Bold = sansi(bold),
    {Docs,NewPos} = render_docs(Content,State,Pos,Ind,D),
    {[Bold, Docs, ransi(bold)],NewPos};
render_element({pre,_,Content},State,Pos,Ind,D) ->
    trimnlnl(render_docs(Content,[pre| State],Pos,Ind + 2,D));
render_element({ul,[{class,<<"types">>}],Content},State,_Pos,Ind,D) ->
    {Docs,_} = render_docs(Content,[types| State],0,Ind + 2,D),
    trimnlnl(["Types:\n", Docs]);
render_element({li,Attr,Content},[types| _] = State,Pos,Ind,C) ->
    Doc = case {proplists:get_value(name,Attr),proplists:get_value(class,Attr)} of
        {undefined,Class}
            when Class =:= undefined;
            Class =:= <<"type">>->
            render_docs(Content,[type| State],Pos,Ind,C);
        {_,<<"description">>}->
            render_docs(Content,[type| State],Pos,Ind + 2,C);
        {Name,_}->
            case render_type_signature(binary_to_atom(Name),C) of
                undefined
                    when Content =:= []->
                    {["-type ", Name, "() :: term()."],0};
                undefined->
                    render_docs(Content,[type| State],Pos,Ind,C);
                Type->
                    {Type,0}
            end
    end,
    trimnl(Doc);
render_element({ul,[],Content},State,Pos,Ind,D) ->
    render_docs(Content,[l| State],Pos,Ind,D);
render_element({ol,[],Content},State,Pos,Ind,D) ->
    render_docs(Content,[l| State],Pos,Ind,D);
render_element({li,[],Content},[l| _] = State,Pos,Ind,D) ->
    Bullet = get_bullet(State,D#config.encoding),
    BulletLen = string:length(Bullet),
    {Docs,_NewPos} = render_docs(Content,[li| State],Pos + BulletLen,Ind + BulletLen,D),
    trimnlnl([Bullet, Docs]);
render_element({dl,_,Content},State,Pos,Ind,D) ->
    render_docs(Content,[dl| State],Pos,Ind,D);
render_element({dt,_,Content},[dl| _] = State,Pos,Ind,D) ->
    Underline = sansi(underline),
    {Docs,_NewPos} = render_docs(Content,[li| State],Pos,Ind,D),
    {[Underline, Docs, ransi(underline), ":", "\n"],0};
render_element({dd,_,Content},[dl| _] = State,Pos,Ind,D) ->
    trimnlnl(render_docs(Content,[li| State],Pos,Ind + 2,D));
render_element(B,State,Pos,Ind,#config{columns = Cols})
    when is_binary(B)->
    case lists:member(pre,State) of
        true->
            Pre = string:replace(B,"\n",[nlpad(Ind)],all),
            {Pre,Pos + lastline(Pre)};
        _->
            render_words(split_to_words(B),State,Pos,Ind,[[]],Cols)
    end;
render_element({Tag,Attr,Content},State,Pos,Ind,D) ->
    case lists:member(Tag,[a, p, 'div', br, h1, h2, h3, i, em, pre, code, ul, ol, li, dl, dt, dd]) of
        true->
            throw({unhandled_element,Tag,Attr,Content});
        false->
            ok
    end,
    render_docs(Content,State,Pos,Ind,D).

render_words(Words,[_, types| State],Pos,Ind,Acc,Cols) ->
    render_words(Words,State,Pos,Ind + 2,Acc,Cols);
render_words([Word| T],State,Pos,Ind,Acc,Cols)
    when is_binary(Word)->
    WordLength = string:length(Word),
    NewPos = WordLength + Pos,
    IsPunct = is_tuple(re:run(Word,"^\\W$",[unicode])),
    if NewPos > Cols - 10 - Ind,
    Word =/= <<>>,
     not IsPunct ->
        render_words(T,State,WordLength + Ind + 1,Ind,[[[nlpad(Ind), Word]]| Acc],Cols);true ->
        [Line| LineAcc] = Acc,
        NewPosSpc = NewPos + 1,
        render_words(T,State,NewPosSpc,Ind,[[Word| Line]| LineAcc],Cols) end;
render_words([],_State,Pos,_Ind,Acc,_Cols) ->
    Lines = lists:map(fun (RevLine)->
        Line = lists:reverse(RevLine),
        lists:join($ ,Line) end,lists:reverse(Acc)),
    {iolist_to_binary(Lines),Pos}.

render_type_signature(Name,#config{docs = #docs_v1{metadata = #{types:=AllTypes}}}) ->
    case [Type || Type = {TName,_} <- maps:keys(AllTypes),TName =:= Name] of
        []->
            undefined;
        Types->
            [(erl_pp:attribute(maps:get(Type,AllTypes))) || Type <- Types]
    end.

pad(N) ->
    pad(N,"").

nlpad(N) ->
    pad(N,"\n").

pad(N,Extra) ->
    Pad = lists:duplicate(N," "),
    case ansi() of
        undefined->
            [Extra, Pad];
        Ansi->
            ["\e[0m", Extra, Pad, Ansi]
    end.

get_bullet(_State,latin1) ->
    <<" * ">>;
get_bullet(State,unicode) ->
    case length([l || l <- State]) of
        Level
            when Level > 4->
            get_bullet(State,latin1);
        Level->
            lists:nth(Level,[<<" • "/utf8>>, <<" ￮ "/utf8>>, <<" ◼ "/utf8>>, <<" ◻ "/utf8>>])
    end.

lastline(Str) ->
    LastStr = case string:find(Str,"\n",trailing) of
        nomatch->
            Str;
        Match->
            tl(string:next_codepoint(Match))
    end,
    string:length(LastStr).

split_to_words(B) ->
    binary:split(B,[<<" ">>],[global]).

trimnlnl({Chars,_Pos}) ->
    nl(nl(string:trim(Chars,trailing,"\n")));
trimnlnl(Chars) ->
    nl(nl(string:trim(Chars,trailing,"\n"))).

trimnl({Chars,_Pos}) ->
    nl(string:trim(Chars,trailing,"\n")).

nl({Chars,_Pos}) ->
    nl(Chars);
nl(Chars) ->
    {[Chars, "\n"],0}.

init_ansi(#config{ansi = undefined,io_opts = Opts}) ->
    case {application:get_env(kernel,shell_docs_ansi),proplists:is_defined(echo,Opts) andalso proplists:is_defined(expand_fun,Opts),os:type()} of
        {{ok,false},_,_}->
            put(ansi,noansi);
        {{ok,true},_,_}->
            put(ansi,[]);
        {_,_,{win32,_}}->
            put(ansi,noansi);
        {_,true,_}->
            put(ansi,[]);
        {_,false,_}->
            put(ansi,noansi)
    end;
init_ansi(#config{ansi = true}) ->
    put(ansi,[]);
init_ansi(#config{ansi = false}) ->
    put(ansi,noansi).

clean_ansi() ->
    case get(ansi) of
        []->
            erase(ansi);
        noansi->
            erase(ansi)
    end,
    ok.

sansi(Type) ->
    sansi(Type,get(ansi)).

sansi(_Type,noansi) ->
    [];
sansi(Type,Curr) ->
    put(ansi,[Type| Curr]),
    ansi(get(ansi)).

ransi(Type) ->
    ransi(Type,get(ansi)).

ransi(_Type,noansi) ->
    [];
ransi(Type,Curr) ->
    put(ansi,proplists:delete(Type,Curr)),
    case ansi(get(ansi)) of
        undefined->
            "\e[0m";
        Ansi->
            Ansi
    end.

ansi() ->
    ansi(get(ansi)).

ansi(noansi) ->
    undefined;
ansi(Curr) ->
    case lists:usort(Curr) of
        []->
            undefined;
        [bold]->
            "\e[;1m";
        [underline]->
            "\e[;;4m";
        [bold, underline]->
            "\e[;1;4m"
    end.