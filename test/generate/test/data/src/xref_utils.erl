-file("xref_utils.erl", 1).

-module(xref_utils).

-compile({no_auto_import,[{error,1}]}).

-export([xset/2]).

-export([is_directory/1, file_info/1, fa_to_mfa/2]).

-export([is_string/2, is_path/1]).

-export([module_filename/2, application_filename/1, application_filename/2]).

-export([release_directory/3, select_application_directories/2, filename_to_application/1, select_last_application_version/1, split_filename/2, scan_directory/4, list_path/2]).

-export([predefined_functions/0, is_funfun/3, is_builtin/3]).

-export([is_static_function/2, is_abstract_module/1]).

-export([closure/1, components/1, condensation/1, path/2, use/2, call/2]).

-export([regexpr/2]).

-export([relation_to_graph/1]).

-export([find_beam/1]).

-export([options/2]).

-export([format_error/1]).

-import(lists, [append/1, delete/2, filter/2, foldl/3, foreach/2, keydelete/3, keysearch/3, keysort/2, last/1, map/2, member/2, reverse/1, sort/1]).

-import(sofs, [difference/2, domain/1, family/1, family_to_relation/1, from_external/2, from_term/2, intersection/2, partition/2, relation/1, relation_to_family/1, restriction/2, set/1, to_external/1, type/1]).

-file("/usr/lib/erlang/lib/kernel-7.2/include/file.hrl", 1).

-record(file_info,{size::non_neg_integer()|undefined,type::device|directory|other|regular|symlink|undefined,access::read|write|read_write|none|undefined,atime::file:date_time()|non_neg_integer()|undefined,mtime::file:date_time()|non_neg_integer()|undefined,ctime::file:date_time()|non_neg_integer()|undefined,mode::non_neg_integer()|undefined,links::non_neg_integer()|undefined,major_device::non_neg_integer()|undefined,minor_device::non_neg_integer()|undefined,inode::non_neg_integer()|undefined,uid::non_neg_integer()|undefined,gid::non_neg_integer()|undefined}).

-record(file_descriptor,{module::module(),data::term()}).

-file("xref_utils.erl", 63).

xset(L,T)
    when is_list(L)->
    from_external(lists:usort(L),T);
xset(S,T) ->
    from_external(S,T).

is_directory(F) ->
    case file:read_file_info(F) of
        {ok,Info}->
            Info#file_info.type =:= directory;
        {error,Error}->
            file_error(F,Error)
    end.

file_info(F) ->
    case file:read_file_info(F) of
        {ok,Info}->
            Readable = case Info#file_info.access of
                Access
                    when Access =:= read;
                    Access =:= read_write->
                    readable;
                _->
                    unreadable
            end,
            Type = case Info#file_info.type of
                directory->
                    directory;
                regular->
                    file;
                _->
                    error
            end,
            case Type of
                error->
                    error({unrecognized_file,F});
                _->
                    {ok,{F,Type,Readable,Info#file_info.mtime}}
            end;
        {error,Error}->
            file_error(F,Error)
    end.

fa_to_mfa(FAs,Mod) ->
    fa_to_mfa(FAs,Mod,[]).

fa_to_mfa([{F,A}| MFs],Mod,L) ->
    fa_to_mfa(MFs,Mod,[{Mod,F,A}| L]);
fa_to_mfa([],_Mod,L) ->
    reverse(L).

module_filename(Dir,Module) ->
    filename:join(Dir,to_list(Module) ++ code:objfile_extension()).

application_filename(AppName) ->
    to_list(AppName) ++ ".app".

application_filename(Dir,AppName) ->
    filename:join(to_list(Dir),application_filename(AppName)).

is_string([],_) ->
    false;
is_string(Term,C) ->
    is_string1(Term,C).

is_string1([H| T],C)
    when H > C->
    is_string1(T,C);
is_string1([],_) ->
    true;
is_string1(_,_) ->
    false.

is_path([S| Ss]) ->
    case is_string(S,31) of
        true->
            is_path(Ss);
        false->
            false
    end;
is_path([]) ->
    true;
is_path(_) ->
    false.

release_directory(Dir,UseLib,SubDir) ->
    SDir = subdir(Dir,"lib",UseLib),
    case file:list_dir(SDir) of
        {ok,FileNames}->
            Files = [(filename:join(SDir,File)) || File <- FileNames],
            case select_application_directories(Files,SubDir) of
                {ok,ApplDirs}->
                    {ok,list_to_atom(filename:basename(Dir)),SDir,ApplDirs};
                Error->
                    Error
            end;
        {error,Error}->
            file_error(SDir,Error)
    end.

select_application_directories(FileNames,Dir) ->
    select_application_directories(FileNames,Dir,Dir =/= [],[]).

filename_to_application(FileName) ->
    Basename = filename:basename(FileName),
    case  catch filename2appl(Basename) of
        {'EXIT',_}->
            {list_to_atom(Basename),[]};
        Split->
            Split
    end.

select_last_application_version(AppVs) ->
    TL = to_external(partition(1,relation(AppVs))),
    [(last(keysort(2,L))) || L <- TL].

-record(scan, {collected = [],errors = [],seen = [],unreadable = []}).

scan_directory(File,Recurse,Collect,Watch) ->
    Init = #scan{},
    S = find_files_dir(File,Recurse,Collect,Watch,Init),
    #scan{collected = L,errors = E,seen = J,unreadable = U} = S,
    {reverse(L),reverse(E),reverse(J),reverse(U)}.

split_filename(File,Extension) ->
    case  catch begin Dir = filename:dirname(File),
    Basename = filename:basename(File,Extension),
    {Dir,Basename ++ Extension} end of
        {'EXIT',_}->
            false;
        R->
            R
    end.

list_path(P,Extensions) ->
    list_dirs(P,1,Extensions,[],[]).

list_dirs([D| Ds],I,Exts,CL,E) ->
    Fun = fun (X,A)->
        File = filename:join(D,X),
        case is_directory(File) of
            false->
                Ext = filename:extension(X),
                case member(Ext,Exts) of
                    true->
                        M = list_to_atom(filename:basename(X,Ext)),
                        [{M,{I,D,X}}| A];
                    false->
                        A
                end;
            true->
                A;
            _Else->
                A
        end end,
    {NCL,NE} = case file:list_dir(D) of
        {ok,C0}->
            {foldl(Fun,CL,C0),E};
        {error,Error}->
            {CL,[file_error(D,Error)| E]}
    end,
    list_dirs(Ds,I + 1,Exts,NCL,NE);
list_dirs([],_I,_Exts,C,E) ->
    {C,E}.

predefined_functions() ->
    [{module_info,0}, {module_info,1}].

is_funfun(erlang,apply,2) ->
    true;
is_funfun(erlang,apply,3) ->
    true;
is_funfun(erlang,spawn,1) ->
    true;
is_funfun(erlang,spawn,2) ->
    true;
is_funfun(erlang,spawn,3) ->
    true;
is_funfun(erlang,spawn,4) ->
    true;
is_funfun(erlang,spawn_link,1) ->
    true;
is_funfun(erlang,spawn_link,2) ->
    true;
is_funfun(erlang,spawn_link,3) ->
    true;
is_funfun(erlang,spawn_link,4) ->
    true;
is_funfun(erlang,spawn_opt,2) ->
    true;
is_funfun(erlang,spawn_opt,3) ->
    true;
is_funfun(erlang,spawn_opt,4) ->
    true;
is_funfun(erlang,spawn_opt,5) ->
    true;
is_funfun(erts_debug,apply,4) ->
    true;
is_funfun(_,_,_) ->
    false.

is_builtin(erts_debug,apply,4) ->
    true;
is_builtin(M,F,A) ->
    erlang:is_builtin(M,F,A).

is_abstract_module(Attributes) ->
    case keysearch(abstract,1,Attributes) of
        {value,{abstract,true}}->
            true;
        {value,{abstract,Vals}}
            when is_list(Vals)->
            member(true,Vals);
        _->
            false
    end.

is_static_function(module_info,0) ->
    true;
is_static_function(module_info,1) ->
    true;
is_static_function(new,_) ->
    true;
is_static_function(instance,_) ->
    true;
is_static_function(_F,_A) ->
    false.

closure(S) ->
    relation_to_graph(S).

components(G) ->
    from_term(digraph_utils:cyclic_strong_components(G),[[atom]]).

condensation(G) ->
    G2 = digraph_utils:condensation(G),
    R = graph_to_relation(G2),
    true = digraph:delete(G2),
    R.

path(G,[E]) ->
    path(G,[E, E]);
path(G,P = [E1| _]) ->
    path(P,G,[[E1]]).

use(G,V) ->
    neighbours(to_external(V),G,reaching_neighbours,type(V)).

call(G,V) ->
    neighbours(to_external(V),G,reachable_neighbours,type(V)).

regexpr({regexpr,RExpr},Var) ->
    Xs = match_list(to_external(Var),RExpr),
    xset(Xs,type(Var));
regexpr({ModExpr,FunExpr,ArityExpr},Var) ->
    Type = type(Var),
    V1 = case {ModExpr,Type} of
        {{atom,Mod},[{ModType,_}]}->
            restriction(Var,xset([Mod],[ModType]));
        {{regexpr,MExpr},[{ModType,_}]}->
            Mods = match_list(to_external(domain(Var)),MExpr),
            restriction(Var,xset(Mods,[ModType]));
        {variable,_}->
            Var;
        {_,_}->
            Var
    end,
    V2 = case FunExpr of
        {atom,FunName}->
            V1L = to_external(V1),
            xset(match_one(V1L,FunName,2),Type);
        {regexpr,FExpr}->
            V1L = to_external(V1),
            xset(match_many(V1L,FExpr,2),Type);
        variable->
            V1
    end,
    case ArityExpr of
        {integer,Arity}->
            V2L = to_external(V2),
            xset(match_one(V2L,Arity,3),Type);
        {regexpr,Expr}->
            V2L = to_external(V2),
            xset(match_many(V2L,Expr,3),Type);
        variable->
            V2
    end.

relation_to_graph(S) ->
    G = digraph:new(),
    Fun = fun ({From,To})->
        digraph:add_vertex(G,From),
        digraph:add_vertex(G,To),
        digraph:add_edge(G,From,To) end,
    foreach(Fun,to_external(S)),
    G.

find_beam(Module)
    when is_atom(Module)->
    case code:which(Module) of
        non_existing->
            error({no_such_module,Module});
        preloaded->
            {Module,{_M,_Bin,File}} = {Module,code:get_object_code(Module)},
            {ok,File};
        cover_compiled->
            error({cover_compiled,Module});
        File->
            {ok,File}
    end;
find_beam(Culprit) ->
    error(badarg,[Culprit]).

options(Options,Valid) ->
    split_options(Options,[],[],[],Valid).

format_error({error,Module,Error}) ->
    Module:format_error(Error);
format_error({file_error,FileName,Reason}) ->
    io_lib:format("~ts: ~tp~n",[FileName, file:format_error(Reason)]);
format_error({unrecognized_file,FileName}) ->
    io_lib:format("~tp is neither a regular file nor a directory~n",[FileName]);
format_error({no_such_module,Module}) ->
    io_lib:format("Cannot find module ~tp using the code path~n",[Module]);
format_error({interpreted,Module}) ->
    io_lib:format("Cannot use BEAM code of interpreted module ~tp~n",[Module]);
format_error(E) ->
    io_lib:format("~tp~n",[E]).

to_list(X)
    when is_atom(X)->
    atom_to_list(X);
to_list(X)
    when is_list(X)->
    X.

select_application_directories([FileName| FileNames],Dir,Flag,L) ->
    case is_directory(FileName) of
        true->
            File = filename:basename(FileName),
            {Name,Vsn} = filename_to_application(File),
            ApplDir = {Name,Vsn,subdir(FileName,Dir,Flag)},
            select_application_directories(FileNames,Dir,Flag,[ApplDir| L]);
        false->
            select_application_directories(FileNames,Dir,Flag,L);
        Error->
            Error
    end;
select_application_directories([],_Dir,_Flag,L) ->
    {ok,reverse(L)}.

subdir(Dir,_,false) ->
    Dir;
subdir(Dir,SubDir,true) ->
    EDir = filename:join(Dir,SubDir),
    case is_directory(EDir) of
        true->
            EDir;
        _FalseOrError->
            Dir
    end.

filename2appl(File) ->
    [ApplName, V] = string:split(File,"-",trailing),
    true = string:length(V) > 0,
    VsnT = string:lexemes(V,"."),
    Vsn = [(list_to_integer(Vsn)) || Vsn <- VsnT],
    {list_to_atom(ApplName),Vsn}.

find_files_dir(Dir,Recurse,Collect,Watch,L) ->
    case file:list_dir(Dir) of
        {ok,Files}->
            find_files(sort(Files),Dir,Recurse,Collect,Watch,L);
        {error,Error}->
            L#scan{errors = [file_error(Dir,Error)| L#scan.errors]}
    end.

find_files([F| Fs],Dir,Recurse,Collect,Watch,L) ->
    File = filename:join(Dir,F),
    L1 = case file_info(File) of
        {ok,{_,directory,readable,_}}
            when Recurse->
            find_files_dir(File,Recurse,Collect,Watch,L);
        {ok,{_,directory,_,_}}->
            L;
        Info->
            #scan{collected = B,errors = E,seen = J,unreadable = U} = L,
            Ext = filename:extension(File),
            C = member(Ext,Collect),
            case C of
                true->
                    case Info of
                        {ok,{_,file,readable,_}}->
                            L#scan{collected = [{Dir,F}| B]};
                        {ok,{_,file,unreadable,_}}->
                            L#scan{unreadable = [File| U]};
                        Error->
                            L#scan{errors = [Error| E]}
                    end;
                false->
                    case member(Ext,Watch) of
                        true->
                            L#scan{seen = [File| J]};
                        false->
                            L
                    end
            end
    end,
    find_files(Fs,Dir,Recurse,Collect,Watch,L1);
find_files([],_Dir,_Recurse,_Collect,_Watch,L) ->
    L.

graph_to_relation(G) ->
    Fun = fun (E)->
        {_E,V1,V2,_Label} = digraph:edge(G,E),
        {V1,V2} end,
    from_term(map(Fun,digraph:edges(G)),[{[atom],[atom]}]).

path([E1, E2| P],G,L) ->
    case digraph:get_short_path(G,E1,E2) of
        false->
            false;
        [_V| Vs]->
            path([E2| P],G,[Vs| L])
    end;
path([_],_G,L) ->
    append(reverse(L)).

neighbours(Vs,G,Fun,VT) ->
    neighbours(Vs,G,Fun,VT,[]).

neighbours([V| Vs],G,Fun,VT,L) ->
    Ns = digraph_utils:Fun([V],G),
    neighbours(Ns,G,Fun,VT,L,V,Vs);
neighbours([],_G,_Fun,[VT],L) ->
    xset(L,[{VT,VT}]).

neighbours([N| Ns],G,Fun,VT,L,V,Vs)
    when Fun =:= reachable_neighbours->
    neighbours(Ns,G,Fun,VT,[{V,N}| L],V,Vs);
neighbours([N| Ns],G,Fun,VT,L,V,Vs) ->
    neighbours(Ns,G,Fun,VT,[{N,V}| L],V,Vs);
neighbours([],G,Fun,VT,L,_V,Vs) ->
    neighbours(Vs,G,Fun,VT,L).

match_list(L,RExpr) ->
    {ok,Expr} = re:compile(RExpr,[unicode]),
    filter(fun (E)->
        match(E,Expr) end,L).

match_one(VarL,Con,Col) ->
    select_each(VarL,fun (E)->
        Con =:= element(Col,E) end).

match_many(VarL,RExpr,Col) ->
    {ok,Expr} = re:compile(RExpr,[unicode]),
    select_each(VarL,fun (E)->
        match(element(Col,E),Expr) end).

match(I,Expr)
    when is_integer(I)->
    S = integer_to_list(I),
    {match,[{0,length(S)}]} =:= re:run(S,Expr,[{capture,first}]);
match(A,Expr)
    when is_atom(A)->
    S = atom_to_list(A),
    case re:run(S,Expr,[{capture,first}]) of
        {match,[{0,Size}]}->
            Size =:= byte_size(unicode:characters_to_binary(S));
        _->
            false
    end.

select_each([{Mod,Funs}| L],Pred) ->
    case filter(Pred,Funs) of
        []->
            select_each(L,Pred);
        NFuns->
            [{Mod,NFuns}| select_each(L,Pred)]
    end;
select_each([],_Pred) ->
    [].

split_options([O| Os],A,P,I,V)
    when is_atom(O)->
    split_options(Os,[O| A],P,I,V);
split_options([O = {Name,_}| Os],A,P,I,V)
    when is_atom(Name)->
    split_options(Os,A,[O| P],I,V);
split_options([O| Os],A,P,I,V) ->
    split_options(Os,A,P,[O| I],V);
split_options([],A,P,I,V) ->
    Atoms = to_external(set(A)),
    Pairs = to_external(relation_to_family(relation(P))),
    option_values(V,Atoms,Pairs,I,[]);
split_options(O,A,P,I,V) ->
    split_options([O],A,P,I,V).

option_values([O| Os],A,P,I,Vs)
    when is_atom(O)->
    option_values(Os,delete(O,A),P,I,[member(O,A)| Vs]);
option_values([{Name,AllowedValues}| Os],A,P,I,Vs) ->
    case keysearch(Name,1,P) of
        {value,{_,Values}}->
            option_value(Name,AllowedValues,Values,A,P,I,Vs,Os);
        false
            when AllowedValues =:= []->
            option_values(Os,A,P,I,[[]| Vs]);
        false->
            [Default| _] = AllowedValues,
            option_values(Os,A,P,I,[[Default]| Vs])
    end;
option_values([],A,P,Invalid,Values) ->
    I2 = to_external(family_to_relation(family(P))),
    {reverse(Values),Invalid ++ A ++ I2}.

option_value(Name,[_Deflt, Fun],Vals,A,P,I,Vs,Os)
    when is_function(Fun)->
    P1 = keydelete(Name,1,P),
    case Fun(Vals) of
        true->
            option_values(Os,A,P1,I,[Vals| Vs]);
        false->
            option_values(Os,A,[{Name,Vals}| P1],I,[[]| Vs])
    end;
option_value(Name,AllowedValues,Values,A,P,I,Vs,Os) ->
    P1 = keydelete(Name,1,P),
    VS = set(Values),
    AVS = set(AllowedValues),
    V1 = to_external(intersection(VS,AVS)),
    {V,NP} = case to_external(difference(VS,AVS)) of
        _
            when AllowedValues =:= []->
            {Values,P1};
        []->
            {V1,P1};
        _
            when length(AllowedValues) =:= 1->
            {Values,P1};
        I1->
            {V1,[{Name,I1}| P1]}
    end,
    option_values(Os,A,NP,I,[V| Vs]).

file_error(File,Error) ->
    error({file_error,File,Error}).

error(Error) ->
    {error,xref_utils,Error}.