-file("make.erl", 1).

-module(make).

-export([all_or_nothing/0, all/0, all/1, files/1, files/2]).

-file("/usr/lib/erlang/lib/kernel-7.2/include/file.hrl", 1).

-record(file_info,{size::non_neg_integer()|undefined,type::device|directory|other|regular|symlink|undefined,access::read|write|read_write|none|undefined,atime::file:date_time()|non_neg_integer()|undefined,mtime::file:date_time()|non_neg_integer()|undefined,ctime::file:date_time()|non_neg_integer()|undefined,mode::non_neg_integer()|undefined,links::non_neg_integer()|undefined,major_device::non_neg_integer()|undefined,minor_device::non_neg_integer()|undefined,inode::non_neg_integer()|undefined,uid::non_neg_integer()|undefined,gid::non_neg_integer()|undefined}).

-record(file_descriptor,{module::module(),data::term()}).

-file("make.erl", 31).

all_or_nothing() ->
    case all() of
        up_to_date->
            up_to_date;
        error->
            halt(1)
    end.

all() ->
    all([]).

all(Options) ->
    run_emake(undefined,Options).

files(Fs) ->
    files(Fs,[]).

files(Fs0,Options) ->
    Fs = [(filename:rootname(F,".erl")) || F <- Fs0],
    run_emake(Fs,Options).

run_emake(Mods,Options) ->
    {MakeOpts,CompileOpts} = sort_options(Options,[],[]),
    Emake = get_emake(Options),
    case normalize_emake(Emake,Mods,CompileOpts) of
        Files
            when is_list(Files)->
            do_make_files(Files,MakeOpts);
        error->
            error
    end.

do_make_files(Fs,Opts) ->
    process(Fs,lists:member(noexec,Opts),load_opt(Opts)).

sort_options([{emake,_} = H| T],Make,Comp) ->
    sort_options(T,[H| Make],Comp);
sort_options([H| T],Make,Comp) ->
    case lists:member(H,[noexec, load, netload, noload, emake]) of
        true->
            sort_options(T,[H| Make],Comp);
        false->
            sort_options(T,Make,[H| Comp])
    end;
sort_options([],Make,Comp) ->
    {Make,lists:reverse(Comp)}.

normalize_emake(EmakeRaw,Mods,Opts) ->
    case EmakeRaw of
        {ok,Emake}
            when Mods =:= undefined->
            transform(Emake,Opts,[],[]);
        {ok,Emake}
            when is_list(Mods)->
            ModsOpts = transform(Emake,Opts,[],[]),
            ModStrings = [(coerce_2_list(M)) || M <- Mods],
            get_opts_from_emakefile(ModsOpts,ModStrings,Opts,[]);
        {error,enoent}
            when Mods =:= undefined->
            CwdMods = [(filename:rootname(F)) || F <- filelib:wildcard("*.erl")],
            [{CwdMods,Opts}];
        {error,enoent}
            when is_list(Mods)->
            [{Mods,Opts}];
        {error,Error}->
            io:format("make: Trouble reading 'Emakefile':~n~tp~n",[Error]),
            error
    end.

get_emake(Opts) ->
    case proplists:get_value(emake,Opts,false) of
        false->
            file:consult('Emakefile');
        OptsEmake->
            {ok,OptsEmake}
    end.

transform([{Mod,ModOpts}| Emake],Opts,Files,Already) ->
    case expand(Mod,Already) of
        []->
            transform(Emake,Opts,Files,Already);
        Mods->
            transform(Emake,Opts,[{Mods,ModOpts ++ Opts}| Files],Mods ++ Already)
    end;
transform([Mod| Emake],Opts,Files,Already) ->
    case expand(Mod,Already) of
        []->
            transform(Emake,Opts,Files,Already);
        Mods->
            transform(Emake,Opts,[{Mods,Opts}| Files],Mods ++ Already)
    end;
transform([],_Opts,Files,_Already) ->
    lists:reverse(Files).

expand(Mod,Already)
    when is_atom(Mod)->
    expand(atom_to_list(Mod),Already);
expand(Mods,Already)
    when is_list(Mods),
     not is_integer(hd(Mods))->
    lists:concat([(expand(Mod,Already)) || Mod <- Mods]);
expand(Mod,Already) ->
    case lists:member($*,Mod) of
        true->
            Fun = fun (F,Acc)->
                M = filename:rootname(F),
                case lists:member(M,Already) of
                    true->
                        Acc;
                    false->
                        [M| Acc]
                end end,
            lists:foldl(Fun,[],filelib:wildcard(Mod ++ ".erl"));
        false->
            Mod2 = filename:rootname(Mod,".erl"),
            case lists:member(Mod2,Already) of
                true->
                    [];
                false->
                    [Mod2]
            end
    end.

get_opts_from_emakefile([{MakefileMods,O}| Rest],Mods,Opts,Result) ->
    case members(Mods,MakefileMods,[],Mods) of
        {[],_}->
            get_opts_from_emakefile(Rest,Mods,Opts,Result);
        {I,RestOfMods}->
            get_opts_from_emakefile(Rest,RestOfMods,Opts,[{I,O}| Result])
    end;
get_opts_from_emakefile([],[],_Opts,Result) ->
    Result;
get_opts_from_emakefile([],RestOfMods,Opts,Result) ->
    [{RestOfMods,Opts}| Result].

members([H| T],MakefileMods,I,Rest) ->
    case lists:member(H,MakefileMods) of
        true->
            members(T,MakefileMods,[H| I],lists:delete(H,Rest));
        false->
            members(T,MakefileMods,I,Rest)
    end;
members([],_MakefileMods,I,Rest) ->
    {I,Rest}.

load_opt(Opts) ->
    case lists:member(netload,Opts) of
        true->
            netload;
        false->
            case lists:member(load,Opts) of
                true->
                    load;
                _->
                    noload
            end
    end.

process([{[],_Opts}| Rest],NoExec,Load) ->
    process(Rest,NoExec,Load);
process([{[H| T],Opts}| Rest],NoExec,Load) ->
    case recompilep(coerce_2_list(H),NoExec,Load,Opts) of
        error->
            error;
        _->
            process([{T,Opts}| Rest],NoExec,Load)
    end;
process([],_NoExec,_Load) ->
    up_to_date.

recompilep(File,NoExec,Load,Opts) ->
    ObjName = lists:append(filename:basename(File),code:objfile_extension()),
    ObjFile = case lists:keysearch(outdir,1,Opts) of
        {value,{outdir,OutDir}}->
            filename:join(coerce_2_list(OutDir),ObjName);
        false->
            ObjName
    end,
    case exists(ObjFile) of
        true->
            recompilep1(File,NoExec,Load,Opts,ObjFile);
        false->
            recompile(File,NoExec,Load,Opts)
    end.

recompilep1(File,NoExec,Load,Opts,ObjFile) ->
    {ok,Erl} = file:read_file_info(lists:append(File,".erl")),
    {ok,Obj} = file:read_file_info(ObjFile),
    recompilep1(Erl,Obj,File,NoExec,Load,Opts).

recompilep1(#file_info{mtime = Te},#file_info{mtime = To},File,NoExec,Load,Opts)
    when Te > To->
    recompile(File,NoExec,Load,Opts);
recompilep1(_Erl,#file_info{mtime = To},File,NoExec,Load,Opts) ->
    recompile2(To,File,NoExec,Load,Opts).

recompile2(ObjMTime,File,NoExec,Load,Opts) ->
    IncludePath = include_opt(Opts),
    case check_includes(lists:append(File,".erl"),IncludePath,ObjMTime) of
        true->
            recompile(File,NoExec,Load,Opts);
        false->
            false
    end.

include_opt([{i,Path}| Rest]) ->
    [Path| include_opt(Rest)];
include_opt([_First| Rest]) ->
    include_opt(Rest);
include_opt([]) ->
    [].

recompile(File,true,_Load,_Opts) ->
    io:format("Out of date: ~ts\n",[File]);
recompile(File,false,Load,Opts) ->
    io:format("Recompile: ~ts\n",[File]),
    case compile:file(File,[report_errors, report_warnings| Opts]) of
        Ok
            when is_tuple(Ok),
            element(1,Ok) == ok->
            maybe_load(element(2,Ok),Load,Opts);
        _Error->
            error
    end.

maybe_load(_Mod,noload,_Opts) ->
    ok;
maybe_load(Mod,Load,Opts) ->
    case compile:output_generated(Opts) of
        true->
            Dir = proplists:get_value(outdir,Opts,"."),
            do_load(Dir,Mod,Load);
        false->
            io:format("** Warning: No object file created - nothing loa" "ded **~n"),
            ok
    end.

do_load(Dir,Mod,load) ->
    code:purge(Mod),
    case code:load_abs(filename:join(Dir,Mod),Mod) of
        {module,Mod}->
            {ok,Mod};
        Other->
            Other
    end;
do_load(Dir,Mod,netload) ->
    Obj = atom_to_list(Mod) ++ code:objfile_extension(),
    Fname = filename:join(Dir,Obj),
    case file:read_file(Fname) of
        {ok,Bin}->
            rpc:eval_everywhere(code,load_binary,[Mod, Fname, Bin]),
            {ok,Mod};
        Other->
            Other
    end.

exists(File) ->
    case file:read_file_info(File) of
        {ok,_}->
            true;
        _->
            false
    end.

coerce_2_list(X)
    when is_atom(X)->
    atom_to_list(X);
coerce_2_list(X) ->
    X.

check_includes(File,IncludePath,ObjMTime) ->
    {ok,Cwd} = file:get_cwd(),
    Path = [Cwd, filename:dirname(File)| IncludePath],
    case epp:open(File,Path,[]) of
        {ok,Epp}->
            check_includes2(Epp,File,ObjMTime);
        _Error->
            false
    end.

check_includes2(Epp,File,ObjMTime) ->
    A1 = erl_anno:new(1),
    case epp:parse_erl_form(Epp) of
        {ok,{attribute,A1,file,{File,A1}}}->
            check_includes2(Epp,File,ObjMTime);
        {ok,{attribute,A1,file,{IncFile,A1}}}->
            case file:read_file_info(IncFile) of
                {ok,#file_info{mtime = MTime}}
                    when MTime > ObjMTime->
                    epp:close(Epp),
                    true;
                _->
                    check_includes2(Epp,File,ObjMTime)
            end;
        {ok,_}->
            check_includes2(Epp,File,ObjMTime);
        {eof,_}->
            epp:close(Epp),
            false;
        {error,_Error}->
            check_includes2(Epp,File,ObjMTime);
        {warning,_Warning}->
            check_includes2(Epp,File,ObjMTime)
    end.