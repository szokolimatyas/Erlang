-file("dialyzer_codeserver.erl", 1).

-module(dialyzer_codeserver).

-export([delete/1, store_temp_contracts/4, give_away/2, finalize_contracts/1, finalize_exported_types/2, finalize_records/1, get_contracts/1, get_callbacks/1, get_exported_types/1, extract_exported_types/1, get_exports/1, get_records_table/1, extract_records/1, get_next_core_label/1, get_temp_contracts/2, all_temp_modules/1, store_contracts/4, get_temp_exported_types/1, get_temp_records_table/1, lookup_temp_mod_records/2, insert/3, insert_exports/2, insert_temp_exported_types/2, insert_fun_meta_info/2, is_exported/2, lookup_mod_code/2, lookup_mfa_code/2, lookup_mfa_var_label/2, lookup_mod_records/2, lookup_mod_contracts/2, lookup_mfa_contract/2, lookup_meta_info/2, new/0, set_next_core_label/2, store_temp_records/3, translate_fake_file/3]).

-export_type([codeserver/0, fun_meta_info/0, contracts/0]).

-file("dialyzer.hrl", 1).

-type(dial_ret()::0|1|2).

-type(dial_warn_tag()::warn_return_no_exit|warn_return_only_exit|warn_not_called|warn_non_proper_list|warn_matching|warn_opaque|warn_fun_app|warn_failing_call|warn_bin_construction|warn_contract_types|warn_contract_syntax|warn_contract_not_equal|warn_contract_subtype|warn_contract_supertype|warn_callgraph|warn_umatched_return|warn_race_condition|warn_behaviour|warn_contract_range|warn_undefined_callbacks|warn_unknown|warn_map_construction).

-type(file_line()::{file:filename(),non_neg_integer()}).

-type(dial_warning()::{dial_warn_tag(),file_line(),{atom(),[term()]}}).

-type(m_or_mfa()::module()|mfa()).

-type(warning_info()::{file:filename(),non_neg_integer(),m_or_mfa()}).

-type(raw_warning()::{dial_warn_tag(),warning_info(),{atom(),[term()]}}).

-type(dial_error()::any()).

-type(anal_type()::succ_typings|plt_build).

-type(anal_type1()::anal_type()|plt_add|plt_check|plt_remove).

-type(contr_constr()::{subtype,erl_types:erl_type(),erl_types:erl_type()}).

-type(contract_pair()::{erl_types:erl_type(),[contr_constr()]}).

-type(dial_define()::{atom(),term()}).

-type(dial_option()::{atom(),term()}).

-type(dial_options()::[dial_option()]).

-type(fopt()::basename|fullpath).

-type(format()::formatted|raw).

-type(iopt()::boolean()).

-type(label()::non_neg_integer()).

-type(dial_warn_tags()::ordsets:ordset(dial_warn_tag())).

-type(rep_mode()::quiet|normal|verbose).

-type(start_from()::byte_code|src_code).

-type(mfa_or_funlbl()::label()|mfa()).

-type(solver()::v1|v2).

-type(doc_plt()::undefined|dialyzer_plt:plt()).

-record(analysis,{analysis_pid::pid()|undefined,type = succ_typings::anal_type(),defines = []::[dial_define()],doc_plt::doc_plt(),files = []::[file:filename()],include_dirs = []::[file:filename()],start_from = byte_code::start_from(),plt::dialyzer_plt:plt(),use_contracts = true::boolean(),race_detection = false::boolean(),behaviours_chk = false::boolean(),timing = false::boolean()|debug,timing_server = none::dialyzer_timing:timing_server(),callgraph_file = ""::file:filename(),solvers::[solver()]}).

-record(options,{files = []::[file:filename()],files_rec = []::[file:filename()],analysis_type = succ_typings::anal_type1(),timing = false::boolean()|debug,defines = []::[dial_define()],from = byte_code::start_from(),get_warnings = maybe::boolean()|maybe,init_plts = []::[file:filename()],include_dirs = []::[file:filename()],output_plt = none::none|file:filename(),legal_warnings = ordsets:new()::dial_warn_tags(),report_mode = normal::rep_mode(),erlang_mode = false::boolean(),use_contracts = true::boolean(),output_file = none::none|file:filename(),output_format = formatted::format(),filename_opt = basename::fopt(),indent_opt = true::iopt(),callgraph_file = ""::file:filename(),check_plt = true::boolean(),solvers = []::[solver()],native = maybe::boolean()|maybe,native_cache = true::boolean()}).

-record(contract,{contracts = []::[contract_pair()],args = []::[erl_types:erl_type()],forms = []::[{_,_}]}).

-file("dialyzer_codeserver.erl", 64).

-type(dict_ets()::ets:tid()).

-type(map_ets()::ets:tid()).

-type(set_ets()::ets:tid()).

-type(types()::erl_types:type_table()).

-type(contracts()::#{mfa() => dialyzer_contracts:file_contract()}).

-type(meta_info()::[{{nowarn_function|dial_warn_tag()},mod|func}]).

-type(fun_meta_info()::[{mfa(),meta_info()}|{module(),[dial_warn_tag()]}]).

-record(codeserver,{next_core_label = 0::label(),code::dict_ets(),exported_types::clean|set_ets(),records::clean|map_ets(),contracts::map_ets(),callbacks::map_ets(),fun_meta_info::dict_ets(),exports::clean|set_ets(),temp_exported_types::clean|set_ets(),temp_records::clean|map_ets(),temp_contracts::clean|map_ets(),temp_callbacks::clean|map_ets()}).

-opaque(codeserver()::#codeserver{}).

ets_dict_find(Key,Table) ->
    try ets:lookup_element(Table,Key,2) of 
        Val->
            {ok,Val}
        catch
            _:_->
                error end.

ets_map_store(Key,Element,Table) ->
    true = ets:insert(Table,{Key,Element}),
    Table.

ets_dict_to_dict(Table) ->
    Fold = fun ({Key,Value},Dict)->
        dict:store(Key,Value,Dict) end,
    ets:foldl(Fold,dict:new(),Table).

ets_set_is_element(Key,Table) ->
    ets:lookup(Table,Key) =/= [].

ets_set_insert_set(Set,Table) ->
    ets_set_insert_list(sets:to_list(Set),Table).

ets_set_insert_list(List,Table) ->
    true = ets:insert(Table,[{E} || E <- List]).

ets_set_to_set(Table) ->
    Fold = fun ({E},Set)->
        sets:add_element(E,Set) end,
    ets:foldl(Fold,sets:new(),Table).

-spec(new() -> codeserver()).

new() ->
    CodeOptions = [compressed, public, {read_concurrency,true}],
    Code = ets:new(dialyzer_codeserver_code,CodeOptions),
    ReadOptions = [compressed, {read_concurrency,true}],
    [Contracts, Callbacks, Records, ExportedTypes] = [(ets:new(Name,ReadOptions)) || Name <- [dialyzer_codeserver_contracts, dialyzer_codeserver_callbacks, dialyzer_codeserver_records, dialyzer_codeserver_exported_types]],
    TempOptions = [public, {write_concurrency,true}],
    [Exports, FunMetaInfo, TempExportedTypes, TempRecords, TempContracts, TempCallbacks] = [(ets:new(Name,TempOptions)) || Name <- [dialyzer_codeserver_exports, dialyzer_codeserver_fun_meta_info, dialyzer_codeserver_temp_exported_types, dialyzer_codeserver_temp_records, dialyzer_codeserver_temp_contracts, dialyzer_codeserver_temp_callbacks]],
    #codeserver{code = Code,exports = Exports,fun_meta_info = FunMetaInfo,exported_types = ExportedTypes,records = Records,contracts = Contracts,callbacks = Callbacks,temp_exported_types = TempExportedTypes,temp_records = TempRecords,temp_contracts = TempContracts,temp_callbacks = TempCallbacks}.

-spec(delete(codeserver()) -> ok).

delete(CServer) ->
    lists:foreach(fun (Table)->
        true = ets:delete(Table) end,tables(CServer)).

-spec(insert(atom(),cerl:c_module(),codeserver()) -> codeserver()).

insert(Mod,ModCode,CS) ->
    Name = cerl:module_name(ModCode),
    Exports = cerl:module_exports(ModCode),
    Attrs = cerl:module_attrs(ModCode),
    Defs = cerl:module_defs(ModCode),
    {Files,SmallDefs} = compress_file_anno(Defs),
    As = cerl:get_ann(ModCode),
    Funs = [{{Mod,cerl:fname_id(Var),cerl:fname_arity(Var)},Val,{Var,cerl_trees:get_label(Fun)}} || Val = {Var,Fun} <- SmallDefs],
    Keys = [Key || {Key,_Value,_Label} <- Funs],
    ModEntry = {Mod,{Name,Exports,Attrs,Keys,As}},
    ModFileEntry = {{mod,Mod},Files},
    true = ets:insert(CS#codeserver.code,[ModEntry, ModFileEntry| Funs]),
    CS.

-spec(get_temp_exported_types(codeserver()) -> sets:set(mfa())).

get_temp_exported_types(#codeserver{temp_exported_types = TempExpTypes}) ->
    ets_set_to_set(TempExpTypes).

-spec(insert_temp_exported_types(sets:set(mfa()),codeserver()) -> codeserver()).

insert_temp_exported_types(Set,CS) ->
    TempExportedTypes = CS#codeserver.temp_exported_types,
    true = ets_set_insert_set(Set,TempExportedTypes),
    CS.

-spec(insert_exports([mfa()],codeserver()) -> codeserver()).

insert_exports(List,#codeserver{exports = Exports} = CS) ->
    true = ets_set_insert_list(List,Exports),
    CS.

-spec(insert_fun_meta_info(fun_meta_info(),codeserver()) -> codeserver()).

insert_fun_meta_info(List,#codeserver{fun_meta_info = FunMetaInfo} = CS) ->
    true = ets:insert(FunMetaInfo,List),
    CS.

-spec(is_exported(mfa(),codeserver()) -> boolean()).

is_exported(MFA,#codeserver{exports = Exports}) ->
    ets_set_is_element(MFA,Exports).

-spec(get_exported_types(codeserver()) -> sets:set(mfa())).

get_exported_types(#codeserver{exported_types = ExpTypes}) ->
    ets_set_to_set(ExpTypes).

-spec(extract_exported_types(codeserver()) -> {codeserver(),set_ets()}).

extract_exported_types(#codeserver{exported_types = ExpTypes} = CS) ->
    {CS#codeserver{exported_types = clean},ExpTypes}.

-spec(get_exports(codeserver()) -> sets:set(mfa())).

get_exports(#codeserver{exports = Exports}) ->
    ets_set_to_set(Exports).

-spec(finalize_exported_types(sets:set(mfa()),codeserver()) -> codeserver()).

finalize_exported_types(Set,#codeserver{exported_types = ExportedTypes,temp_exported_types = TempETypes} = CS) ->
    true = ets_set_insert_set(Set,ExportedTypes),
    true = ets:delete(TempETypes),
    CS#codeserver{temp_exported_types = clean}.

-spec(lookup_mod_code(atom(),codeserver()) -> cerl:c_module()).

lookup_mod_code(Mod,CS)
    when is_atom(Mod)->
    table__lookup(CS#codeserver.code,Mod).

-spec(lookup_mfa_code(mfa(),codeserver()) -> {cerl:c_var(),cerl:c_fun()}).

lookup_mfa_code({_M,_F,_A} = MFA,CS) ->
    table__lookup(CS#codeserver.code,MFA).

-spec(lookup_mfa_var_label(mfa(),codeserver()) -> {cerl:c_var(),label()}).

lookup_mfa_var_label({_M,_F,_A} = MFA,CS) ->
    ets:lookup_element(CS#codeserver.code,MFA,3).

-spec(get_next_core_label(codeserver()) -> label()).

get_next_core_label(#codeserver{next_core_label = NCL}) ->
    NCL.

-spec(set_next_core_label(label(),codeserver()) -> codeserver()).

set_next_core_label(NCL,CS) ->
    CS#codeserver{next_core_label = NCL}.

-spec(lookup_mod_records(atom(),codeserver()) -> types()).

lookup_mod_records(Mod,#codeserver{records = RecDict})
    when is_atom(Mod)->
    case ets_dict_find(Mod,RecDict) of
        error->
            maps:new();
        {ok,Map}->
            Map
    end.

-spec(get_records_table(codeserver()) -> map_ets()).

get_records_table(#codeserver{records = RecDict}) ->
    RecDict.

-spec(extract_records(codeserver()) -> {codeserver(),map_ets()}).

extract_records(#codeserver{records = RecDict} = CS) ->
    {CS#codeserver{records = clean},RecDict}.

-spec(store_temp_records(module(),types(),codeserver()) -> codeserver()).

store_temp_records(Mod,Map,#codeserver{temp_records = TempRecDict} = CS)
    when is_atom(Mod)->
    case maps:size(Map) =:= 0 of
        true->
            CS;
        false->
            CS#codeserver{temp_records = ets_map_store(Mod,Map,TempRecDict)}
    end.

-spec(get_temp_records_table(codeserver()) -> map_ets()).

get_temp_records_table(#codeserver{temp_records = TempRecDict}) ->
    TempRecDict.

-spec(lookup_temp_mod_records(module(),codeserver()) -> types()).

lookup_temp_mod_records(Mod,#codeserver{temp_records = TempRecDict}) ->
    case ets_dict_find(Mod,TempRecDict) of
        error->
            maps:new();
        {ok,Map}->
            Map
    end.

-spec(finalize_records(codeserver()) -> codeserver()).

finalize_records(#codeserver{temp_records = TmpRecords,records = Records} = CS) ->
    A0 = erl_anno:new(0),
    AFun = fun (_)->
        A0 end,
    FFun = fun ({F,Abs,Type})->
        NewAbs = erl_parse:map_anno(AFun,Abs),
        {F,NewAbs,Type} end,
    ArFun = fun ({Arity,Fields})->
        {Arity,lists:map(FFun,Fields)} end,
    List = dialyzer_utils:ets_tab2list(TmpRecords),
    true = ets:delete(TmpRecords),
    Fun = fun ({Mod,Map})->
        MFun = fun ({record,_},{FileLine,ArityFields})->
            {FileLine,lists:map(ArFun,ArityFields)};(_,{{M,FileLine,Abs,Args},Type})->
            {{M,FileLine,erl_parse:map_anno(AFun,Abs),Args},Type} end,
        {Mod,maps:map(MFun,Map)} end,
    NewList = lists:map(Fun,List),
    true = ets:insert(Records,NewList),
    CS#codeserver{temp_records = clean}.

-spec(lookup_mod_contracts(atom(),codeserver()) -> contracts()).

lookup_mod_contracts(Mod,#codeserver{contracts = ContDict})
    when is_atom(Mod)->
    case ets_dict_find(Mod,ContDict) of
        error->
            maps:new();
        {ok,Keys}->
            maps:from_list([(get_file_contract(Key,ContDict)) || Key <- Keys])
    end.

get_file_contract(Key,ContDict) ->
    {Key,ets:lookup_element(ContDict,Key,2)}.

-spec(lookup_mfa_contract(mfa(),codeserver()) -> error|{ok,dialyzer_contracts:file_contract()}).

lookup_mfa_contract(MFA,#codeserver{contracts = ContDict}) ->
    ets_dict_find(MFA,ContDict).

-spec(lookup_meta_info(module()|mfa(),codeserver()) -> {ok,meta_info()}|error).

lookup_meta_info(MorMFA,#codeserver{fun_meta_info = FunMetaInfo}) ->
    ets_dict_find(MorMFA,FunMetaInfo).

-spec(get_contracts(codeserver()) -> dict:dict(mfa(),dialyzer_contracts:file_contract())).

get_contracts(#codeserver{contracts = ContDict}) ->
    dict:filter(fun ({_M,_F,_A},_)->
        true;(_,_)->
        false end,ets_dict_to_dict(ContDict)).

-spec(get_callbacks(codeserver()) -> list()).

get_callbacks(#codeserver{callbacks = CallbDict}) ->
    ets:tab2list(CallbDict).

-spec(store_temp_contracts(module(),contracts(),contracts(),codeserver()) -> codeserver()).

store_temp_contracts(Mod,SpecMap,CallbackMap,#codeserver{temp_contracts = Cn,temp_callbacks = Cb} = CS)
    when is_atom(Mod)->
    CS1 = CS#codeserver{temp_contracts = ets_map_store(Mod,SpecMap,Cn)},
    CS1#codeserver{temp_callbacks = ets_map_store(Mod,CallbackMap,Cb)}.

-spec(all_temp_modules(codeserver()) -> [module()]).

all_temp_modules(#codeserver{temp_contracts = TempContTable}) ->
    ets:select(TempContTable,[{{'$1','$2'},[],['$1']}]).

-spec(store_contracts(module(),contracts(),contracts(),codeserver()) -> codeserver()).

store_contracts(Mod,SpecMap,CallbackMap,CS) ->
    #codeserver{contracts = SpecDict,callbacks = CallbackDict} = CS,
    Keys = maps:keys(SpecMap),
    true = ets:insert(SpecDict,maps:to_list(SpecMap)),
    true = ets:insert(SpecDict,{Mod,Keys}),
    true = ets:insert(CallbackDict,maps:to_list(CallbackMap)),
    CS.

-spec(get_temp_contracts(module(),codeserver()) -> {contracts(),contracts()}).

get_temp_contracts(Mod,#codeserver{temp_contracts = TempContDict,temp_callbacks = TempCallDict}) ->
    [{Mod,Contracts}] = ets:lookup(TempContDict,Mod),
    true = ets:delete(TempContDict,Mod),
    [{Mod,Callbacks}] = ets:lookup(TempCallDict,Mod),
    true = ets:delete(TempCallDict,Mod),
    {Contracts,Callbacks}.

-spec(give_away(codeserver(),pid()) -> ok).

give_away(CServer,Pid) ->
    lists:foreach(fun (Table)->
        true = ets:give_away(Table,Pid,any) end,tables(CServer)).

tables(#codeserver{code = Code,fun_meta_info = FunMetaInfo,exports = Exports,temp_exported_types = TempExpTypes,temp_records = TempRecords,temp_contracts = TempContracts,temp_callbacks = TempCallbacks,exported_types = ExportedTypes,records = Records,contracts = Contracts,callbacks = Callbacks}) ->
    [Table || Table <- [Code, FunMetaInfo, Exports, TempExpTypes, TempRecords, TempContracts, TempCallbacks, ExportedTypes, Records, Contracts, Callbacks],Table =/= clean].

-spec(finalize_contracts(codeserver()) -> codeserver()).

finalize_contracts(#codeserver{temp_contracts = TempContDict,temp_callbacks = TempCallDict} = CS) ->
    true = ets:delete(TempContDict),
    true = ets:delete(TempCallDict),
    CS#codeserver{temp_contracts = clean,temp_callbacks = clean}.

-spec(translate_fake_file(codeserver(),module(),file:filename()) -> file:filename()).

translate_fake_file(#codeserver{code = Code},Module,FakeFile) ->
    Files = ets:lookup_element(Code,{mod,Module},2),
    {FakeFile,File} = lists:keyfind(FakeFile,1,Files),
    File.

table__lookup(TablePid,M)
    when is_atom(M)->
    {Name,Exports,Attrs,Keys,As} = ets:lookup_element(TablePid,M,2),
    Defs = [(table__lookup(TablePid,Key)) || Key <- Keys],
    cerl:ann_c_module(As,Name,Exports,Attrs,Defs);
table__lookup(TablePid,MFA) ->
    ets:lookup_element(TablePid,MFA,2).

compress_file_anno(Term) ->
    {Files,SmallTerm} = compress_file_anno(Term,[]),
    {[{FakeFile,File} || {File,{file,FakeFile}} <- Files],SmallTerm}.

compress_file_anno({file,F},Fs)
    when is_list(F)->
    case lists:keyfind(F,1,Fs) of
        false->
            I = integer_to_list(length(Fs)),
            FileI = {file,I},
            NFs = [{F,FileI}| Fs],
            {NFs,FileI};
        {F,FileI}->
            {Fs,FileI}
    end;
compress_file_anno(T,Fs)
    when is_tuple(T)->
    {NFs,NL} = compress_file_anno(tuple_to_list(T),Fs),
    {NFs,list_to_tuple(NL)};
compress_file_anno([E| L],Fs) ->
    {Fs1,NE} = compress_file_anno(E,Fs),
    {NFs,NL} = compress_file_anno(L,Fs1),
    {NFs,[NE| NL]};
compress_file_anno(T,Fs) ->
    {Fs,T}.