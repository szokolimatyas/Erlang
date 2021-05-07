-file("dets_v9.erl", 1).

-module(dets_v9).

-export([mark_dirty/1, read_file_header/2, check_file_header/2, do_perform_save/1, initiate_file/11, prep_table_copy/9, init_freelist/1, fsck_input/4, bulk_input/3, output_objs/3, bchunk_init/2, try_bchunk_header/2, compact_init/3, read_bchunks/2, write_cache/1, may_grow/3, find_object/2, slot_objs/2, scan_objs/8, db_hash/2, no_slots/1, table_parameters/1]).

-export([file_info/1, v_segments/1]).

-export([cache_segps/3]).

-dialyzer(no_improper_lists).

-compile({inline,[{max_objsize,1}, {maxobjsize,1}]}).

-compile({inline,[{write_segment_file,6}]}).

-compile({inline,[{sz2pos,1}, {adjsz,1}]}).

-compile({inline,[{skip_bytes,6}, {make_object,4}]}).

-compile({inline,[{segp_cache,2}, {get_segp,1}, {get_arrpart,1}]}).

-compile({inline,[{h,2}]}).

-file("dets.hrl", 1).

-type(access()::read|read_write).

-type(auto_save()::infinity|non_neg_integer()).

-type(hash_bif()::phash|phash2).

-type(keypos()::pos_integer()).

-type(no_colls()::[{LogSize::non_neg_integer(),NoCollections::non_neg_integer()}]).

-type(no_slots()::default|non_neg_integer()).

-type(tab_name()::term()).

-type(type()::bag|duplicate_bag|set).

-type(update_mode()::dirty|new_dirty|saved|{error,Reason::term()}).

-record(head,{m::non_neg_integer(),m2::non_neg_integer(),next::non_neg_integer(),fptr::file:fd(),no_objects::non_neg_integer(),no_keys::non_neg_integer(),maxobjsize::undefined|non_neg_integer(),n,type::type(),keypos::keypos(),freelists::undefined|tuple(),freelists_p::undefined|non_neg_integer(),no_collections::undefined|no_colls(),auto_save::auto_save(),update_mode::update_mode(),fixed = false::false|{{integer(),integer()},[{pid(),non_neg_integer()}]},hash_bif::hash_bif(),has_md5::boolean(),min_no_slots::no_slots(),max_no_slots::no_slots(),cache::undefined|cache(),filename::file:name(),access = read_write::access(),ram_file = false::boolean(),name::tab_name(),parent::undefined|pid(),server::undefined|pid(),bump::non_neg_integer(),base::non_neg_integer()}).

-record(fileheader,{freelist::non_neg_integer(),fl_base::non_neg_integer(),cookie::non_neg_integer(),closed_properly::non_neg_integer(),type::badtype|type(),version::non_neg_integer(),m::non_neg_integer(),next::non_neg_integer(),keypos::keypos(),no_objects::non_neg_integer(),no_keys::non_neg_integer(),min_no_slots::non_neg_integer(),max_no_slots::non_neg_integer(),no_colls::undefined|no_colls(),hash_method::non_neg_integer(),read_md5::binary(),has_md5::boolean(),md5::binary(),trailer::non_neg_integer(),eof::non_neg_integer(),n}).

-type(delay()::non_neg_integer()).

-type(threshold()::non_neg_integer()).

-type(cache_parms()::{Delay::delay(),Size::threshold()}).

-record(cache,{cache::[{Key::term(),{Seq::non_neg_integer(),Item::term()}}],csize::non_neg_integer(),inserts::non_neg_integer(),wrtime::undefined|integer(),tsize::threshold(),delay::delay()}).

-type(cache()::#cache{}).

-file("dets_v9.erl", 47).

-record('$hash2',{file_format_version,bchunk_format_version,file,type,keypos,hash_method,n,m,next,min,max,no_objects,no_keys,no_colls::no_colls()}).

mark_dirty(Head) ->
    Dirty = [{8,<<0:32>>}],
    {_H,ok} = dets_utils:pwrite(Head,Dirty),
    ok = dets_utils:sync(Head),
    {ok,_Pos} = dets_utils:position(Head,Head#head.freelists_p),
    dets_utils:truncate(Head,cur).

prep_table_copy(Fd,Tab,Fname,Type,Kp,Ram,CacheSz,Auto,Parms) ->
    case Parms of
        #'$hash2'{file_format_version = 9,bchunk_format_version = 1,n = N,m = M,next = Next,min = Min,max = Max,hash_method = HashMethodCode,no_objects = NoObjects,no_keys = NoKeys,no_colls = _NoColls}
            when is_integer(N),
            is_integer(M),
            is_integer(Next),
            is_integer(Min),
            is_integer(Max),
            is_integer(NoObjects),
            is_integer(NoKeys),
            NoObjects >= NoKeys->
            HashMethod = code_to_hash_method(HashMethodCode),
            case hash_invars(N,M,Next,Min,Max) of
                false->
                    throw(badarg);
                true->
                    init_file(Fd,Tab,Fname,Type,Kp,Min,Max,Ram,CacheSz,Auto,false,M,N,Next,HashMethod,NoObjects,NoKeys)
            end;
        _->
            throw(badarg)
    end.

initiate_file(Fd,Tab,Fname,Type,Kp,MinSlots0,MaxSlots0,Ram,CacheSz,Auto,DoInitSegments) ->
    MaxSlots1 = min(MaxSlots0,256 * 512 * 256),
    MinSlots1 = min(MinSlots0,MaxSlots1),
    MinSlots = slots2(MinSlots1),
    MaxSlots = slots2(MaxSlots1),
    M = Next = MinSlots,
    N = 0,
    init_file(Fd,Tab,Fname,Type,Kp,MinSlots,MaxSlots,Ram,CacheSz,Auto,DoInitSegments,M,N,Next,phash2,0,0).

init_file(Fd,Tab,Fname,Type,Kp,MinSlots,MaxSlots,Ram,CacheSz,Auto,DoInitSegments,M,N,Next,HashMethod,NoObjects,NoKeys) ->
    Ftab = dets_utils:init_alloc(56 + 28 * 4 + 16 + 4 + 124 + 4 * 256),
    Head0 = #head{m = M,m2 = M * 2,next = Next,fptr = Fd,no_objects = NoObjects,no_keys = NoKeys,maxobjsize = 0,n = N,type = Type,update_mode = dirty,freelists = Ftab,no_collections = orddict:new(),auto_save = Auto,hash_bif = HashMethod,has_md5 = true,keypos = Kp,min_no_slots = MinSlots,max_no_slots = MaxSlots,ram_file = Ram,filename = Fname,name = Tab,cache = dets_utils:new_cache(CacheSz),bump = 16,base = 56 + 28 * 4 + 16 + 4 + 124 + 4 * 256},
    FreeListsPointer = 0,
    NoColls = <<0:(28 * 4)/unit:8>>,
    FileHeader = file_header(Head0,FreeListsPointer,0,NoColls),
    W0 = {0,[FileHeader| <<0:(4 * 256)/unit:8>>]},
    lists:foreach(fun ({I1,I2})
        when is_integer(I1),
        is_integer(I2)->
        ok;({K,V})->
        put(K,V) end,erase()),
    Zero = seg_zero(),
    {Head1,Ws1} = init_parts(Head0,0,no_parts(Next),Zero,[]),
    NoSegs = no_segs(Next),
    {Head2,WsI,WsP} = init_segments(Head1,0,NoSegs,Zero,[],[]),
    Ws2 = if DoInitSegments ->
        WsP ++ WsI;true ->
        WsP end,
    dets_utils:pwrite(Fd,Fname,[W0| lists:append(Ws1) ++ Ws2]),
    true = hash_invars(Head2),
    {_,Where,_} = dets_utils:alloc(Head2,16),
    NewFtab = dets_utils:init_alloc(Where),
    Head = Head2#head{freelists = NewFtab,base = Where},
    {ok,Head}.

slots2(NoSlots)
    when NoSlots >= 256->
    1 bsl dets_utils:log2(NoSlots).

init_parts(Head,PartNo,NoParts,Zero,Ws)
    when PartNo < NoParts->
    PartPos = 56 + 28 * 4 + 16 + 4 + 124 + 4 * PartNo,
    {NewHead,W,_Part} = alloc_part(Head,Zero,PartPos),
    init_parts(NewHead,PartNo + 1,NoParts,Zero,[W| Ws]);
init_parts(Head,_PartNo,_NoParts,_Zero,Ws) ->
    {Head,Ws}.

init_segments(Head,SegNo,NoSegs,SegZero,WsP,WsI)
    when SegNo < NoSegs->
    {NewHead,WI,Ws} = allocate_segment(Head,SegZero,SegNo),
    init_segments(NewHead,SegNo + 1,NoSegs,SegZero,Ws ++ WsP,[WI| WsI]);
init_segments(Head,_SegNo,_NoSegs,_SegZero,WsP,WsI) ->
    {Head,WsI,WsP}.

allocate_segment(Head,SegZero,SegNo) ->
    PartPos = 56 + 28 * 4 + 16 + 4 + 124 + 4 * (SegNo div 512),
    case get_arrpart(PartPos) of
        undefined->
            {Head1,[InitArrPart, ArrPartPointer],Part} = alloc_part(Head,SegZero,PartPos),
            {NewHead,InitSegment,[SegPointer]} = alloc_seg(Head1,SegZero,SegNo,Part),
            {NewHead,InitSegment,[InitArrPart, SegPointer, ArrPartPointer]};
        Part->
            alloc_seg(Head,SegZero,SegNo,Part)
    end.

alloc_part(Head,PartZero,PartPos) ->
    {NewHead,Part,_} = dets_utils:alloc(Head,adjsz(4 * 512)),
    arrpart_cache(PartPos,Part),
    InitArrPart = {Part,PartZero},
    ArrPartPointer = {PartPos,<<Part:32>>},
    {NewHead,[InitArrPart, ArrPartPointer],Part}.

alloc_seg(Head,SegZero,SegNo,Part) ->
    {NewHead,Segment,_} = dets_utils:alloc(Head,adjsz(4 * 512)),
    InitSegment = {Segment,SegZero},
    Pos = Part + 4 * (SegNo band (512 - 1)),
    segp_cache(Pos,Segment),
    dets_utils:disk_map_segment(Segment,SegZero),
    SegPointer = {Pos,<<Segment:32>>},
    {NewHead,InitSegment,[SegPointer]}.

init_freelist(Head) ->
    Pos = Head#head.freelists_p,
    free_lists_from_file(Head,Pos).

read_file_header(Fd,FileName) ->
    {ok,Bin} = dets_utils:pread_close(Fd,FileName,0,56 + 28 * 4 + 16 + 4),
    <<FreeList:32,Cookie:32,CP:32,Type2:32,Version:32,M:32,Next:32,Kp:32,NoObjects:32,NoKeys:32,MinNoSlots:32,MaxNoSlots:32,HashMethod:32,N:32,NoCollsB:(28 * 4)/binary,MD5:16/binary,FlBase:32>> = Bin,
    <<_:12/binary,MD5DigestedPart:(56 + 28 * 4 + 16 + 4 - 16 - 4 - 12)/binary,_/binary>> = Bin,
    {ok,EOF} = dets_utils:position_close(Fd,FileName,eof),
    {ok,<<FileSize:32>>} = dets_utils:pread_close(Fd,FileName,EOF - 4,4),
    {CL,<<>>} = lists:foldl(fun (LSz,{Acc,<<NN:32,R/binary>>})->
        if NN =:= 0 ->
            {Acc,R};true ->
            {[{LSz,NN}| Acc],R} end end,{[],NoCollsB},lists:seq(4,32 - 1)),
    NoColls = if CL =:= [],
    NoObjects > 0 ->
        undefined;true ->
        lists:reverse(CL) end,
    Base = case FlBase of
        0->
            56 + 28 * 4 + 16 + 4 + 124 + 4 * 256;
        _->
            FlBase
    end,
    FH = #fileheader{freelist = FreeList,fl_base = Base,cookie = Cookie,closed_properly = CP,type = dets_utils:code_to_type(Type2),version = Version,m = M,next = Next,keypos = Kp,no_objects = NoObjects,no_keys = NoKeys,min_no_slots = MinNoSlots,max_no_slots = MaxNoSlots,no_colls = NoColls,hash_method = HashMethod,read_md5 = MD5,has_md5 = <<0:16/unit:8>> =/= MD5,md5 = erlang:md5(MD5DigestedPart),trailer = FileSize + FlBase,eof = EOF,n = N},
    {ok,Fd,FH}.

check_file_header(FH,Fd) ->
    HashBif = code_to_hash_method(FH#fileheader.hash_method),
    Test = if FH#fileheader.cookie =/= 11259375 ->
        {error,not_a_dets_file};FH#fileheader.type =:= badtype ->
        {error,invalid_type_code};FH#fileheader.version =/= 9 ->
        {error,bad_version};FH#fileheader.has_md5,
    FH#fileheader.read_md5 =/= FH#fileheader.md5 ->
        {error,not_a_dets_file};FH#fileheader.trailer =/= FH#fileheader.eof ->
        {error,not_closed};HashBif =:= undefined ->
        {error,bad_hash_bif};FH#fileheader.closed_properly =:= 1 ->
        ok;FH#fileheader.closed_properly =:= 0 ->
        {error,not_closed};true ->
        {error,not_a_dets_file} end,
    case Test of
        ok->
            MaxObjSize = max_objsize(FH#fileheader.no_colls),
            H = #head{m = FH#fileheader.m,m2 = FH#fileheader.m * 2,next = FH#fileheader.next,fptr = Fd,no_objects = FH#fileheader.no_objects,no_keys = FH#fileheader.no_keys,maxobjsize = MaxObjSize,n = FH#fileheader.n,type = FH#fileheader.type,update_mode = saved,auto_save = infinity,fixed = false,freelists_p = FH#fileheader.freelist,hash_bif = HashBif,has_md5 = FH#fileheader.has_md5,keypos = FH#fileheader.keypos,min_no_slots = FH#fileheader.min_no_slots,max_no_slots = FH#fileheader.max_no_slots,no_collections = FH#fileheader.no_colls,bump = 16,base = FH#fileheader.fl_base},
            {ok,H};
        Error->
            Error
    end.

max_objsize(NoColls = undefined) ->
    NoColls;
max_objsize(NoColls) ->
    max_objsize(NoColls,0).

max_objsize([],Max) ->
    Max;
max_objsize([{_,0}| L],Max) ->
    max_objsize(L,Max);
max_objsize([{I,_}| L],_Max) ->
    max_objsize(L,I).

cache_segps(Fd,FileName,M) ->
    NoParts = no_parts(M),
    ArrStart = 56 + 28 * 4 + 16 + 4 + 124 + 4 * 0,
    {ok,Bin} = dets_utils:pread_close(Fd,FileName,ArrStart,4 * NoParts),
    cache_arrparts(Bin,56 + 28 * 4 + 16 + 4 + 124,Fd,FileName).

cache_arrparts(<<ArrPartPos:32,B/binary>>,Pos,Fd,FileName) ->
    arrpart_cache(Pos,ArrPartPos),
    {ok,ArrPartBin} = dets_utils:pread_close(Fd,FileName,ArrPartPos,512 * 4),
    cache_segps1(Fd,ArrPartBin,ArrPartPos),
    cache_arrparts(B,Pos + 4,Fd,FileName);
cache_arrparts(<<>>,_Pos,_Fd,_FileName) ->
    ok.

cache_segps1(_Fd,<<0:32,_/binary>>,_P) ->
    ok;
cache_segps1(Fd,<<S:32,B/binary>>,P) ->
    dets_utils:disk_map_segment_p(Fd,S),
    segp_cache(P,S),
    cache_segps1(Fd,B,P + 4);
cache_segps1(_Fd,<<>>,_P) ->
    ok.

no_parts(NoSlots) ->
    (NoSlots - 1) div (256 * 512) + 1.

no_segs(NoSlots) ->
    (NoSlots - 1) div 256 + 1.

bulk_input(Head,InitFun,_Cntrs) ->
    bulk_input(Head,InitFun,make_ref(),0).

bulk_input(Head,InitFun,Ref,Seq) ->
    fun (close)->
        _ = ( catch InitFun(close));(read)->
        case  catch {Ref,InitFun(read)} of
            {Ref,end_of_input}->
                end_of_input;
            {Ref,{L0,NewInitFun}}
                when is_list(L0),
                is_function(NewInitFun)->
                Kp = Head#head.keypos,
                case  catch bulk_objects(L0,Head,Kp,Seq,[]) of
                    {'EXIT',_Error}->
                        _ = ( catch NewInitFun(close)),
                        {error,invalid_objects_list};
                    {L,NSeq}->
                        {L,bulk_input(Head,NewInitFun,Ref,NSeq)}
                end;
            {Ref,Value}->
                {error,{init_fun,Value}};
            Error->
                throw({thrown,Error})
        end end.

bulk_objects([T| Ts],Head,Kp,Seq,L) ->
    BT = term_to_binary(T),
    Key = element(Kp,T),
    bulk_objects(Ts,Head,Kp,Seq + 1,[make_object(Head,Key,Seq,BT)| L]);
bulk_objects([],_Head,Kp,Seq,L)
    when is_integer(Kp),
    is_integer(Seq)->
    {L,Seq}.

output_objs(Head,SlotNums,Cntrs) ->
    fun (close)->
        Cache = {},
        Acc = [],
        true = ets:insert(Cntrs,{1,0,[],0}),
        true = ets:insert(Cntrs,{no,0,0}),
        Fun = output_objs2(foo,Acc,Head,Cache,Cntrs,SlotNums,bar),
        Fun(close);([])->
        output_objs(Head,SlotNums,Cntrs);(L)->
        true = ets:delete_all_objects(Cntrs),
        true = ets:insert(Cntrs,{no,0,0}),
        Es = bin2term(L,Head#head.keypos),
        Cache = {},
        {NE,NAcc,NCache} = output_slots(Es,Head,Cache,Cntrs,0,0),
        output_objs2(NE,NAcc,Head,NCache,Cntrs,SlotNums,1) end.

output_objs2(E,Acc,Head,Cache,SizeT,SlotNums,0) ->
    NCache = write_all_sizes(Cache,SizeT,Head,more),
    Max = max(1,min(tuple_size(NCache),10)),
    output_objs2(E,Acc,Head,NCache,SizeT,SlotNums,Max);
output_objs2(E,Acc,Head,Cache,SizeT,SlotNums,ChunkI) ->
    fun (close)->
        {_,[],Cache1} = if Acc =:= [] ->
            {foo,[],Cache};true ->
            output_slot(Acc,Head,Cache,[],SizeT,0,0) end,
        _NCache = write_all_sizes(Cache1,SizeT,Head,no_more),
        SegSz = 512 * 4,
        {_,SegEnd,_} = dets_utils:alloc(Head,adjsz(SegSz)),
        [{no,NoObjects,NoKeys}] = ets:lookup(SizeT,no),
        Head1 = Head#head{no_objects = NoObjects,no_keys = NoKeys},
        true = ets:delete(SizeT,no),
        {NewHead,NL,_MaxSz,_End} = allocate_all_objects(Head1,SizeT),
        segment_file(SizeT,NewHead,NL,SegEnd),
        {MinSlots,EstNoSlots,MaxSlots} = SlotNums,
        if EstNoSlots =:= bulk_init ->
            {ok,0,NewHead};true ->
            EstNoSegs = no_segs(EstNoSlots),
            MinNoSegs = no_segs(MinSlots),
            MaxNoSegs = no_segs(MaxSlots),
            NoSegs = no_segs(NoKeys),
            Diff = abs(NoSegs - EstNoSegs),
            if Diff > 5,
            NoSegs =< MaxNoSegs,
            NoSegs >= MinNoSegs ->
                {try_again,NoKeys};true ->
                {ok,0,NewHead} end end;(L)->
        Es = bin2term(L,Head#head.keypos),
        {NE,NAcc,NCache} = output_slots(E,Es,Acc,Head,Cache,SizeT,0,0),
        output_objs2(NE,NAcc,Head,NCache,SizeT,SlotNums,ChunkI - 1) end.

compact_init(ReadHead,WriteHead,TableParameters) ->
    SizeT = ets:new(dets_compact,[]),
    #head{no_keys = NoKeys,no_objects = NoObjects} = ReadHead,
    NoObjsPerSize = TableParameters#'$hash2'.no_colls,
    {NewWriteHead,Bases,SegAddr,SegEnd} = prepare_file_init(NoObjects,NoKeys,NoObjsPerSize,SizeT,WriteHead),
    Input = compact_input(ReadHead,NewWriteHead,SizeT,tuple_size(Bases)),
    Output = fast_output(NewWriteHead,SizeT,Bases,SegAddr,SegEnd),
    TmpDir = filename:dirname(NewWriteHead#head.filename),
    Reply = ( catch file_sorter:sort(Input,Output,[{format,binary}, {tmpdir,TmpDir}, {header,1}])),
    ets:delete(SizeT),
    Reply.

compact_input(Head,WHead,SizeT,NoSizes) ->
    L = dets_utils:all_allocated_as_list(Head),
    Cache = list_to_tuple(tuple_to_list({}) ++ lists:duplicate(NoSizes - tuple_size({}),[0])),
    compact_input(Head,WHead,SizeT,Cache,L).

compact_input(Head,WHead,SizeT,Cache,L) ->
    fun (close)->
        ok;(read)->
        compact_read(Head,WHead,SizeT,Cache,L,0,[],0) end.

compact_read(_Head,WHead,SizeT,Cache,[],_Min,[],_ASz) ->
    _ = fast_write_all_sizes(Cache,SizeT,WHead),
    end_of_input;
compact_read(Head,WHead,SizeT,Cache,L,Min,SegBs,ASz)
    when ASz + Min >= 60 * 8192,
    ASz > 0->
    NCache = fast_write_all_sizes(Cache,SizeT,WHead),
    {SegBs,compact_input(Head,WHead,SizeT,NCache,L)};
compact_read(Head,WHead,SizeT,Cache,[[From| To]| L],Min,SegBs,ASz) ->
    Max = max(8192 * 3,Min),
    case check_pread_arg(Max,Head) of
        true->
            case dets_utils:pread_n(Head#head.fptr,From,Max) of
                eof->
                    not_ok;
                Bin1
                    when byte_size(Bin1) < Min->
                    Pad = Min - byte_size(Bin1),
                    NewBin = <<Bin1/binary,0:Pad/unit:8>>,
                    compact_objs(Head,WHead,SizeT,NewBin,L,From,To,SegBs,Cache,ASz);
                NewBin->
                    compact_objs(Head,WHead,SizeT,NewBin,L,From,To,SegBs,Cache,ASz)
            end;
        false->
            not_ok
    end.

compact_objs(Head,WHead,SizeT,Bin,L,From,To,SegBs,Cache,ASz)
    when From =:= To->
    case L of
        []->
            {SegBs,compact_input(Head,WHead,SizeT,Cache,L)};
        [[From1| To1]| L1]->
            Skip1 = From1 - From,
            case Bin of
                <<_:Skip1/binary,NewBin/binary>>->
                    compact_objs(Head,WHead,SizeT,NewBin,L1,From1,To1,SegBs,Cache,ASz);
                _
                    when byte_size(Bin) < Skip1->
                    compact_read(Head,WHead,SizeT,Cache,L,0,SegBs,ASz)
            end
    end;
compact_objs(Head,WHead,SizeT,<<Size:32,St:32,_Sz:32,KO/binary>> = Bin,L,From,To,SegBs,Cache,ASz)
    when St =:= 305419896->
    LSize = sz2pos(Size),
    Size2 = 1 bsl (LSize - 1),
    if byte_size(Bin) >= Size2 ->
        NASz = ASz + Size2,
        <<SlotObjs:Size2/binary,NewBin/binary>> = Bin,
        Term = if Head#head.type =:= set ->
            binary_to_term(KO);true ->
            <<_KSz:32,B2/binary>> = KO,
            binary_to_term(B2) end,
        Key = element(Head#head.keypos,Term),
        Slot = db_hash(Key,Head),
        From1 = From + Size2,
        [Addr| AL] = element(LSize,Cache),
        NCache = setelement(LSize,Cache,[Addr + Size2, SlotObjs| AL]),
        NSegBs = [<<Slot:32,Size:32,Addr:32,LSize:8>>| SegBs],
        compact_objs(Head,WHead,SizeT,NewBin,L,From1,To,NSegBs,NCache,NASz);true ->
        compact_read(Head,WHead,SizeT,Cache,[[From| To]| L],Size2,SegBs,ASz) end;
compact_objs(Head,WHead,SizeT,<<_:32,_St:32,_:32,_/binary>> = Bin,L,From,To,SegBs,Cache,ASz)
    when byte_size(Bin) >= 512 * 4->
    <<_:(512 * 4)/binary,NewBin/binary>> = Bin,
    compact_objs(Head,WHead,SizeT,NewBin,L,From + 512 * 4,To,SegBs,Cache,ASz);
compact_objs(Head,WHead,SizeT,<<_:32,_St:32,_:32,_/binary>> = Bin,L,From,To,SegBs,Cache,ASz)
    when byte_size(Bin) < 512 * 4->
    compact_read(Head,WHead,SizeT,Cache,[[From| To]| L],512 * 4,SegBs,ASz);
compact_objs(Head,WHead,SizeT,_Bin,L,From,To,SegBs,Cache,ASz) ->
    compact_read(Head,WHead,SizeT,Cache,[[From| To]| L],0,SegBs,ASz).

read_bchunks(Head,L) ->
    read_bchunks(Head,L,0,[],0).

read_bchunks(_Head,L,Min,Bs,ASz)
    when ASz + Min >= 4 * 8192,
    Bs =/= []->
    {lists:reverse(Bs),L};
read_bchunks(Head,{From,To,L},Min,Bs,ASz) ->
    Max = max(8192 * 2,Min),
    case check_pread_arg(Max,Head) of
        true->
            case dets_utils:pread_n(Head#head.fptr,From,Max) of
                eof->
                    {error,premature_eof};
                NewBin
                    when byte_size(NewBin) >= Min->
                    bchunks(Head,L,NewBin,Bs,ASz,From,To);
                Bin1
                    when To - From =:= Min,
                    L =:= <<>>->
                    Pad = Min - byte_size(Bin1),
                    NewBin = <<Bin1/binary,0:Pad/unit:8>>,
                    bchunks(Head,L,NewBin,Bs,ASz,From,To);
                _->
                    {error,premature_eof}
            end;
        false->
            {error,dets_utils:bad_object(bad_object,{read_bchunks,Max})}
    end.

bchunks(Head,L,Bin,Bs,ASz,From,To)
    when From =:= To->
    if L =:= <<>> ->
        {finished,lists:reverse(Bs)};true ->
        <<From1:32,To1:32,L1/binary>> = L,
        Skip1 = From1 - From,
        case Bin of
            <<_:Skip1/binary,NewBin/binary>>->
                bchunks(Head,L1,NewBin,Bs,ASz,From1,To1);
            _
                when byte_size(Bin) < Skip1->
                read_bchunks(Head,{From1,To1,L1},0,Bs,ASz)
        end end;
bchunks(Head,L,<<Size:32,St:32,_Sz:32,KO/binary>> = Bin,Bs,ASz,From,To)
    when St =:= 305419896;
    St =:= 61591023->
    LSize = sz2pos(Size),
    Size2 = 1 bsl (LSize - 1),
    if byte_size(Bin) >= Size2 ->
        <<B0:Size2/binary,NewBin/binary>> = Bin,
        Term = if Head#head.type =:= set ->
            binary_to_term(KO);true ->
            <<_KSz:32,B2/binary>> = KO,
            binary_to_term(B2) end,
        Key = element(Head#head.keypos,Term),
        Slot = db_hash(Key,Head),
        B = {LSize,Slot,B0},
        bchunks(Head,L,NewBin,[B| Bs],ASz + Size2,From + Size2,To);true ->
        read_bchunks(Head,{From,To,L},Size2,Bs,ASz) end;
bchunks(Head,L,<<_:32,_St:32,_:32,_/binary>> = Bin,Bs,ASz,From,To)
    when byte_size(Bin) >= 512 * 4->
    <<_:(512 * 4)/binary,NewBin/binary>> = Bin,
    bchunks(Head,L,NewBin,Bs,ASz,From + 512 * 4,To);
bchunks(Head,L,<<_:32,_St:32,_:32,_/binary>> = Bin,Bs,ASz,From,To)
    when byte_size(Bin) < 512 * 4->
    read_bchunks(Head,{From,To,L},512 * 4,Bs,ASz);
bchunks(Head,L,_Bin,Bs,ASz,From,To) ->
    read_bchunks(Head,{From,To,L},0,Bs,ASz).

bchunk_init(Head,InitFun) ->
    Ref = make_ref(),
    case  catch {Ref,InitFun(read)} of
        {Ref,end_of_input}->
            {error,{init_fun,end_of_input}};
        {Ref,{[],NInitFun}}
            when is_function(NInitFun)->
            bchunk_init(Head,NInitFun);
        {Ref,{[ParmsBin| L],NInitFun}}
            when is_list(L),
            is_function(NInitFun)->
            #head{fptr = Fd,type = Type,keypos = Kp,auto_save = Auto,cache = Cache,filename = Fname,ram_file = Ram,name = Tab} = Head,
            case try_bchunk_header(ParmsBin,Head) of
                {ok,Parms}->
                    #'$hash2'{no_objects = NoObjects,no_keys = NoKeys,no_colls = NoObjsPerSize} = Parms,
                    CacheSz = dets_utils:cache_size(Cache),
                    {ok,Head1} = prep_table_copy(Fd,Tab,Fname,Type,Kp,Ram,CacheSz,Auto,Parms),
                    SizeT = ets:new(dets_init,[]),
                    {NewHead,Bases,SegAddr,SegEnd} = prepare_file_init(NoObjects,NoKeys,NoObjsPerSize,SizeT,Head1),
                    ECache = list_to_tuple(tuple_to_list({}) ++ lists:duplicate(tuple_size(Bases) - tuple_size({}),[0])),
                    Input = fun (close)->
                        _ = ( catch NInitFun(close));(read)->
                        do_make_slots(L,ECache,SizeT,NewHead,Ref,0,NInitFun) end,
                    Output = fast_output(NewHead,SizeT,Bases,SegAddr,SegEnd),
                    TmpDir = filename:dirname(Head#head.filename),
                    Reply = ( catch file_sorter:sort(Input,Output,[{format,binary}, {tmpdir,TmpDir}, {header,1}])),
                    ets:delete(SizeT),
                    Reply;
                not_ok->
                    {error,{init_fun,ParmsBin}}
            end;
        {Ref,Value}->
            {error,{init_fun,Value}};
        Error->
            {thrown,Error}
    end.

try_bchunk_header(ParmsBin,Head) ->
    #head{type = Type,keypos = Kp,hash_bif = HashBif} = Head,
    HashMethod = hash_method_to_code(HashBif),
    case  catch binary_to_term(ParmsBin) of
        Parms
            when is_record(Parms,'$hash2'),
            Parms#'$hash2'.type =:= Type,
            Parms#'$hash2'.keypos =:= Kp,
            Parms#'$hash2'.hash_method =:= HashMethod,
            Parms#'$hash2'.bchunk_format_version =:= 1->
            {ok,Parms};
        _->
            not_ok
    end.

bchunk_input(InitFun,SizeT,Head,Ref,Cache,ASz) ->
    fun (close)->
        _ = ( catch InitFun(close));(read)->
        case  catch {Ref,InitFun(read)} of
            {Ref,end_of_input}->
                _ = fast_write_all_sizes(Cache,SizeT,Head),
                end_of_input;
            {Ref,{L,NInitFun}}
                when is_list(L),
                is_function(NInitFun)->
                do_make_slots(L,Cache,SizeT,Head,Ref,ASz,NInitFun);
            {Ref,Value}->
                {error,{init_fun,Value}};
            Error->
                throw({thrown,Error})
        end end.

do_make_slots(L,Cache,SizeT,Head,Ref,ASz,InitFun) ->
    case  catch make_slots(L,Cache,[],ASz) of
        {'EXIT',_}->
            _ = ( catch InitFun(close)),
            {error,invalid_objects_list};
        {Cache1,SegBs,NASz}
            when NASz > 60 * 8192->
            NCache = fast_write_all_sizes(Cache1,SizeT,Head),
            F = bchunk_input(InitFun,SizeT,Head,Ref,NCache,0),
            {SegBs,F};
        {NCache,SegBs,NASz}->
            F = bchunk_input(InitFun,SizeT,Head,Ref,NCache,NASz),
            {SegBs,F}
    end.

make_slots([{LSize,Slot,<<Size:32,St:32,Sz:32,KO/binary>> = Bin0}| Bins],Cache,SegBs,ASz) ->
    Bin = if St =:= 305419896 ->
        Bin0;St =:= 61591023 ->
        <<Size:32,305419896:32,Sz:32,KO/binary>> end,
    BSz = byte_size(Bin0),
    true = BSz =:= 1 bsl (LSize - 1),
    NASz = ASz + BSz,
    [Addr| L] = element(LSize,Cache),
    NSegBs = [<<Slot:32,Size:32,Addr:32,LSize:8>>| SegBs],
    NCache = setelement(LSize,Cache,[Addr + BSz, Bin| L]),
    make_slots(Bins,NCache,NSegBs,NASz);
make_slots([],Cache,SegBs,ASz) ->
    {Cache,SegBs,ASz}.

fast_output(Head,SizeT,Bases,SegAddr,SegEnd) ->
    fun (close)->
        fast_output_end(Head,SizeT);(L)->
        case file:position(Head#head.fptr,SegAddr) of
            {ok,SegAddr}->
                NewSegAddr = write_segment_file(L,Bases,Head,[],SegAddr,SegAddr),
                fast_output2(Head,SizeT,Bases,NewSegAddr,SegAddr,SegEnd);
            Error->
                 catch dets_utils:file_error(Error,Head#head.filename)
        end end.

fast_output2(Head,SizeT,Bases,SegAddr,SS,SegEnd) ->
    fun (close)->
        FinalZ = SegEnd - SegAddr,
        dets_utils:write(Head,dets_utils:make_zeros(FinalZ)),
        fast_output_end(Head,SizeT);(L)->
        NewSegAddr = write_segment_file(L,Bases,Head,[],SegAddr,SS),
        fast_output2(Head,SizeT,Bases,NewSegAddr,SS,SegEnd) end.

fast_output_end(Head,SizeT) ->
    case ets:foldl(fun ({_Sz,_Pos,Cnt,NoC},Acc)->
        (Cnt =:= NoC) and Acc end,true,SizeT) of
        true->
            {ok,Head};
        false->
            {error,invalid_objects_list}
    end.

write_segment_file([<<Slot:32,BSize:32,AddrToBe:32,LSize:8>>| Bins],Bases,Head,Ws,SegAddr,SS) ->
    Pos = SS + 2 * 4 * Slot,
    write_segment_file(Bins,Bases,Head,Ws,SegAddr,SS,Pos,BSize,AddrToBe,LSize);
write_segment_file([],_Bases,Head,Ws,SegAddr,_SS) ->
    dets_utils:write(Head,Ws),
    SegAddr.

write_segment_file(Bins,Bases,Head,Ws,SegAddr,SS,Pos,BSize,AddrToBe,LSize)
    when Pos =:= SegAddr->
    Addr = AddrToBe + element(LSize,Bases),
    NWs = [Ws| <<BSize:32,Addr:32>>],
    write_segment_file(Bins,Bases,Head,NWs,SegAddr + 2 * 4,SS);
write_segment_file(Bins,Bases,Head,Ws,SegAddr,SS,Pos,BSize,AddrToBe,LSize)
    when Pos - SegAddr < 100->
    Addr = AddrToBe + element(LSize,Bases),
    NoZeros = Pos - SegAddr,
    NWs = [Ws| <<0:NoZeros/unit:8,BSize:32,Addr:32>>],
    NSegAddr = SegAddr + NoZeros + 2 * 4,
    write_segment_file(Bins,Bases,Head,NWs,NSegAddr,SS);
write_segment_file(Bins,Bases,Head,Ws,SegAddr,SS,Pos,BSize,AddrToBe,LSize) ->
    Addr = AddrToBe + element(LSize,Bases),
    NoZeros = Pos - SegAddr,
    NWs = [Ws, dets_utils:make_zeros(NoZeros)| <<BSize:32,Addr:32>>],
    NSegAddr = SegAddr + NoZeros + 2 * 4,
    write_segment_file(Bins,Bases,Head,NWs,NSegAddr,SS).

fast_write_all_sizes(Cache,SizeT,Head) ->
    CacheL = lists:reverse(tuple_to_list(Cache)),
    fast_write_sizes(CacheL,tuple_size(Cache),SizeT,Head,[],[]).

fast_write_sizes([],_Sz,_SizeT,Head,NCL,PwriteList) ->
    #head{filename = FileName,fptr = Fd} = Head,
    ok = dets_utils:pwrite(Fd,FileName,PwriteList),
    list_to_tuple(NCL);
fast_write_sizes([[_Addr] = C| CL],Sz,SizeT,Head,NCL,PwriteList) ->
    fast_write_sizes(CL,Sz - 1,SizeT,Head,[C| NCL],PwriteList);
fast_write_sizes([[Addr| C]| CL],Sz,SizeT,Head,NCL,PwriteList) ->
    case ets:lookup(SizeT,Sz) of
        []->
            throw({error,invalid_objects_list});
        [{Sz,Position,_ObjCounter,_NoCollections}]->
            NoColls = length(C),
            _ = ets:update_counter(SizeT,Sz,{3,NoColls}),
            Pos = Position + Addr - NoColls * (1 bsl (Sz - 1)),
            fast_write_sizes(CL,Sz - 1,SizeT,Head,[[Addr]| NCL],[{Pos,lists:reverse(C)}| PwriteList])
    end.

prepare_file_init(NoObjects,NoKeys,NoObjsPerSize,SizeT,Head) ->
    SegSz = 512 * 4,
    {_,SegEnd,_} = dets_utils:alloc(Head,adjsz(SegSz)),
    Head1 = Head#head{no_objects = NoObjects,no_keys = NoKeys},
    true = ets:insert(SizeT,{1,0,[],0}),
    lists:foreach(fun ({LogSz,NoColls})->
        true = ets:insert(SizeT,{LogSz + 1,0,0,NoColls}) end,NoObjsPerSize),
    {NewHead,NL0,MaxSz,EndOfFile} = allocate_all_objects(Head1,SizeT),
    [{1,SegAddr,[],0}| NL] = NL0,
    true = ets:delete_all_objects(SizeT),
    lists:foreach(fun (X)->
        true = ets:insert(SizeT,X) end,NL),
    Bases = lists:foldl(fun ({LSz,P,_D,_N},A)->
        setelement(LSz,A,P) end,erlang:make_tuple(MaxSz,0),NL),
    Est = lists:foldl(fun ({LSz,_,_,N},A)->
        A + (1 bsl (LSz - 1)) * N end,0,NL),
    ok = write_bytes(NewHead,EndOfFile,Est),
    {NewHead,Bases,SegAddr,SegEnd}.

write_bytes(_Head,_EndOfFile,Est)
    when Est < 60 * 8192->
    ok;
write_bytes(Head,EndOfFile,_Est) ->
    Fd = Head#head.fptr,
    {ok,Start} = file:position(Fd,eof),
    BytesToWrite = EndOfFile - Start,
    SizeInKB = 64,
    Bin = list_to_binary(lists:duplicate(SizeInKB * 4,lists:seq(0,255))),
    write_loop(Head,BytesToWrite,Bin).

write_loop(Head,BytesToWrite,Bin)
    when BytesToWrite >= byte_size(Bin)->
    case file:write(Head#head.fptr,Bin) of
        ok->
            write_loop(Head,BytesToWrite - byte_size(Bin),Bin);
        Error->
            dets_utils:file_error(Error,Head#head.filename)
    end;
write_loop(_Head,0,_Bin) ->
    ok;
write_loop(Head,BytesToWrite,Bin) ->
    <<SmallBin:BytesToWrite/binary,_/binary>> = Bin,
    write_loop(Head,BytesToWrite,SmallBin).

allocate_all_objects(Head,SizeT) ->
    DTL = lists:reverse(lists:keysort(1,ets:tab2list(SizeT))),
    MaxSz = element(1,hd(DTL)),
    {Head1,NL} = allocate_all(Head,DTL,[]),
    {_Head,EndOfFile,_} = dets_utils:alloc(Head1,16),
    NewHead = Head1#head{maxobjsize = max_objsize(Head1#head.no_collections)},
    {NewHead,NL,MaxSz,EndOfFile}.

allocate_all(Head,[{1,_,Data,_}],L) ->
    NoParts = no_parts(Head#head.next),
    Addr = 56 + 28 * 4 + 16 + 4 + 124 + 4 * 256 + NoParts * 4 * 512,
    {Head,[{1,Addr,Data,0}| L]};
allocate_all(Head,[{LSize,_,Data,NoCollections}| DTL],L) ->
    Size = 1 bsl (LSize - 1),
    {_Head,Addr,_} = dets_utils:alloc(Head,adjsz(Size)),
    Head1 = dets_utils:alloc_many(Head,Size,NoCollections,Addr),
    NoColls = Head1#head.no_collections,
    NewNoColls = orddict:update_counter(LSize - 1,NoCollections,NoColls),
    NewHead = Head1#head{no_collections = NewNoColls},
    E = {LSize,Addr,Data,NoCollections},
    allocate_all(NewHead,DTL,[E| L]).

bin2term(Bin,Kp) ->
    bin2term1(Bin,Kp,[]).

bin2term1([<<Slot:32,Seq:32,BinTerm/binary>>| BTs],Kp,L) ->
    Term = binary_to_term(BinTerm),
    Key = element(Kp,Term),
    bin2term1(BTs,Kp,[{Slot,Key,Seq,Term,BinTerm}| L]);
bin2term1([],_Kp,L) ->
    lists:reverse(L).

write_all_sizes({} = Cache,_SizeT,_Head,_More) ->
    Cache;
write_all_sizes(Cache,SizeT,Head,More) ->
    CacheL = lists:reverse(tuple_to_list(Cache)),
    Sz = length(CacheL),
    NCL = case ets:info(SizeT,size) of
        1
            when More =:= no_more->
            all_sizes(CacheL,Sz,SizeT);
        _->
            write_sizes(CacheL,Sz,SizeT,Head)
    end,
    list_to_tuple(NCL).

all_sizes([] = CL,_Sz,_SizeT) ->
    CL;
all_sizes([[] = C| CL],Sz,SizeT) ->
    [C| all_sizes(CL,Sz - 1,SizeT)];
all_sizes([C0| CL],Sz,SizeT) ->
    C = lists:reverse(C0),
    NoCollections = length(C),
    true = ets:insert(SizeT,{Sz,0,C,NoCollections}),
    [[]| all_sizes(CL,Sz - 1,SizeT)].

write_sizes([] = CL,_Sz,_SizeT,_Head) ->
    CL;
write_sizes([[] = C| CL],Sz,SizeT,Head) ->
    [C| write_sizes(CL,Sz - 1,SizeT,Head)];
write_sizes([C| CL],Sz,SizeT,Head) ->
    {FileName,Fd} = case ets:lookup(SizeT,Sz) of
        []->
            temp_file(Head,SizeT,Sz);
        [{_,_,{FN,F},_}]->
            {FN,F}
    end,
    NoCollections = length(C),
    _ = ets:update_counter(SizeT,Sz,{4,NoCollections}),
    case file:write(Fd,lists:reverse(C)) of
        ok->
            [[]| write_sizes(CL,Sz - 1,SizeT,Head)];
        Error->
            dets_utils:file_error(FileName,Error)
    end.

output_slots([E| Es],Head,Cache,SizeT,NoKeys,NoObjs) ->
    output_slots(E,Es,[E],Head,Cache,SizeT,NoKeys,NoObjs);
output_slots([],_Head,Cache,SizeT,NoKeys,NoObjs) ->
    _ = ets:update_counter(SizeT,no,{2,NoObjs}),
    _ = ets:update_counter(SizeT,no,{3,NoKeys}),
    {not_a_tuple,[],Cache}.

output_slots(E,[E1| Es],Acc,Head,Cache,SizeT,NoKeys,NoObjs)
    when element(1,E) =:= element(1,E1)->
    output_slots(E1,Es,[E1| Acc],Head,Cache,SizeT,NoKeys,NoObjs);
output_slots(E,[],Acc,_Head,Cache,SizeT,NoKeys,NoObjs) ->
    _ = ets:update_counter(SizeT,no,{2,NoObjs}),
    _ = ets:update_counter(SizeT,no,{3,NoKeys}),
    {E,Acc,Cache};
output_slots(_E,L,Acc,Head,Cache,SizeT,NoKeys,NoObjs) ->
    output_slot(Acc,Head,Cache,L,SizeT,NoKeys,NoObjs).

output_slot(Es,Head,Cache,L,SizeT,NoKeys,NoObjs) ->
    Slot = element(1,hd(Es)),
    {Bins,Size,No,KNo} = prep_slot(lists:sort(Es),Head),
    NNoKeys = NoKeys + KNo,
    NNoObjs = NoObjs + No,
    BSize = Size + 8,
    LSize = sz2pos(BSize),
    Size2 = 1 bsl (LSize - 1),
    Pad = <<0:(Size2 - BSize)/unit:8>>,
    BinObject = [<<BSize:32,305419896:32>>, Bins| Pad],
    Cache1 = if LSize > tuple_size(Cache) ->
        C1 = list_to_tuple(tuple_to_list(Cache) ++ lists:duplicate(LSize - tuple_size(Cache),[])),
        setelement(LSize,C1,[BinObject]);true ->
        CL = element(LSize,Cache),
        setelement(LSize,Cache,[BinObject| CL]) end,
    PBin = <<Slot:32,BSize:32,LSize:8>>,
    PL = element(1,Cache1),
    NCache = setelement(1,Cache1,[PBin| PL]),
    output_slots(L,Head,NCache,SizeT,NNoKeys,NNoObjs).

prep_slot(L,Head)
    when Head#head.type =/= set->
    prep_slot(L,Head,[]);
prep_slot([{_Slot,Key,_Seq,_T,BT}| L],_Head) ->
    prep_set_slot(L,Key,BT,0,0,0,[]).

prep_slot([{_Slot,Key,Seq,T,_BT}| L],Head,W) ->
    prep_slot(L,Head,[{Key,{Seq,{insert,T}}}| W]);
prep_slot([],Head,W) ->
    WLs = dets_utils:family(W),
    {[],Bins,Size,No,KNo,_} = eval_slot(WLs,[],Head#head.type,[],[],0,0,0,false),
    {Bins,Size,No,KNo}.

prep_set_slot([{_,K,_Seq,_T1,BT1}| L],K,_BT,Sz,NoKeys,NoObjs,Ws) ->
    prep_set_slot(L,K,BT1,Sz,NoKeys,NoObjs,Ws);
prep_set_slot([{_,K1,_Seq,_T1,BT1}| L],_K,BT,Sz,NoKeys,NoObjs,Ws) ->
    BSize = byte_size(BT) + 4,
    NWs = [Ws, <<BSize:32>>| BT],
    prep_set_slot(L,K1,BT1,Sz + BSize,NoKeys + 1,NoObjs + 1,NWs);
prep_set_slot([],_K,BT,Sz,NoKeys,NoObjs,Ws) ->
    BSize = byte_size(BT) + 4,
    {[Ws, <<BSize:32>>| BT],Sz + BSize,NoKeys + 1,NoObjs + 1}.

segment_file(SizeT,Head,FileData,SegEnd) ->
    I = 2,
    true = ets:delete_all_objects(SizeT),
    lists:foreach(fun (X)->
        true = ets:insert(SizeT,X) end,FileData),
    [{1,SegAddr,Data,0}| FileData1] = FileData,
    NewData = case Data of
        {InFile,In0}->
            {OutFile,Out} = temp_file(Head,SizeT,I),
            _ = file:close(In0),
            {ok,In} = dets_utils:open(InFile,[raw, binary, read]),
            {ok,0} = dets_utils:position(In,InFile,bof),
            seg_file(SegAddr,SegAddr,In,InFile,Out,OutFile,SizeT,SegEnd),
            _ = file:close(In),
            _ = file:delete(InFile),
            {OutFile,Out};
        Objects->
            {LastAddr,B} = seg_file(Objects,SegAddr,SegAddr,SizeT,[]),
            dets_utils:disk_map_segment(SegAddr,B),
            FinalZ = SegEnd - LastAddr,
            [B| dets_utils:make_zeros(FinalZ)]
    end,
    true = ets:delete_all_objects(SizeT),
    lists:foreach(fun (X)->
        true = ets:insert(SizeT,X) end,[{10000,SegAddr,NewData,0}| FileData1]),
    ok.

seg_file(Addr,SS,In,InFile,Out,OutFile,SizeT,SegEnd) ->
    case dets_utils:read_n(In,4500) of
        eof->
            FinalZ = SegEnd - Addr,
            dets_utils:fwrite(Out,OutFile,dets_utils:make_zeros(FinalZ));
        Bin->
            {NewAddr,L} = seg_file(Bin,Addr,SS,SizeT,[]),
            dets_utils:disk_map_segment(Addr,L),
            ok = dets_utils:fwrite(Out,OutFile,L),
            seg_file(NewAddr,SS,In,InFile,Out,OutFile,SizeT,SegEnd)
    end.

seg_file(<<Slot:32,BSize:32,LSize:8,T/binary>>,Addr,SS,SizeT,L) ->
    seg_file_item(T,Addr,SS,SizeT,L,Slot,BSize,LSize);
seg_file([<<Slot:32,BSize:32,LSize:8>>| T],Addr,SS,SizeT,L) ->
    seg_file_item(T,Addr,SS,SizeT,L,Slot,BSize,LSize);
seg_file([],Addr,_SS,_SizeT,L) ->
    {Addr,lists:reverse(L)};
seg_file(<<>>,Addr,_SS,_SizeT,L) ->
    {Addr,lists:reverse(L)}.

seg_file_item(T,Addr,SS,SizeT,L,Slot,BSize,LSize) ->
    SlotPos = SS + 2 * 4 * Slot,
    NoZeros = SlotPos - Addr,
    PSize = NoZeros + 2 * 4,
    Inc = 1 bsl (LSize - 1),
    CollP = ets:update_counter(SizeT,LSize,Inc) - Inc,
    PointerBin = if NoZeros =:= 0 ->
        <<BSize:32,CollP:32>>;NoZeros > 100 ->
        [dets_utils:make_zeros(NoZeros)| <<BSize:32,CollP:32>>];true ->
        <<0:NoZeros/unit:8,BSize:32,CollP:32>> end,
    seg_file(T,Addr + PSize,SS,SizeT,[PointerBin| L]).

temp_file(Head,SizeT,N) ->
    TmpName = lists:concat([Head#head.filename, '.', N]),
    {ok,Fd} = dets_utils:open(TmpName,[raw, binary, write]),
    true = ets:insert(SizeT,{N,0,{TmpName,Fd},0}),
    {TmpName,Fd}.

fsck_input(Head,Fd,Cntrs,FileHeader) ->
    MaxSz0 = case FileHeader#fileheader.has_md5 of
        true
            when is_list(FileHeader#fileheader.no_colls)->
            1 bsl max_objsize(FileHeader#fileheader.no_colls);
        _->
            case file:position(Fd,eof) of
                {ok,Pos}->
                    Pos;
                _->
                    1 bsl 32
            end
    end,
    MaxSz = max(MaxSz0,8192),
    State0 = fsck_read(56 + 28 * 4 + 16 + 4 + 124 + 4 * 256,Fd,[],0),
    fsck_input(Head,State0,Fd,MaxSz,Cntrs).

fsck_input(Head,State,Fd,MaxSz,Cntrs) ->
    fun (close)->
        ok;(read)->
        case State of
            done->
                end_of_input;
            {done,L,_Seq}->
                R = count_input(L),
                {R,fsck_input(Head,done,Fd,MaxSz,Cntrs)};
            {cont,L,Bin,Pos,Seq}->
                R = count_input(L),
                FR = fsck_objs(Bin,Head#head.keypos,Head,[],Seq),
                NewState = fsck_read(FR,Pos,Fd,MaxSz,Head),
                {R,fsck_input(Head,NewState,Fd,MaxSz,Cntrs)}
        end end.

count_input(L) ->
    lists:reverse(L).

fsck_read(Pos,F,L,Seq) ->
    case file:position(F,Pos) of
        {ok,_}->
            read_more_bytes([],0,Pos,F,L,Seq);
        _Error->
            {done,L,Seq}
    end.

fsck_read({more,Bin,Sz,L,Seq},Pos,F,MaxSz,Head)
    when Sz > MaxSz->
    FR = skip_bytes(Bin,16,Head#head.keypos,Head,L,Seq),
    fsck_read(FR,Pos,F,MaxSz,Head);
fsck_read({more,Bin,Sz,L,Seq},Pos,F,_MaxSz,_Head) ->
    read_more_bytes(Bin,Sz,Pos,F,L,Seq);
fsck_read({new,Skip,L,Seq},Pos,F,_MaxSz,_Head) ->
    NewPos = Pos + Skip,
    fsck_read(NewPos,F,L,Seq).

read_more_bytes(B,Min,Pos,F,L,Seq) ->
    Max = if Min < 8192 ->
        8192;true ->
        Min end,
    case dets_utils:read_n(F,Max) of
        eof->
            {done,L,Seq};
        Bin->
            NewPos = Pos + byte_size(Bin),
            {cont,L,list_to_binary([B, Bin]),NewPos,Seq}
    end.

fsck_objs(Bin = <<Sz:32,Status:32,Tail/binary>>,Kp,Head,L,Seq) ->
    if Status =:= 305419896 ->
        Sz1 = Sz - 8,
        case Tail of
            <<BinTerm:Sz1/binary,Tail2/binary>>->
                case  catch bin2keybins(BinTerm,Head) of
                    {'EXIT',_Reason}->
                        skip_bytes(Bin,16,Kp,Head,L,Seq);
                    BOs->
                        {NL,NSeq} = make_objects(BOs,Seq,Kp,Head,L),
                        Skip = 1 bsl (sz2pos(Sz) - 1) - Sz,
                        skip_bytes(Tail2,Skip,Kp,Head,NL,NSeq)
                end;
            _
                when byte_size(Tail) < Sz1->
                {more,Bin,Sz,L,Seq}
        end;true ->
        skip_bytes(Bin,16,Kp,Head,L,Seq) end;
fsck_objs(Bin,_Kp,_Head,L,Seq) ->
    {more,Bin,0,L,Seq}.

make_objects([{K,BT}| Os],Seq,Kp,Head,L) ->
    Obj = make_object(Head,K,Seq,BT),
    make_objects(Os,Seq + 1,Kp,Head,[Obj| L]);
make_objects([],Seq,_Kp,_Head,L) ->
    {L,Seq}.

make_object(Head,Key,Seq,BT) ->
    Slot = db_hash(Key,Head),
    <<Slot:32,Seq:32,BT/binary>>.

skip_bytes(Bin,Skip,Kp,Head,L,Seq) ->
    case Bin of
        <<_:Skip/binary,Tail/binary>>->
            fsck_objs(Tail,Kp,Head,L,Seq);
        _
            when byte_size(Bin) < Skip->
            {new,Skip - byte_size(Bin),L,Seq}
    end.

do_perform_save(H) ->
    {ok,FreeListsPointer} = dets_utils:position(H,eof),
    H1 = H#head{freelists_p = FreeListsPointer},
    {FLW,FLSize} = free_lists_to_file(H1),
    FileSize = FreeListsPointer + FLSize + 4,
    AdjustedFileSize = case H#head.base of
        56 + 28 * 4 + 16 + 4 + 124 + 4 * 256->
            FileSize;
        Base->
            FileSize - Base
    end,
    ok = dets_utils:write(H1,[FLW| <<AdjustedFileSize:32>>]),
    FileHeader = file_header(H1,FreeListsPointer,1),
    case dets_utils:debug_mode() of
        true->
            TmpHead0 = init_freelist(H1#head{fixed = false}),
            TmpHead = TmpHead0#head{base = H1#head.base},
            case  catch dets_utils:all_allocated_as_list(TmpHead) =:= dets_utils:all_allocated_as_list(H1) of
                true->
                    dets_utils:pwrite(H1,[{0,FileHeader}]);
                _->
                    throw(dets_utils:corrupt_reason(H1,{failed_to_save_free_lists,FreeListsPointer,TmpHead#head.freelists,H1#head.freelists}))
            end;
        false->
            dets_utils:pwrite(H1,[{0,FileHeader}])
    end.

file_header(Head,FreeListsPointer,ClosedProperly) ->
    NoColls = case Head#head.no_collections of
        undefined->
            [];
        NC->
            NC
    end,
    L = orddict:merge(fun (_K,V1,V2)->
        V1 + V2 end,NoColls,lists:map(fun (X)->
        {X,0} end,lists:seq(4,32 - 1))),
    CW = lists:map(fun ({_LSz,N})->
        <<N:32>> end,L),
    file_header(Head,FreeListsPointer,ClosedProperly,CW).

file_header(Head,FreeListsPointer,ClosedProperly,NoColls) ->
    Cookie = 11259375,
    TypeCode = dets_utils:type_to_code(Head#head.type),
    Version = 9,
    HashMethod = hash_method_to_code(Head#head.hash_bif),
    H1 = <<FreeListsPointer:32,Cookie:32,ClosedProperly:32>>,
    H2 = <<TypeCode:32,Version:32,(Head#head.m):32,(Head#head.next):32,(Head#head.keypos):32,(Head#head.no_objects):32,(Head#head.no_keys):32,(Head#head.min_no_slots):32,(Head#head.max_no_slots):32,HashMethod:32,(Head#head.n):32>>,
    DigH = [H2| NoColls],
    MD5 = case Head#head.has_md5 of
        true->
            erlang:md5(DigH);
        false->
            <<0:16/unit:8>>
    end,
    Base = case Head#head.base of
        56 + 28 * 4 + 16 + 4 + 124 + 4 * 256->
            <<0:32>>;
        FlBase->
            <<FlBase:32>>
    end,
    [H1, DigH, MD5, Base| <<0:124/unit:8>>].

free_lists_to_file(H) ->
    FL = dets_utils:get_freelists(H),
    free_list_to_file(FL,H,1,tuple_size(FL),[],0).

free_list_to_file(_Ftab,_H,Pos,Sz,Ws,WsSz)
    when Pos > Sz->
    {[Ws| <<(4 + 8):32,61591023:32,12345:32>>],WsSz + 4 + 8};
free_list_to_file(Ftab,H,Pos,Sz,Ws,WsSz) ->
    Max = (4096 - 4 - 8) div 4,
    F = fun (N,L,W,S)
        when N =:= 0->
        {N,L,W,S};(N,L,W,S)->
        {L1,N1,More} = if N > Max ->
            {lists:sublist(L,Max),Max,{N - Max,lists:nthtail(Max,L)}};true ->
            {L,N,no_more} end,
        Size = N1 * 4 + 4 + 8,
        Header = <<Size:32,61591023:32,Pos:32>>,
        NW = [W, Header| L1],
        case More of
            no_more->
                {0,[],NW,S + Size};
            {NN,NL}->
                ok = dets_utils:write(H,NW),
                {NN,NL,[],S + Size}
        end end,
    {NWs,NWsSz} = dets_utils:tree_to_bin(element(Pos,Ftab),F,Max,Ws,WsSz),
    free_list_to_file(Ftab,H,Pos + 1,Sz,NWs,NWsSz).

free_lists_from_file(H,Pos) ->
    {ok,Pos} = dets_utils:position(H#head.fptr,H#head.filename,Pos),
    FL = dets_utils:empty_free_lists(),
    case  catch bin_to_tree([],H,start,FL,-1,[]) of
        {'EXIT',_}->
            throw({error,{bad_freelists,H#head.filename}});
        Ftab->
            H#head{freelists = Ftab,base = 56 + 28 * 4 + 16 + 4 + 124 + 4 * 256}
    end.

bin_to_tree(Bin,H,LastPos,Ftab,A0,L) ->
    case Bin of
        <<_Size:32,61591023:32,12345:32,_/binary>>
            when L =:= []->
            Ftab;
        <<_Size:32,61591023:32,12345:32,_/binary>>->
            setelement(LastPos,Ftab,dets_utils:list_to_tree(L));
        <<Size:32,61591023:32,Pos:32,T/binary>>
            when byte_size(T) >= Size - 4 - 8->
            {NFtab,L1,A1} = if Pos =/= LastPos,
            LastPos =/= start ->
                Tree = dets_utils:list_to_tree(L),
                {setelement(LastPos,Ftab,Tree),[],-1};true ->
                {Ftab,L,A0} end,
            {NL,B2,A2} = bin_to_tree1(T,Size - 8 - 4,A1,L1),
            bin_to_tree(B2,H,Pos,NFtab,A2,NL);
        _->
            Bin2 = dets_utils:read_n(H#head.fptr,4096),
            bin_to_tree(list_to_binary([Bin| Bin2]),H,LastPos,Ftab,A0,L)
    end.

bin_to_tree1(<<A1:32,A2:32,A3:32,A4:32,T/binary>>,Size,A,L)
    when Size >= 16,
    A < A1,
    A1 < A2,
    A2 < A3,
    A3 < A4->
    bin_to_tree1(T,Size - 16,A4,[A4, A3, A2, A1| L]);
bin_to_tree1(<<A1:32,T/binary>>,Size,A,L)
    when Size >= 4,
    A < A1->
    bin_to_tree1(T,Size - 4,A1,[A1| L]);
bin_to_tree1(B,0,A,L) ->
    {L,B,A}.

slot_objs(H,Slot)
    when Slot >= H#head.next->
    '$end_of_table';
slot_objs(H,Slot) ->
    {ok,_Pointer,Objects} = slot_objects(H,Slot),
    Objects.

h(I,phash2) ->
    erlang:phash2(I);
h(I,phash) ->
    erlang:phash(I,67108863) - 1.

db_hash(Key,Head)
    when Head#head.hash_bif =:= phash2->
    H = erlang:phash2(Key),
    Hash = H band (Head#head.m - 1),
    if Hash < Head#head.n ->
        H band (Head#head.m2 - 1);true ->
        Hash end;
db_hash(Key,Head) ->
    H = h(Key,Head#head.hash_bif),
    Hash = H rem Head#head.m,
    if Hash < Head#head.n ->
        H rem Head#head.m2;true ->
        Hash end.

hash_method_to_code(phash2) ->
    1;
hash_method_to_code(phash) ->
    0.

code_to_hash_method(1) ->
    phash2;
code_to_hash_method(0) ->
    phash;
code_to_hash_method(_) ->
    undefined.

no_slots(Head) ->
    {Head#head.min_no_slots,Head#head.next,Head#head.max_no_slots}.

table_parameters(Head) ->
    case Head#head.no_collections of
        undefined->
            undefined;
        CL->
            NoColls0 = lists:foldl(fun ({_,0},A)->
                A;(E,A)->
                [E| A] end,[],CL),
            NoColls = lists:reverse(NoColls0),
            #'$hash2'{file_format_version = 9,bchunk_format_version = 1,file = filename:basename(Head#head.filename),type = Head#head.type,keypos = Head#head.keypos,hash_method = hash_method_to_code(Head#head.hash_bif),n = Head#head.n,m = Head#head.m,next = Head#head.next,min = Head#head.min_no_slots,max = Head#head.max_no_slots,no_objects = Head#head.no_objects,no_keys = Head#head.no_keys,no_colls = NoColls}
    end.

re_hash(Head,SlotStart) ->
    FromSlotPos = slot_position(SlotStart),
    ToSlotPos = slot_position(SlotStart + Head#head.m),
    RSpec = [{FromSlotPos,4 * 512}],
    {ok,[FromBin]} = dets_utils:pread(RSpec,Head),
    split_bins(FromBin,Head,FromSlotPos,ToSlotPos,[],[],0).

split_bins(<<>>,Head,_Pos1,_Pos2,_ToRead,_L,0) ->
    {Head,ok};
split_bins(<<>>,Head,Pos1,Pos2,ToRead,L,_SoFar) ->
    re_hash_write(Head,ToRead,L,Pos1,Pos2);
split_bins(FB,Head,Pos1,Pos2,ToRead,L,SoFar) ->
    <<Sz1:32,P1:32,FT/binary>> = FB,
    <<B1:8/binary,_/binary>> = FB,
    NSoFar = SoFar + Sz1,
    NPos1 = Pos1 + 2 * 4,
    NPos2 = Pos2 + 2 * 4,
    if NSoFar > 10 * 8192,
    ToRead =/= [] ->
        {NewHead,ok} = re_hash_write(Head,ToRead,L,Pos1,Pos2),
        split_bins(FB,NewHead,Pos1,Pos2,[],[],0);Sz1 =:= 0 ->
        E = {skip,B1},
        split_bins(FT,Head,NPos1,NPos2,ToRead,[E| L],NSoFar);true ->
        E = {Sz1,P1,B1,Pos1,Pos2},
        NewToRead = [{P1,Sz1}| ToRead],
        split_bins(FT,Head,NPos1,NPos2,NewToRead,[E| L],NSoFar) end.

re_hash_write(Head,ToRead,L,Pos1,Pos2) ->
    check_pread2_arg(ToRead,Head),
    {ok,Bins} = dets_utils:pread(ToRead,Head),
    Z = <<0:32,0:32>>,
    {Head1,BinFS,BinTS,WsB} = re_hash_slots(Bins,L,Head,Z,[],[],[]),
    WPos1 = Pos1 - 2 * 4 * length(L),
    WPos2 = Pos2 - 2 * 4 * length(L),
    ToWrite = [{WPos1,BinFS}, {WPos2,BinTS}| WsB],
    dets_utils:pwrite(Head1,ToWrite).

re_hash_slots(Bins,[{skip,B1}| L],Head,Z,BinFS,BinTS,WsB) ->
    re_hash_slots(Bins,L,Head,Z,[B1| BinFS],[Z| BinTS],WsB);
re_hash_slots([FB| Bins],[E| L],Head,Z,BinFS,BinTS,WsB) ->
    {Sz1,P1,B1,Pos1,Pos2} = E,
    KeyObjs = case  catch per_key(Head,FB) of
        {'EXIT',_Error}->
            Bad = dets_utils:bad_object(re_hash_slots,{FB,E}),
            throw(dets_utils:corrupt_reason(Head,Bad));
        Else->
            Else
    end,
    case re_hash_split(KeyObjs,Head,[],0,[],0) of
        {_KL,_KSz,[],0}->
            Sz1 = _KSz + 8,
            re_hash_slots(Bins,L,Head,Z,[B1| BinFS],[Z| BinTS],WsB);
        {[],0,_ML,_MSz}->
            Sz1 = _MSz + 8,
            re_hash_slots(Bins,L,Head,Z,[Z| BinFS],[B1| BinTS],WsB);
        {KL,KSz,ML,MSz}
            when KL =/= [],
            KSz > 0,
            ML =/= [],
            MSz > 0->
            {Head1,FS1,Ws1} = updated(Head,P1,Sz1,KSz,Pos1,KL,true,foo,bar),
            {NewHead,[{Pos2,Bin2}],Ws2} = updated(Head1,0,0,MSz,Pos2,ML,true,foo,bar),
            NewBinFS = case FS1 of
                [{Pos1,Bin1}]->
                    [Bin1| BinFS];
                []->
                    [B1| BinFS]
            end,
            NewBinTS = [Bin2| BinTS],
            NewWsB = Ws2 ++ Ws1 ++ WsB,
            re_hash_slots(Bins,L,NewHead,Z,NewBinFS,NewBinTS,NewWsB)
    end;
re_hash_slots([],[],Head,_Z,BinFS,BinTS,WsB) ->
    {Head,BinFS,BinTS,lists:reverse(WsB)}.

re_hash_split([E| KeyObjs],Head,KL,KSz,ML,MSz) ->
    {Key,Sz,Bin,_Item,_Objs} = E,
    New = h(Key,Head#head.hash_bif) rem Head#head.m2,
    if New >= Head#head.m ->
        re_hash_split(KeyObjs,Head,KL,KSz,[Bin| ML],MSz + Sz);true ->
        re_hash_split(KeyObjs,Head,[Bin| KL],KSz + Sz,ML,MSz) end;
re_hash_split([],_Head,KL,KSz,ML,MSz) ->
    {lists:reverse(KL),KSz,lists:reverse(ML),MSz}.

write_cache(Head) ->
    C = Head#head.cache,
    case dets_utils:is_empty_cache(C) of
        true->
            {Head,[],[]};
        false->
            {NewC,MaxInserts,PerKey} = dets_utils:reset_cache(C),
            MaxNoInsertedKeys = min(MaxInserts,length(PerKey)),
            Head1 = Head#head{cache = NewC},
            case may_grow(Head1,MaxNoInsertedKeys,once) of
                {Head2,ok}->
                    eval_work_list(Head2,PerKey);
                HeadError->
                    throw(HeadError)
            end
    end.

may_grow(Head,0,once) ->
    {Head,ok};
may_grow(Head,_N,_How)
    when Head#head.fixed =/= false->
    {Head,ok};
may_grow(#head{access = read} = Head,_N,_How) ->
    {Head,ok};
may_grow(Head,_N,_How)
    when Head#head.next >= Head#head.max_no_slots->
    {Head,ok};
may_grow(Head,N,How) ->
    Extra = min(2 * 256,Head#head.no_keys + N - Head#head.next),
    case  catch may_grow1(Head,Extra,How) of
        {error,_Reason} = Error->
            dets_utils:corrupt(Head,Error);
        {NewHead,Reply}
            when is_record(Head,head)->
            {NewHead,Reply}
    end.

may_grow1(Head,Extra,many_times)
    when Extra > 256->
    Reply = grow(Head,1,undefined),
    self() ! {'$dets_call',self(),may_grow},
    Reply;
may_grow1(Head,Extra,_How) ->
    grow(Head,Extra,undefined).

grow(Head,Extra,_SegZero)
    when Extra =< 0->
    {Head,ok};
grow(Head,Extra,undefined) ->
    grow(Head,Extra,seg_zero());
grow(Head,_Extra,_SegZero)
    when Head#head.next >= Head#head.max_no_slots->
    {Head,ok};
grow(Head,Extra,SegZero) ->
    #head{n = N,next = Next,m = M} = Head,
    SegNum = Next div 256,
    {Head0,W,Ws1} = allocate_segment(Head,SegZero,SegNum),
    {Head1,ok} = dets_utils:pwrite(Head0,[W| Ws1]),
    {Head2,ok} = re_hash(Head1,N),
    NewHead = if N + 256 =:= M ->
        Head2#head{n = 0,next = Next + 256,m = 2 * M,m2 = 4 * M};true ->
        Head2#head{n = N + 256,next = Next + 256} end,
    true = hash_invars(NewHead),
    grow(NewHead,Extra - 256,SegZero).

hash_invars(H) ->
    hash_invars(H#head.n,H#head.m,H#head.next,H#head.min_no_slots,H#head.max_no_slots).

hash_invars(N,M,Next,Min,Max) ->
    (N band (256 - 1) =:= 0) and (M band (256 - 1) =:= 0) and (Next band (256 - 1) =:= 0) and (Min band (256 - 1) =:= 0) and (Max band (256 - 1) =:= 0) and (0 =< N) and (N =< M) and (N =< 2 * Next) and (M =< Next) and (Next =< 2 * M) and (0 =< Min) and (Min =< Next) and (Next =< Max) and (Min =< M).

seg_zero() ->
    <<0:(4 * 512)/unit:8>>.

find_object(Head,Object) ->
    Key = element(Head#head.keypos,Object),
    Slot = db_hash(Key,Head),
    find_object(Head,Object,Slot).

find_object(H,_Obj,Slot)
    when Slot >= H#head.next->
    false;
find_object(H,Obj,Slot) ->
    case  catch slot_objects(H,Slot) of
        {ok,Pointer,Objects}->
            case lists:member(Obj,Objects) of
                true->
                    {ok,Pointer};
                false->
                    false
            end;
        _->
            false
    end.

slot_objects(Head,Slot) ->
    SlotPos = slot_position(Slot),
    MaxSize = maxobjsize(Head),
    case dets_utils:ipread(Head,SlotPos,MaxSize) of
        {ok,{BucketSz,Pointer,<<BucketSz:32,_St:32,KeysObjs/binary>>}}->
            case  catch bin2objs(KeysObjs,Head#head.type,[]) of
                {'EXIT',_Error}->
                    Bad = dets_utils:bad_object(slot_objects,{SlotPos,KeysObjs}),
                    throw(dets_utils:corrupt_reason(Head,Bad));
                Objs
                    when is_list(Objs)->
                    {ok,Pointer,lists:reverse(Objs)}
            end;
        []->
            {ok,0,[]};
        BadRead->
            Bad = dets_utils:bad_object(slot_objects,{SlotPos,BadRead}),
            throw(dets_utils:corrupt_reason(Head,Bad))
    end.

eval_work_list(Head,[{Key,[{_Seq,{lookup,Pid}}]}]) ->
    SlotPos = slot_position(db_hash(Key,Head)),
    MaxSize = maxobjsize(Head),
    Objs = case dets_utils:ipread(Head,SlotPos,MaxSize) of
        {ok,{_BucketSz,_Pointer,Bin}}->
            case  catch per_key(Head,Bin) of
                {'EXIT',_Error}->
                    Bad = dets_utils:bad_object(eval_work_list,{SlotPos,Bin}),
                    throw(dets_utils:corrupt_reason(Head,Bad));
                KeyObjs
                    when is_list(KeyObjs)->
                    case dets_utils:mkeysearch(Key,1,KeyObjs) of
                        false->
                            [];
                        {value,{Key,_KS,_KB,O,Os}}->
                            case  catch binobjs2terms(Os) of
                                {'EXIT',_Error}->
                                    Bad = dets_utils:bad_object(eval_work_list,{SlotPos,Bin,KeyObjs}),
                                    throw(dets_utils:corrupt_reason(Head,Bad));
                                Terms
                                    when is_list(Terms)->
                                    get_objects([O| Terms])
                            end
                    end
            end;
        []->
            [];
        BadRead->
            Bad = dets_utils:bad_object(eval_work_list,{SlotPos,BadRead}),
            throw(dets_utils:corrupt_reason(Head,Bad))
    end,
    {Head,[{Pid,Objs}],[]};
eval_work_list(Head,PerKey) ->
    SWLs = tag_with_slot(PerKey,Head,[]),
    P1 = dets_utils:family(SWLs),
    {PerSlot,SlotPositions} = remove_slot_tag(P1,[],[]),
    {ok,Bins} = dets_utils:pread(SlotPositions,Head),
    read_buckets(PerSlot,SlotPositions,Bins,Head,[],[],[],[],0,0,0).

tag_with_slot([{K,_} = WL| WLs],Head,L) ->
    tag_with_slot(WLs,Head,[{db_hash(K,Head),WL}| L]);
tag_with_slot([],_Head,L) ->
    L.

remove_slot_tag([{S,SWLs}| SSWLs],Ls,SPs) ->
    remove_slot_tag(SSWLs,[SWLs| Ls],[{slot_position(S),4 * 2}| SPs]);
remove_slot_tag([],Ls,SPs) ->
    {Ls,SPs}.

read_buckets([WLs| SPs],[{P1,_8}| Ss],[<<_Zero:32,P2:32>>| Bs],Head,PWLs,ToRead,LU,Ws,NoObjs,NoKeys,SoFar)
    when P2 =:= 0->
    {NewHead,NLU,NWs,No,KNo} = eval_bucket_keys(WLs,P1,0,0,[],Head,Ws,LU),
    NewNoObjs = No + NoObjs,
    NewNoKeys = KNo + NoKeys,
    read_buckets(SPs,Ss,Bs,NewHead,PWLs,ToRead,NLU,NWs,NewNoObjs,NewNoKeys,SoFar);
read_buckets([WorkLists| SPs],[{P1,_8}| Ss],[<<Size:32,P2:32>>| Bs],Head,PWLs,ToRead,LU,Ws,NoObjs,NoKeys,SoFar)
    when SoFar + Size < 10 * 8192;
    ToRead =:= []->
    NewToRead = [{P2,Size}| ToRead],
    NewPWLs = [{P2,P1,WorkLists}| PWLs],
    NewSoFar = SoFar + Size,
    read_buckets(SPs,Ss,Bs,Head,NewPWLs,NewToRead,LU,Ws,NoObjs,NoKeys,NewSoFar);
read_buckets(SPs,Ss,Bs,Head,PWLs0,ToRead0,LU,Ws,NoObjs,NoKeys,SoFar)
    when SoFar > 0->
    PWLs = lists:keysort(1,PWLs0),
    ToRead = lists:keysort(1,ToRead0),
    check_pread2_arg(ToRead,Head),
    {ok,Bins} = dets_utils:pread(ToRead,Head),
    case  catch eval_buckets(Bins,PWLs,Head,LU,Ws,0,0) of
        {ok,NewHead,NLU,[],0,0}->
            read_buckets(SPs,Ss,Bs,NewHead,[],[],NLU,[],NoObjs,NoKeys,0);
        {ok,Head1,NLU,NWs,No,KNo}->
            NewNoObjs = NoObjs + No,
            NewNoKeys = NoKeys + KNo,
            {NewHead,ok} = dets_utils:pwrite(Head1,lists:reverse(NWs)),
            read_buckets(SPs,Ss,Bs,NewHead,[],[],NLU,[],NewNoObjs,NewNoKeys,0);
        Error->
            Bad = dets_utils:bad_object(read_buckets,{Bins,Error}),
            throw(dets_utils:corrupt_reason(Head,Bad))
    end;
read_buckets([],[],[],Head,[],[],LU,Ws,NoObjs,NoKeys,0) ->
    {NewHead,NWs} = update_no_keys(Head,Ws,NoObjs,NoKeys),
    {NewHead,LU,lists:reverse(NWs)}.

eval_buckets([Bin| Bins],[SP| SPs],Head,LU,Ws,NoObjs,NoKeys) ->
    {Pos,P1,WLs} = SP,
    KeyObjs = per_key(Head,Bin),
    {NewHead,NLU,NWs,No,KNo} = eval_bucket_keys(WLs,P1,Pos,byte_size(Bin),KeyObjs,Head,Ws,LU),
    eval_buckets(Bins,SPs,NewHead,NLU,NWs,NoObjs + No,NoKeys + KNo);
eval_buckets([],[],Head,LU,Ws,NoObjs,NoKeys) ->
    {ok,Head,LU,Ws,NoObjs,NoKeys}.

eval_bucket_keys(WLs,SlotPos,Pos,OldSize,KeyObjs,Head,Ws,LU) ->
    {NLU,Bins,BSize,No,KNo,Ch} = eval_slot(WLs,KeyObjs,Head#head.type,LU,[],0,0,0,false),
    {NewHead,W1,W2} = updated(Head,Pos,OldSize,BSize,SlotPos,Bins,Ch,No,KNo),
    {NewHead,NLU,W2 ++ W1 ++ Ws,No,KNo}.

updated(Head,Pos,OldSize,BSize,SlotPos,Bins,Ch,DeltaNoOs,DeltaNoKs) ->
    BinsSize = BSize + 8,
    if Pos =:= 0,
    BSize =:= 0 ->
        {Head,[],[]};Pos =:= 0,
    BSize > 0 ->
        {Head1,NewPos,FPos} = dets_utils:alloc(Head,adjsz(BinsSize)),
        NewHead = one_bucket_added(Head1,FPos - 1),
        W1 = {NewPos,[<<BinsSize:32,305419896:32>>| Bins]},
        W2 = {SlotPos,<<BinsSize:32,NewPos:32>>},
        {NewHead,[W2],[W1]};Pos =/= 0,
    BSize =:= 0 ->
        {Head1,FPos} = dets_utils:free(Head,Pos,adjsz(OldSize)),
        NewHead = one_bucket_removed(Head1,FPos - 1),
        W1 = {Pos + 4,<<61591023:32>>},
        W2 = {SlotPos,<<0:32,0:32>>},
        {NewHead,[W2],[W1]};Pos =/= 0,
    BSize > 0,
    Ch =:= false ->
        {Head,[],[]};Pos =/= 0,
    BSize > 0 ->
        Overwrite0 = if OldSize =:= BinsSize ->
            same;true ->
            sz2pos(OldSize) =:= sz2pos(BinsSize) end,
        Overwrite = if Head#head.fixed =/= false ->
            (Overwrite0 =/= false) and (DeltaNoOs =:= 0) and (DeltaNoKs =:= 0);true ->
            Overwrite0 end,
        if Overwrite =:= same ->
            W1 = {Pos + 8,Bins},
            {Head,[],[W1]};Overwrite ->
            W1 = {Pos,[<<BinsSize:32,305419896:32>>| Bins]},
            W2 = {SlotPos,<<BinsSize:32,Pos:32>>},
            {Head,[W2],[W1]};true ->
            {Head1,FPosF} = dets_utils:free(Head,Pos,adjsz(OldSize)),
            {Head2,NewPos,FPosA} = dets_utils:alloc(Head1,adjsz(BinsSize)),
            Head3 = one_bucket_added(Head2,FPosA - 1),
            NewHead = one_bucket_removed(Head3,FPosF - 1),
            W0 = {NewPos,[<<BinsSize:32,305419896:32>>| Bins]},
            W2 = {SlotPos,<<BinsSize:32,NewPos:32>>},
            W1 = if Pos =/= NewPos ->
                [W0, {Pos + 4,<<61591023:32>>}];true ->
                [W0] end,
            {NewHead,[W2],W1} end end.

one_bucket_added(H,_Log2)
    when H#head.no_collections =:= undefined->
    H;
one_bucket_added(H,Log2)
    when H#head.maxobjsize >= Log2->
    NewNoColls = orddict:update_counter(Log2,1,H#head.no_collections),
    H#head{no_collections = NewNoColls};
one_bucket_added(H,Log2) ->
    NewNoColls = orddict:update_counter(Log2,1,H#head.no_collections),
    H#head{no_collections = NewNoColls,maxobjsize = Log2}.

one_bucket_removed(H,_FPos)
    when H#head.no_collections =:= undefined->
    H;
one_bucket_removed(H,Log2)
    when H#head.maxobjsize > Log2->
    NewNoColls = orddict:update_counter(Log2,-1,H#head.no_collections),
    H#head{no_collections = NewNoColls};
one_bucket_removed(H,Log2)
    when H#head.maxobjsize =:= Log2->
    NewNoColls = orddict:update_counter(Log2,-1,H#head.no_collections),
    MaxObjSize = max_objsize(NewNoColls),
    H#head{no_collections = NewNoColls,maxobjsize = MaxObjSize}.

eval_slot([{Key,Commands}| WLs] = WLs0,[{K,KS,KB,O,Os}| KOs1] = KOs,Type,LU,Ws,No,KNo,BSz,Ch) ->
    case dets_utils:cmp(K,Key) of
        0->
            Old = [O| binobjs2terms(Os)],
            {NLU,NWs,Sz,No1,KNo1,NCh} = eval_key(Key,Commands,Old,Type,KB,KS,LU,Ws,Ch),
            eval_slot(WLs,KOs1,Type,NLU,NWs,No1 + No,KNo1 + KNo,Sz + BSz,NCh);
        -1->
            eval_slot(WLs0,KOs1,Type,LU,[Ws| KB],No,KNo,KS + BSz,Ch);
        1->
            {NLU,NWs,Sz,No1,KNo1,NCh} = eval_key(Key,Commands,[],Type,[],0,LU,Ws,Ch),
            eval_slot(WLs,KOs,Type,NLU,NWs,No1 + No,KNo1 + KNo,Sz + BSz,NCh)
    end;
eval_slot([{Key,Commands}| WLs],[],Type,LU,Ws,No,KNo,BSz,Ch) ->
    {NLU,NWs,Sz,No1,KNo1,NCh} = eval_key(Key,Commands,[],Type,[],0,LU,Ws,Ch),
    eval_slot(WLs,[],Type,NLU,NWs,No1 + No,KNo1 + KNo,Sz + BSz,NCh);
eval_slot([],[{_Key,Size,KeyBin,_,_}| KOs],Type,LU,Ws,No,KNo,BSz,Ch) ->
    eval_slot([],KOs,Type,LU,[Ws| KeyBin],No,KNo,Size + BSz,Ch);
eval_slot([],[],_Type,LU,Ws,No,KNo,BSz,Ch) ->
    {LU,Ws,BSz,No,KNo,Ch}.

eval_key(_K,[{_Seq,{lookup,Pid}}],[],_Type,_KeyBin,_KeySz,LU,Ws,Ch) ->
    NLU = [{Pid,[]}| LU],
    {NLU,Ws,0,0,0,Ch};
eval_key(_K,[{_Seq,{lookup,Pid}}],Old0,_Type,KeyBin,KeySz,LU,Ws,Ch) ->
    Old = lists:keysort(2,Old0),
    Objs = get_objects(Old),
    NLU = [{Pid,Objs}| LU],
    {NLU,[Ws| KeyBin],KeySz,0,0,Ch};
eval_key(K,Comms,Orig,Type,KeyBin,KeySz,LU,Ws,Ch) ->
    Old = dets_utils:msort(Orig),
    case eval_key1(Comms,[],Old,Type,K,LU,Ws,0,Orig) of
        {ok,NLU}
            when Old =:= []->
            {NLU,Ws,0,0,0,Ch};
        {ok,NLU}->
            {NLU,[Ws| KeyBin],KeySz,0,0,Ch};
        {NLU,NWs,NSz,No}
            when Old =:= [],
            NSz > 0->
            {NLU,NWs,NSz,No,1,true};
        {NLU,NWs,NSz,No}
            when Old =/= [],
            NSz =:= 0->
            {NLU,NWs,NSz,No,-1,true};
        {NLU,NWs,NSz,No}->
            {NLU,NWs,NSz,No,0,true}
    end.

eval_key1([{_Seq,{insert,Term}}| L],Cs,[{Term,_,_}] = Old,Type = set,K,LU,Ws,No,Orig) ->
    eval_key1(L,Cs,Old,Type,K,LU,Ws,No,Orig);
eval_key1([{Seq,{insert,Term}}| L],Cs,Old,Type = set,K,LU,Ws,No,Orig) ->
    NNo = No + 1 - length(Old),
    eval_key1(L,Cs,[{Term,Seq,insert}],Type,K,LU,Ws,NNo,Orig);
eval_key1([{_Seq,{lookup,Pid}}| L],Cs,Old,Type,Key,LU,Ws,No,Orig) ->
    {ok,New0,NewNo} = eval_comms(Cs,Old,Type,No),
    New = lists:keysort(2,New0),
    Objs = get_objects(New),
    NLU = [{Pid,Objs}| LU],
    if L =:= [] ->
        eval_end(New,NLU,Type,Ws,NewNo,Orig);true ->
        NewOld = dets_utils:msort(New),
        eval_key1(L,[],NewOld,Type,Key,NLU,Ws,NewNo,Orig) end;
eval_key1([{_Seq,delete_key}| L],_Cs,Old,Type,K,LU,Ws,No,Orig) ->
    NewNo = No - length(Old),
    eval_key1(L,[],[],Type,K,LU,Ws,NewNo,Orig);
eval_key1([{_Seq,{delete_object,Term}}| L],Cs,[{Term,_,_}],Type = set,K,LU,Ws,No,Orig) ->
    eval_key1(L,Cs,[],Type,K,LU,Ws,No - 1,Orig);
eval_key1([{_Seq,{delete_object,_T}}| L],Cs,Old1,Type = set,K,LU,Ws,No,Orig) ->
    eval_key1(L,Cs,Old1,Type,K,LU,Ws,No,Orig);
eval_key1([{Seq,{Comm,Term}}| L],Cs,Old,Type,K,LU,Ws,No,Orig)
    when Type =/= set->
    eval_key1(L,[{Term,Seq,Comm}| Cs],Old,Type,K,LU,Ws,No,Orig);
eval_key1([],Cs,Old,Type = set,_Key,LU,Ws,No,Orig) ->
    [] = Cs,
    eval_end(Old,LU,Type,Ws,No,Orig);
eval_key1([],Cs,Old,Type,_Key,LU,Ws,No,Orig) ->
    {ok,New,NewNo} = eval_comms(Cs,Old,Type,No),
    eval_end(New,LU,Type,Ws,NewNo,Orig).

eval_comms([],L,_Type = set,No) ->
    {ok,L,No};
eval_comms(Cs,Old,Type,No) ->
    Commands = dets_utils:msort(Cs),
    case Type of
        bag->
            eval_bag(Commands,Old,[],No);
        duplicate_bag->
            eval_dupbag(Commands,Old,[],No)
    end.

eval_end(New0,LU,Type,Ws,NewNo,Orig) ->
    New = lists:keysort(2,New0),
    NoChange = if length(New) =/= length(Orig) ->
        false;true ->
        same_terms(Orig,New) end,
    if NoChange ->
        {ok,LU};New =:= [] ->
        {LU,Ws,0,NewNo};true ->
        {Ws1,Sz} = make_bins(New,[],0),
        if Type =:= set ->
            {LU,[Ws| Ws1],Sz,NewNo};true ->
            NSz = Sz + 4,
            {LU,[Ws, <<NSz:32>>| Ws1],NSz,NewNo} end end.

same_terms([E1| L1],[E2| L2])
    when element(1,E1) =:= element(1,E2)->
    same_terms(L1,L2);
same_terms([],[]) ->
    true;
same_terms(_L1,_L2) ->
    false.

make_bins([{_Term,_Seq,B}| L],W,Sz)
    when is_binary(B)->
    make_bins(L,[W| B],Sz + byte_size(B));
make_bins([{Term,_Seq,insert}| L],W,Sz) ->
    B = term_to_binary(Term),
    BSize = byte_size(B) + 4,
    make_bins(L,[W, [<<BSize:32>>| B]],Sz + BSize);
make_bins([],W,Sz) ->
    {W,Sz}.

get_objects([{T,_S,_BT}| L]) ->
    [T| get_objects(L)];
get_objects([]) ->
    [].

eval_bag([{Term1,_S1,Op} = N| L] = L0,[{Term2,_,_} = O| Old] = Old0,New,No) ->
    case {Op,dets_utils:cmp(Term1,Term2)} of
        {delete_object,-1}->
            eval_bag(L,Old0,New,No);
        {insert,-1}->
            bag_object(L,Old0,New,No,[N],Term1);
        {delete_object,0}->
            bag_object(L,Old,New,No - 1,[],Term1);
        {insert,0}->
            bag_object(L,Old,New,No - 1,[N],Term1);
        {_,1}->
            eval_bag(L0,Old,[O| New],No)
    end;
eval_bag([{_Term1,_Seq1,delete_object}| L],[] = Old,New,No) ->
    eval_bag(L,Old,New,No);
eval_bag([{Term,_Seq1,insert} = N| L],[] = Old,New,No) ->
    bag_object(L,Old,New,No,[N],Term);
eval_bag([] = L,[O| Old],New,No) ->
    eval_bag(L,Old,[O| New],No);
eval_bag([],[],New,No) ->
    {ok,New,No}.

bag_object([{Term,_,insert} = N| L],Old,New,No,_N,Term) ->
    bag_object(L,Old,New,No,[N],Term);
bag_object([{Term,_,delete_object}| L],Old,New,No,_N,Term) ->
    bag_object(L,Old,New,No,[],Term);
bag_object(L,Old,New,No,[],_Term) ->
    eval_bag(L,Old,New,No);
bag_object(L,Old,New,No,[N],_Term) ->
    eval_bag(L,Old,[N| New],No + 1).

eval_dupbag([{Term1,_S1,Op} = N| L] = L0,[{Term2,_,_} = O| Old] = Old0,New,No) ->
    case {Op,dets_utils:cmp(Term1,Term2)} of
        {delete_object,-1}->
            eval_dupbag(L,Old0,New,No);
        {insert,-1}->
            dup_object(L,Old0,New,No + 1,Term1,[N]);
        {_,0}->
            old_dup_object(L0,Old,New,No,Term1,[O]);
        {_,1}->
            eval_dupbag(L0,Old,[O| New],No)
    end;
eval_dupbag([{_Term1,_Seq1,delete_object}| L],[] = Old,New,No) ->
    eval_dupbag(L,Old,New,No);
eval_dupbag([{Term,_Seq1,insert} = N| L],[] = Old,New,No) ->
    dup_object(L,Old,New,No + 1,Term,[N]);
eval_dupbag([] = L,[O| Old],New,No) ->
    eval_dupbag(L,Old,[O| New],No);
eval_dupbag([],[],New,No) ->
    {ok,New,No}.

old_dup_object(L,[{Term,_,_} = Obj| Old],New,No,Term,N) ->
    old_dup_object(L,Old,New,No,Term,[Obj| N]);
old_dup_object(L,Old,New,No,Term,N) ->
    dup_object(L,Old,New,No,Term,N).

dup_object([{Term,_,insert} = Obj| L],Old,New,No,Term,Q) ->
    dup_object(L,Old,New,No + 1,Term,[Obj| Q]);
dup_object([{Term,_Seq,delete_object}| L],Old,New,No,Term,Q) ->
    NewNo = No - length(Q),
    dup_object(L,Old,New,NewNo,Term,[]);
dup_object(L,Old,New,No,_Term,Q) ->
    eval_dupbag(L,Old,Q ++ New,No).

update_no_keys(Head,Ws,0,0) ->
    {Head,Ws};
update_no_keys(Head,Ws,DeltaObjects,DeltaKeys) ->
    NoKeys = Head#head.no_keys,
    NewNoKeys = NoKeys + DeltaKeys,
    NewNoObject = Head#head.no_objects + DeltaObjects,
    NewHead = Head#head{no_objects = NewNoObject,no_keys = NewNoKeys},
    NWs = if NewNoKeys > NewHead#head.max_no_slots ->
        Ws;NoKeys div 256 =:= NewNoKeys div 256 ->
        Ws;true ->
        [{0,file_header(NewHead,0,0)}| Ws] end,
    {NewHead,NWs}.

slot_position(S) ->
    SegNo = S bsr 8,
    PartPos = 56 + 28 * 4 + 16 + 4 + 124 + 4 * (SegNo bsr 9),
    Part = get_arrpart(PartPos),
    Pos = Part + 4 * (SegNo band (512 - 1)),
    get_segp(Pos) + 4 * 2 * (S band (256 - 1)).

check_pread2_arg([{_Pos,Sz}],Head)
    when Sz > 10 * 8192->
    case check_pread_arg(Sz,Head) of
        true->
            ok;
        false->
            Bad = dets_utils:bad_object(check_pread2_arg,Sz),
            throw(dets_utils:corrupt_reason(Head,Bad))
    end;
check_pread2_arg(_ToRead,_Head) ->
    ok.

check_pread_arg(Sz,Head)
    when Sz > 10 * 8192->
    maxobjsize(Head) >= Sz;
check_pread_arg(_Sz,_Head) ->
    true.

segp_cache(Pos,Segment) ->
    put(Pos,Segment).

get_segp(Pos) ->
    get(Pos).

arrpart_cache(Pos,ArrPart) ->
    put(Pos,ArrPart).

get_arrpart(Pos) ->
    get(Pos).

sz2pos(N) ->
    1 + dets_utils:log2(N).

adjsz(N) ->
    N - 1.

maxobjsize(Head)
    when Head#head.maxobjsize =:= undefined->
    1 bsl 32;
maxobjsize(Head) ->
    1 bsl Head#head.maxobjsize.

scan_objs(Head,Bin,From,To,L,Ts,R,Type) ->
    case  catch scan_skip(Bin,From,To,L,Ts,R,Type,0) of
        {'EXIT',_Reason}->
            bad_object;
        Reply = {more,_From1,_To,_L,_Ts,_R,Size}
            when Size > 10 * 8192->
            case check_pread_arg(Size,Head) of
                true->
                    Reply;
                false->
                    bad_object
            end;
        Reply->
            Reply
    end.

scan_skip(Bin,From,To,L,Ts,R,Type,Skip) ->
    From1 = From + Skip,
    case Bin of
        _
            when From1 >= To->
            if From1 > To;
            L =:= <<>> ->
                {more,From1,To,L,Ts,R,0};true ->
                <<From2:32,To1:32,L1/binary>> = L,
                Skip1 = From2 - From,
                scan_skip(Bin,From,To1,L1,Ts,R,Type,Skip1) end;
        <<_:Skip/binary,_Size:32,St:32,_Sz:32,KO/binary>>
            when St =/= 305419896,
            St =/= 61591023->
            scan_skip(KO,From1 + 12,To,L,Ts,R,Type,512 * 4 - 12);
        <<_:Skip/binary,Size:32,_St:32,Sz:32,KO/binary>>
            when Size - 12 =< byte_size(KO)->
            bin2bins(KO,From1 + 12,To,L,Ts,R,Type,Size,Sz);
        <<_:Skip/binary,Size:32,_St:32,_Sz:32,_KO/binary>>->
            {more,From1,To,L,Ts,R,Size};
        _
            when Skip >= 0->
            {more,From1,To,L,Ts,R,0}
    end.

bin2bins(Bin,From,To,L,Ts,R,Type = set,Size,ObjSz0) ->
    ObjsSz1 = Size - ObjSz0,
    if ObjsSz1 =:= 8 ->
        slot_end(Bin,From,To,L,[Bin| Ts],R,Type,Size,1);true ->
        ObjSz = ObjSz0 - 4,
        <<_:ObjSz/binary,NObjSz:32,T/binary>> = Bin,
        bins_set(T,From,To,L,[Bin| Ts],R,Type,Size,2,NObjSz,ObjsSz1 - NObjSz,Bin) end;
bin2bins(<<ObjSz:32,Bin/binary>> = KO,From,To,L,Ts,R,Type,Size,Sz) ->
    bins_bag(Bin,From,To,L,Ts,R,Type,Size,1,Sz - ObjSz - 4,ObjSz - 4,Size - Sz,KO).

bins_set(Bin,From,To,L,Ts,R,Type,Size,NoObjs,_ObjSz0,8,KO) ->
    slot_end(KO,From,To,L,[Bin| Ts],R,Type,Size,NoObjs);
bins_set(Bin,From,To,L,Ts,R,Type,Size,NoObjs,ObjSz0,ObjsSz,KO) ->
    ObjSz = ObjSz0 - 4,
    <<_:ObjSz/binary,NObjSz:32,T/binary>> = Bin,
    bins_set(T,From,To,L,[Bin| Ts],R,Type,Size,NoObjs + 1,NObjSz,ObjsSz - NObjSz,KO).

bins_bag(Bin,From,To,L,Ts,R,Type,Size,NoObjs,Sz,ObjSz,ObjsSz,KO)
    when Sz > 0->
    <<_:ObjSz/binary,NObjSz:32,T/binary>> = Bin,
    bins_bag(T,From,To,L,[Bin| Ts],R,Type,Size,NoObjs + 1,Sz - NObjSz,NObjSz - 4,ObjsSz,KO);
bins_bag(Bin,From,To,L,Ts,R,Type,Size,NoObjs,_Z,_ObjSz,8,KO) ->
    slot_end(KO,From,To,L,[Bin| Ts],R,Type,Size,NoObjs);
bins_bag(Bin,From,To,L,Ts,R,Type,Size,NoObjs,_Z,ObjSz,ObjsSz,KO) ->
    <<_:ObjSz/binary,Sz:32,NObjSz:32,T/binary>> = Bin,
    bins_bag(T,From,To,L,[Bin| Ts],R,Type,Size,NoObjs + 1,Sz - NObjSz - 4,NObjSz - 4,ObjsSz - Sz,KO).

slot_end(KO,From,To,L,Ts,R,Type,Size,NoObjs) ->
    Skip = 1 bsl dets_utils:log2(Size) - 12,
    if R >= 0 ->
        scan_skip(KO,From,To,L,Ts,R + Size,Type,Skip);true ->
        case R + NoObjs of
            R1
                when R1 >= -1->
                From1 = From + Skip,
                Bin1 = case KO of
                    <<_:Skip/binary,B/binary>>->
                        B;
                    _->
                        <<>>
                end,
                {stop,Bin1,From1,To,L,Ts};
            R1->
                scan_skip(KO,From,To,L,Ts,R1,Type,Skip)
        end end.

file_info(FH) ->
    #fileheader{closed_properly = CP,keypos = Kp,m = M,next = Next,n = N,version = Version,type = Type,no_objects = NoObjects,no_keys = NoKeys} = FH,
    if CP =:= 0 ->
        {error,not_closed};FH#fileheader.cookie =/= 11259375 ->
        {error,not_a_dets_file};FH#fileheader.version =/= 9 ->
        {error,bad_version};true ->
        {ok,[{closed_properly,CP}, {keypos,Kp}, {m,M}, {n,N}, {next,Next}, {no_objects,NoObjects}, {no_keys,NoKeys}, {type,Type}, {version,Version}]} end.

v_segments(#head{} = H) ->
    v_parts(H,0,0).

v_parts(_H,256,_SegNo) ->
    done;
v_parts(H,PartNo,SegNo) ->
    Fd = H#head.fptr,
    PartPos = dets_utils:read_4(Fd,56 + 28 * 4 + 16 + 4 + 124 + 4 * PartNo),
    if PartPos =:= 0 ->
        done;true ->
        PartBin = dets_utils:pread_n(Fd,PartPos,512 * 4),
        v_segments(H,PartBin,PartNo + 1,SegNo) end.

v_segments(H,<<>>,PartNo,SegNo) ->
    v_parts(H,PartNo,SegNo);
v_segments(_H,<<0:32,_/binary>>,_PartNo,_SegNo) ->
    done;
v_segments(H,<<Seg:32,T/binary>>,PartNo,SegNo) ->
    io:format("<~w>SEGMENT ~w~n",[Seg, SegNo]),
    v_segment(H,SegNo,Seg,0),
    v_segments(H,T,PartNo,SegNo + 1).

v_segment(_H,_,_SegPos,256) ->
    done;
v_segment(H,SegNo,SegPos,SegSlot) ->
    Slot = SegSlot + SegNo * 256,
    BucketP = SegPos + 4 * 2 * SegSlot,
    case  catch read_bucket(H,BucketP,H#head.type) of
        {'EXIT',Reason}->
            dets_utils:vformat("** dets: Corrupt or truncated dets file" "~n",[]),
            io:format("~nERROR ~tp~n",[Reason]);
        []->
            true;
        {Size,CollP,Objects}->
            io:format("   <~w>~w: <~w:~p>~w~n",[BucketP, Slot, CollP, Size, Objects])
    end,
    v_segment(H,SegNo,SegPos,SegSlot + 1).

read_bucket(Head,Position,Type) ->
    MaxSize = maxobjsize(Head),
    case dets_utils:ipread(Head,Position,MaxSize) of
        {ok,{Size,Pointer,<<Size:32,_Status:32,KeysObjs/binary>>}}->
            Objs = bin2objs(KeysObjs,Type,[]),
            {Size,Pointer,lists:reverse(Objs)};
        []->
            []
    end.

per_key(Head,<<BinSize:32,305419896:32,Bin/binary>> = B) ->
    true = byte_size(B) =:= BinSize,
    if Head#head.type =:= set ->
        per_set_key(Bin,Head#head.keypos,[]);true ->
        per_bag_key(Bin,Head#head.keypos,[]) end.

per_set_key(<<Size:32,T/binary>> = B,KeyPos,L) ->
    <<KeyBin:Size/binary,R/binary>> = B,
    Term = binary_to_term(T),
    Key = element(KeyPos,Term),
    Item = {Term,-(1 bsl 26),KeyBin},
    per_set_key(R,KeyPos,[{Key,Size,KeyBin,Item,[]}| L]);
per_set_key(<<>>,KeyPos,L)
    when is_integer(KeyPos)->
    lists:reverse(L).

per_bag_key(<<Size:32,ObjSz:32,T/binary>> = B,KeyPos,L) ->
    <<KeyBin:Size/binary,R/binary>> = B,
    ObjSz1 = ObjSz - 4,
    Size1 = Size - ObjSz - 4,
    <<_:ObjSz1/binary,KeyObjs:Size1/binary,_/binary>> = T,
    <<_Size:32,Bin:ObjSz/binary,_/binary>> = B,
    Term = binary_to_term(T),
    Key = element(KeyPos,Term),
    Item = {Term,-(1 bsl 26),Bin},
    per_bag_key(R,KeyPos,[{Key,Size,KeyBin,Item,KeyObjs}| L]);
per_bag_key(<<>>,KeyPos,L)
    when is_integer(KeyPos)->
    lists:reverse(L).

binobjs2terms(<<ObjSz:32,T/binary>> = B) ->
    binobjs2terms(B,T,ObjSz,byte_size(B) - ObjSz,-(1 bsl 26) + 1,[]);
binobjs2terms([] = B) ->
    B;
binobjs2terms(<<>>) ->
    [].

binobjs2terms(Bin,Obj,_ObjSz,_Size = 0,N,L) ->
    lists:reverse(L,[{binary_to_term(Obj),N,Bin}]);
binobjs2terms(Bin,Bin1,ObjSz,Size,N,L) ->
    <<B:ObjSz/binary,T/binary>> = Bin,
    <<NObjSz:32,T1/binary>> = T,
    Item = {binary_to_term(Bin1),N,B},
    binobjs2terms(T,T1,NObjSz,Size - NObjSz,N + 1,[Item| L]).

bin2objs(KeysObjs,set,Ts) ->
    <<ObjSz:32,T/binary>> = KeysObjs,
    bin2objs(T,ObjSz - 4,byte_size(KeysObjs) - ObjSz,Ts);
bin2objs(KeysObjs,_Type,Ts) ->
    bin2objs2(KeysObjs,Ts).

bin2objs2(<<Size:32,ObjSz:32,T/binary>>,Ts) ->
    bin2objs(T,ObjSz - 4,Size - ObjSz - 4,Ts);
bin2objs2(<<>>,Ts) ->
    Ts.

bin2objs(Bin,ObjSz,_Size = 0,Ts) ->
    <<_:ObjSz/binary,T/binary>> = Bin,
    bin2objs2(T,[binary_to_term(Bin)| Ts]);
bin2objs(Bin,ObjSz,Size,Ts) ->
    <<_:ObjSz/binary,NObjSz:32,T/binary>> = Bin,
    bin2objs(T,NObjSz - 4,Size - NObjSz,[binary_to_term(Bin)| Ts]).

bin2keybins(KeysObjs,Head)
    when Head#head.type =:= set->
    <<ObjSz:32,T/binary>> = KeysObjs,
    bin2keybins(T,Head#head.keypos,ObjSz - 4,byte_size(KeysObjs) - ObjSz,[]);
bin2keybins(KeysObjs,Head) ->
    bin2keybins2(KeysObjs,Head#head.keypos,[]).

bin2keybins2(<<Size:32,ObjSz:32,T/binary>>,Kp,L) ->
    bin2keybins(T,Kp,ObjSz - 4,Size - ObjSz - 4,L);
bin2keybins2(<<>>,Kp,L)
    when is_integer(Kp)->
    lists:reverse(L).

bin2keybins(Bin,Kp,ObjSz,_Size = 0,L) ->
    <<Obj:ObjSz/binary,T/binary>> = Bin,
    Term = binary_to_term(Obj),
    bin2keybins2(T,Kp,[{element(Kp,Term),Obj}| L]);
bin2keybins(Bin,Kp,ObjSz,Size,L) ->
    <<Obj:ObjSz/binary,NObjSz:32,T/binary>> = Bin,
    Term = binary_to_term(Obj),
    bin2keybins(T,Kp,NObjSz - 4,Size - NObjSz,[{element(Kp,Term),Obj}| L]).