-file("sets.erl", 1).

-module(sets).

-export([new/0, is_set/1, size/1, is_empty/1, to_list/1, from_list/1]).

-export([is_element/2, add_element/2, del_element/2]).

-export([union/2, union/1, intersection/2, intersection/1]).

-export([is_disjoint/2]).

-export([subtract/2, is_subset/2]).

-export([fold/3, filter/2]).

-export_type([set/0, set/1]).

-type(seg()::tuple()).

-type(segs(_Element)::tuple()).

-record(set,{size = 0::non_neg_integer(),n = 16::non_neg_integer(),maxn = 16::pos_integer(),bso = 16 div 2::non_neg_integer(),exp_size = 16 * 5::non_neg_integer(),con_size = 16 * 3::non_neg_integer(),empty::seg(),segs::segs(_)}).

-type(set()::set(_)).

-opaque(set(Element)::#set{segs::segs(Element)}).

-spec(new() -> set()).

new() ->
    Empty = mk_seg(16),
    #set{empty = Empty,segs = {Empty}}.

-spec(is_set(Set) -> boolean() when Set::term()).

is_set(#set{}) ->
    true;
is_set(_) ->
    false.

-spec(size(Set) -> non_neg_integer() when Set::set()).

size(S) ->
    S#set.size.

-spec(is_empty(Set) -> boolean() when Set::set()).

is_empty(S) ->
    S#set.size =:= 0.

-spec(to_list(Set) -> List when Set::set(Element),List::[Element]).

to_list(S) ->
    fold(fun (Elem,List)->
        [Elem| List] end,[],S).

-spec(from_list(List) -> Set when List::[Element],Set::set(Element)).

from_list(L) ->
    lists:foldl(fun (E,S)->
        add_element(E,S) end,new(),L).

-spec(is_element(Element,Set) -> boolean() when Set::set(Element)).

is_element(E,S) ->
    Slot = get_slot(S,E),
    Bkt = get_bucket(S,Slot),
    lists:member(E,Bkt).

-spec(add_element(Element,Set1) -> Set2 when Set1::set(Element),Set2::set(Element)).

add_element(E,S0) ->
    Slot = get_slot(S0,E),
    Bkt = get_bucket(S0,Slot),
    case lists:member(E,Bkt) of
        true->
            S0;
        false->
            S1 = update_bucket(S0,Slot,[E| Bkt]),
            maybe_expand(S1)
    end.

-spec(del_element(Element,Set1) -> Set2 when Set1::set(Element),Set2::set(Element)).

del_element(E,S0) ->
    Slot = get_slot(S0,E),
    Bkt = get_bucket(S0,Slot),
    case lists:member(E,Bkt) of
        false->
            S0;
        true->
            S1 = update_bucket(S0,Slot,lists:delete(E,Bkt)),
            maybe_contract(S1,1)
    end.

-spec(update_bucket(Set1,Slot,Bkt) -> Set2 when Set1::set(Element),Set2::set(Element),Slot::non_neg_integer(),Bkt::[Element]).

update_bucket(Set,Slot,NewBucket) ->
    SegI = (Slot - 1) div 16 + 1,
    BktI = (Slot - 1) rem 16 + 1,
    Segs = Set#set.segs,
    Seg = element(SegI,Segs),
    Set#set{segs = setelement(SegI,Segs,setelement(BktI,Seg,NewBucket))}.

-spec(union(Set1,Set2) -> Set3 when Set1::set(Element),Set2::set(Element),Set3::set(Element)).

union(S1,S2)
    when S1#set.size < S2#set.size->
    fold(fun (E,S)->
        add_element(E,S) end,S2,S1);
union(S1,S2) ->
    fold(fun (E,S)->
        add_element(E,S) end,S1,S2).

-spec(union(SetList) -> Set when SetList::[set(Element)],Set::set(Element)).

union([S1, S2| Ss]) ->
    union1(union(S1,S2),Ss);
union([S]) ->
    S;
union([]) ->
    new().

-spec(union1(set(E),[set(E)]) -> set(E)).

union1(S1,[S2| Ss]) ->
    union1(union(S1,S2),Ss);
union1(S1,[]) ->
    S1.

-spec(intersection(Set1,Set2) -> Set3 when Set1::set(Element),Set2::set(Element),Set3::set(Element)).

intersection(S1,S2)
    when S1#set.size < S2#set.size->
    filter(fun (E)->
        is_element(E,S2) end,S1);
intersection(S1,S2) ->
    filter(fun (E)->
        is_element(E,S1) end,S2).

-spec(intersection(SetList) -> Set when SetList::[set(Element), ...],Set::set(Element)).

intersection([S1, S2| Ss]) ->
    intersection1(intersection(S1,S2),Ss);
intersection([S]) ->
    S.

-spec(intersection1(set(E),[set(E)]) -> set(E)).

intersection1(S1,[S2| Ss]) ->
    intersection1(intersection(S1,S2),Ss);
intersection1(S1,[]) ->
    S1.

-spec(is_disjoint(Set1,Set2) -> boolean() when Set1::set(Element),Set2::set(Element)).

is_disjoint(S1,S2)
    when S1#set.size < S2#set.size->
    fold(fun (_,false)->
        false;(E,true)->
         not is_element(E,S2) end,true,S1);
is_disjoint(S1,S2) ->
    fold(fun (_,false)->
        false;(E,true)->
         not is_element(E,S1) end,true,S2).

-spec(subtract(Set1,Set2) -> Set3 when Set1::set(Element),Set2::set(Element),Set3::set(Element)).

subtract(S1,S2) ->
    filter(fun (E)->
         not is_element(E,S2) end,S1).

-spec(is_subset(Set1,Set2) -> boolean() when Set1::set(Element),Set2::set(Element)).

is_subset(S1,S2) ->
    fold(fun (E,Sub)->
        Sub andalso is_element(E,S2) end,true,S1).

-spec(fold(Function,Acc0,Set) -> Acc1 when Function::fun((Element,AccIn) -> AccOut),Set::set(Element),Acc0::Acc,Acc1::Acc,AccIn::Acc,AccOut::Acc).

fold(F,Acc,D) ->
    fold_set(F,Acc,D).

-spec(filter(Pred,Set1) -> Set2 when Pred::fun((Element) -> boolean()),Set1::set(Element),Set2::set(Element)).

filter(F,D) ->
    filter_set(F,D).

-spec(get_slot(set(E),E) -> non_neg_integer()).

get_slot(T,Key) ->
    H = erlang:phash(Key,T#set.maxn),
    if H > T#set.n ->
        H - T#set.bso;true ->
        H end.

-spec(get_bucket(set(),non_neg_integer()) -> term()).

get_bucket(T,Slot) ->
    get_bucket_s(T#set.segs,Slot).

fold_set(F,Acc,D)
    when is_function(F,2)->
    Segs = D#set.segs,
    fold_segs(F,Acc,Segs,tuple_size(Segs)).

fold_segs(F,Acc,Segs,I)
    when I >= 1->
    Seg = element(I,Segs),
    fold_segs(F,fold_seg(F,Acc,Seg,tuple_size(Seg)),Segs,I - 1);
fold_segs(_,Acc,_,_) ->
    Acc.

fold_seg(F,Acc,Seg,I)
    when I >= 1->
    fold_seg(F,fold_bucket(F,Acc,element(I,Seg)),Seg,I - 1);
fold_seg(_,Acc,_,_) ->
    Acc.

fold_bucket(F,Acc,[E| Bkt]) ->
    fold_bucket(F,F(E,Acc),Bkt);
fold_bucket(_,Acc,[]) ->
    Acc.

filter_set(F,D)
    when is_function(F,1)->
    Segs0 = tuple_to_list(D#set.segs),
    {Segs1,Fc} = filter_seg_list(F,Segs0,[],0),
    maybe_contract(D#set{segs = list_to_tuple(Segs1)},Fc).

filter_seg_list(F,[Seg| Segs],Fss,Fc0) ->
    Bkts0 = tuple_to_list(Seg),
    {Bkts1,Fc1} = filter_bkt_list(F,Bkts0,[],Fc0),
    filter_seg_list(F,Segs,[list_to_tuple(Bkts1)| Fss],Fc1);
filter_seg_list(_,[],Fss,Fc) ->
    {lists:reverse(Fss,[]),Fc}.

filter_bkt_list(F,[Bkt0| Bkts],Fbs,Fc0) ->
    {Bkt1,Fc1} = filter_bucket(F,Bkt0,[],Fc0),
    filter_bkt_list(F,Bkts,[Bkt1| Fbs],Fc1);
filter_bkt_list(_,[],Fbs,Fc) ->
    {lists:reverse(Fbs),Fc}.

filter_bucket(F,[E| Bkt],Fb,Fc) ->
    case F(E) of
        true->
            filter_bucket(F,Bkt,[E| Fb],Fc);
        false->
            filter_bucket(F,Bkt,Fb,Fc + 1)
    end;
filter_bucket(_,[],Fb,Fc) ->
    {Fb,Fc}.

get_bucket_s(Segs,Slot) ->
    SegI = (Slot - 1) div 16 + 1,
    BktI = (Slot - 1) rem 16 + 1,
    element(BktI,element(SegI,Segs)).

put_bucket_s(Segs,Slot,Bkt) ->
    SegI = (Slot - 1) div 16 + 1,
    BktI = (Slot - 1) rem 16 + 1,
    Seg = setelement(BktI,element(SegI,Segs),Bkt),
    setelement(SegI,Segs,Seg).

-spec(maybe_expand(set(E)) -> set(E)).

maybe_expand(T0)
    when T0#set.size + 1 > T0#set.exp_size->
    T = maybe_expand_segs(T0),
    N = T#set.n + 1,
    Segs0 = T#set.segs,
    Slot1 = N - T#set.bso,
    B = get_bucket_s(Segs0,Slot1),
    Slot2 = N,
    {B1,B2} = rehash(B,Slot1,Slot2,T#set.maxn),
    Segs1 = put_bucket_s(Segs0,Slot1,B1),
    Segs2 = put_bucket_s(Segs1,Slot2,B2),
    T#set{size = T#set.size + 1,n = N,exp_size = N * 5,con_size = N * 3,segs = Segs2};
maybe_expand(T) ->
    T#set{size = T#set.size + 1}.

-spec(maybe_expand_segs(set(E)) -> set(E)).

maybe_expand_segs(T)
    when T#set.n =:= T#set.maxn->
    T#set{maxn = 2 * T#set.maxn,bso = 2 * T#set.bso,segs = expand_segs(T#set.segs,T#set.empty)};
maybe_expand_segs(T) ->
    T.

-spec(maybe_contract(set(E),non_neg_integer()) -> set(E)).

maybe_contract(T,Dc)
    when T#set.size - Dc < T#set.con_size,
    T#set.n > 16->
    N = T#set.n,
    Slot1 = N - T#set.bso,
    Segs0 = T#set.segs,
    B1 = get_bucket_s(Segs0,Slot1),
    Slot2 = N,
    B2 = get_bucket_s(Segs0,Slot2),
    Segs1 = put_bucket_s(Segs0,Slot1,B1 ++ B2),
    Segs2 = put_bucket_s(Segs1,Slot2,[]),
    N1 = N - 1,
    maybe_contract_segs(T#set{size = T#set.size - Dc,n = N1,exp_size = N1 * 5,con_size = N1 * 3,segs = Segs2});
maybe_contract(T,Dc) ->
    T#set{size = T#set.size - Dc}.

-spec(maybe_contract_segs(set(E)) -> set(E)).

maybe_contract_segs(T)
    when T#set.n =:= T#set.bso->
    T#set{maxn = T#set.maxn div 2,bso = T#set.bso div 2,segs = contract_segs(T#set.segs)};
maybe_contract_segs(T) ->
    T.

-spec(rehash([T],integer(),pos_integer(),pos_integer()) -> {[T],[T]}).

rehash([E| T],Slot1,Slot2,MaxN) ->
    {L1,L2} = rehash(T,Slot1,Slot2,MaxN),
    case erlang:phash(E,MaxN) of
        Slot1->
            {[E| L1],L2};
        Slot2->
            {L1,[E| L2]}
    end;
rehash([],_,_,_) ->
    {[],[]}.

-spec(mk_seg(16) -> seg()).

mk_seg(16) ->
    {[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]}.

-spec(expand_segs(segs(E),seg()) -> segs(E)).

expand_segs({B1},Empty) ->
    {B1,Empty};
expand_segs({B1,B2},Empty) ->
    {B1,B2,Empty,Empty};
expand_segs({B1,B2,B3,B4},Empty) ->
    {B1,B2,B3,B4,Empty,Empty,Empty,Empty};
expand_segs({B1,B2,B3,B4,B5,B6,B7,B8},Empty) ->
    {B1,B2,B3,B4,B5,B6,B7,B8,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty};
expand_segs({B1,B2,B3,B4,B5,B6,B7,B8,B9,B10,B11,B12,B13,B14,B15,B16},Empty) ->
    {B1,B2,B3,B4,B5,B6,B7,B8,B9,B10,B11,B12,B13,B14,B15,B16,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty,Empty};
expand_segs(Segs,Empty) ->
    list_to_tuple(tuple_to_list(Segs) ++ lists:duplicate(tuple_size(Segs),Empty)).

-spec(contract_segs(segs(E)) -> segs(E)).

contract_segs({B1,_}) ->
    {B1};
contract_segs({B1,B2,_,_}) ->
    {B1,B2};
contract_segs({B1,B2,B3,B4,_,_,_,_}) ->
    {B1,B2,B3,B4};
contract_segs({B1,B2,B3,B4,B5,B6,B7,B8,_,_,_,_,_,_,_,_}) ->
    {B1,B2,B3,B4,B5,B6,B7,B8};
contract_segs({B1,B2,B3,B4,B5,B6,B7,B8,B9,B10,B11,B12,B13,B14,B15,B16,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_,_}) ->
    {B1,B2,B3,B4,B5,B6,B7,B8,B9,B10,B11,B12,B13,B14,B15,B16};
contract_segs(Segs) ->
    Ss = tuple_size(Segs) div 2,
    list_to_tuple(lists:sublist(tuple_to_list(Segs),1,Ss)).