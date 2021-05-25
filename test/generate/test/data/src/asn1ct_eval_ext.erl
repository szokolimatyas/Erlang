-file("asn1ct_eval_ext.erl", 1).

-module(asn1ct_eval_ext).

-export([transform_to_EXTERNAL1994/1, transform_to_EXTERNAL1994_maps/1]).

transform_to_EXTERNAL1994({'EXTERNAL',DRef,IndRef,Data_v_desc,Encoding} = V) ->
    Identification = case {DRef,IndRef} of
        {DRef,asn1_NOVALUE}->
            {syntax,DRef};
        {asn1_NOVALUE,IndRef}->
            {presentation-context-id,IndRef};
        _->
            {context-negotiation,{'EXTERNAL_identification_context-negotiation',IndRef,DRef}}
    end,
    case Encoding of
        {octet-aligned,Val}
            when is_list(Val);
            is_binary(Val)->
            {'EXTERNAL',Identification,Data_v_desc,Val};
        _->
            V
    end.

transform_to_EXTERNAL1994_maps(V0) ->
    Identification = case V0 of
        #{direct-reference:=DRef,indirect-reference:=asn1_NOVALUE}->
            {syntax,DRef};
        #{direct-reference:=asn1_NOVALUE,indirect-reference:=IndRef}->
            {presentation-context-id,IndRef};
        #{direct-reference:=DRef,indirect-reference:=IndRef}->
            {context-negotiation,#{transfer-syntax=>DRef,presentation-context-id=>IndRef}}
    end,
    case V0 of
        #{encoding:={octet-aligned,Val}}
            when is_list(Val);
            is_binary(Val)->
            V = #{identification=>Identification,data-value=>Val},
            case V0 of
                #{data-value-descriptor:=asn1_NOVALUE}->
                    V;
                #{data-value-descriptor:=Dvd}->
                    V#{data-value-descriptor=>Dvd}
            end;
        _->
            V = [{K,V} || {K,V} <- maps:to_list(V0),V =/= asn1_NOVALUE],
            maps:from_list(V)
    end.