{-# LANGUAGE EmptyDataDeriving #-}

-- https://github.com/erlang/otp/blob/master/lib/stdlib/src/erl_parse.yrl

module Erlang.Type where

newtype Var = Var String
  deriving (Show)

getVString :: Var -> String
getVString (Var s) = s

newtype Atom = Atom String
  deriving (Show)

getAString :: Atom -> String
getAString (Atom s) = s

data Forms
  = Forms0 Form
  | Forms1 Form Forms
  deriving (Show)

data Form
  = -- form -> attribute dot : '$1'.
    Form0 Attribute
  | -- form -> function dot : '$1'.
    Form1 Function
  deriving (Show)

data Attribute
  = -- attribute -> '-' atom attr_val               : build_attribute('$2', '$3').
    Attribute0 Atom AttrVal
  | -- attribute -> '-' atom typed_attr_val         : build_typed_attribute('$2','$3').
    -- attribute -> '-' atom '(' typed_attr_val ')' : build_typed_attribute('$2','$4').
    Attribute1 Atom TypedAttrVal
  | -- attribute -> '-' 'spec' type_spec            : build_type_spec('$2', '$3').
    Attribute2 TypeSpec
  | -- attribute -> '-' 'callback' type_spec        : build_type_spec('$2', '$3').
    Attribute3 TypeSpec
  deriving (Show)

data TypeSpec
  = -- type_spec -> spec_fun type_sigs : {'$1', '$2'}.
    -- type_spec -> '(' spec_fun type_sigs ')' : {'$2', '$3'}.
    TypeSpec SpecFunc TypeSigs
  deriving (Show)

data SpecFunc
  = -- spec_fun ->                           atom : '$1'.
    SpecFunc0 Atom
  | -- spec_fun ->                  atom ':' atom : {'$1', '$3'}.
    SpecFunc1 Atom Atom
  deriving (Show)

data TypedAttrVal
  = -- typed_attr_val -> expr ',' typed_record_fields : {typed_record, '$1', '$3'}.
    TypedAttrVal0 Expr TypedRecordFields
  | -- typed_attr_val -> expr '::' top_type           : {type_def, '$1', '$3'}.
    TypedAttrVal1 Expr TopType
  deriving (Show)

newtype TypedRecordFields
  = -- typed_record_fields -> '{' typed_exprs '}' : {tuple, ?anno('$1'), '$2'}.
    TypedRecordFields TypedExprs
  deriving (Show)

data TypedExprs
  = -- typed_exprs -> typed_expr                 : ['$1'].
    TypedExprs0 TypedExpr
  | -- typed_exprs -> typed_expr ',' typed_exprs : ['$1'|'$3'].
    TypedExprs1 TypedExpr TypedExprs
  | -- typed_exprs -> expr ',' typed_exprs       : ['$1'|'$3'].
    TypedExprs2 Expr TypedExprs
  | -- typed_exprs -> typed_expr ',' exprs       : ['$1'|'$3'].
    TypedExprs3 TypedExpr Exprs
  deriving (Show)

data TypedExpr
  = -- typed_expr -> expr '::' top_type          : {typed,'$1','$3'}.
    TypedExpr Expr TopType
  deriving (Show)

data TypeSigs
  = -- type_sigs -> type_sig                     : ['$1'].
    TypeSigs0 TypeSig
  | -- type_sigs -> type_sig ';' type_sigs       : ['$1'|'$3'].
    TypeSigs1 TypeSig TypeSigs
  deriving (Show)

data TypeSig
  = -- type_sig -> fun_type                      : '$1'.
    TypeSig0 FunType
  | -- type_sig -> fun_type 'when' type_guards   : {type, ?anno('$1'), bounded_fun,
    --                                              ['$1','$3']}.
    TypeSig1 FunType TypeGuards
  deriving (Show)

data TypeGuards
  = -- type_guards -> type_guard                 : ['$1'].
    TypeGuards0 TypeGuard
  | -- type_guards -> type_guard ',' type_guards : ['$1'|'$3'].
    TypeGuards1 TypeGuard TypeGuards
  deriving (Show)

data TypeGuard
  = -- type_guard -> atom '(' top_types ')'   : build_compat_constraint('$1', '$3').
    TypeGuard0 Atom TopTypes
  | -- type_guard -> var '::' top_type        : build_constraint('$1', '$3').
    TypeGuard1 Var TopType
  deriving (Show)

data TopTypes
  = -- top_types -> top_type                     : ['$1'].
    TopTypes0 TopType
  | -- top_types -> top_type ',' top_types       : ['$1'|'$3'].
    TopTypes1 TopType TopTypes
  deriving (Show)

data TopType
  = -- top_type -> var '::' top_type             : {ann_type, ?anno('$1'), ['$1','$3']}.
    TopType0 Var TopType
  | -- top_type -> type '|' top_type             : lift_unions('$1','$3').
    TopType1 Type TopType
  | -- top_type -> type                          : '$1'.
    TopType2 Type
  deriving (Show)

data Type
  = -- type -> type '..' type                    : {type, ?anno('$1'), range, ['$1', '$3']}.
    Type0 Type Type
  | -- type -> type add_op type                  : ?mkop2('$1', '$2', '$3').
    Type1 Type AddOp Type
  | -- type -> type mult_op type                 : ?mkop2('$1', '$2', '$3').
    Type2 Type MultOp Type
  | -- type -> prefix_op type                    : ?mkop1('$1', '$2').
    Type3 PrefixOp Type
  | -- type -> '(' top_type ')'                  : '$2'.
    Type4 TopType
  | -- type -> var                               : '$1'.
    Type5 Var
  | -- type -> atom                              : '$1'.
    Type6 Atom
  | -- type -> atom '(' ')'                      : build_gen_type('$1').
    Type7 Atom
  | -- type -> atom '(' top_types ')'            : build_type('$1', '$3').
    Type8 Atom TopTypes
  | -- type -> atom ':' atom '(' ')'             : {remote_type, ?anno('$1'),
    Type9 Atom Atom
  | -- type -> atom ':' atom '(' top_types ')'   : {remote_type, ?anno('$1'),
    Type10 Atom Atom TopTypes
  | -- type -> '[' ']'                           : {type, ?anno('$1'), nil, []}.
    Type11
  | -- type -> '[' top_type ']'                  : {type, ?anno('$1'), list, ['$2']}.
    Type12 TopType
  | -- type -> '[' top_type ',' '...' ']'        : {type, ?anno('$1'),
    Type13 TopType
  | -- type -> '#' '{' '}'                       : {type, ?anno('$1'), map, []}.
    Type14
  | -- type -> '#' '{' map_pair_types '}'        : {type, ?anno('$1'), map, '$3'}.
    Type15 MapPairTypes
  | -- type -> '{' '}'                           : {type, ?anno('$1'), tuple, []}.
    Type16
  | -- type -> '{' top_types '}'                 : {type, ?anno('$1'), tuple, '$2'}.
    Type17 TopTypes
  | -- type -> '#' atom '{' '}'                  : {type, ?anno('$1'), record, ['$2']}.
    Type18 Atom
  | -- type -> '#' atom '{' field_types '}'      : {type, ?anno('$1'),
    Type19 Atom FieldTypes
  | -- type -> binary_type                       : '$1'.
    Type20 BinaryType
  | -- type -> integer                           : '$1'.
    Type21 Integer
  | -- type -> char                              : '$1'.
    Type22 Char
  | -- type -> 'fun' '(' ')'                     : {type, ?anno('$1'), 'fun', []}.
    Type23
  | -- type -> 'fun' '(' fun_type ')'            : '$3'.
    Type24 FunType
  deriving (Show)

data FunType
  = -- fun_type -> '(' '...' ')' '->' top_type   : {type, ?anno('$1'), 'fun',
    --                                              [{type, ?anno('$1'), any}, '$5']}.
    FunType0 TopType
  | -- fun_type -> '(' ')' '->' top_type  : {type, ?anno('$1'), 'fun',
    --                                       [{type, ?anno('$1'), product, []}, '$4']}.
    FunType1 TopType
  | -- fun_type -> '(' top_types ')' '->' top_type
    --                                    : {type, ?anno('$1'), 'fun',
    --                                       [{type, ?anno('$1'), product, '$2'},'$5']}.
    FunType2 TopTypes TopType
  deriving (Show)

data MapPairTypes
  = -- map_pair_types -> map_pair_type                    : ['$1'].
    MapPairTypes0 MapPairType
  | -- map_pair_types -> map_pair_type ',' map_pair_types : ['$1'|'$3'].
    MapPairTypes1 MapPairType MapPairTypes
  deriving (Show)

data MapPairType
  = -- map_pair_type  -> top_type '=>' top_type  : {type, ?anno('$2'),
    --                                              map_field_assoc,['$1','$3']}.
    MapPairType0 TopType TopType
  | -- map_pair_type  -> top_type ':=' top_type  : {type, ?anno('$2'),
    --                                              map_field_exact,['$1','$3']}.
    MapPairType1 TopType TopType
  deriving (Show)

data FieldTypes
  = -- field_types -> field_type                 : ['$1'].
    FieldTypes0 FieldType
  | -- field_types -> field_type ',' field_types : ['$1'|'$3'].
    FieldTypes1 FieldType FieldTypes
  deriving (Show)

data FieldType
  = -- field_type -> atom '::' top_type          : {type, ?anno('$1'), field_type,
    --                                              ['$1', '$3']}.
    FieldType Atom TopType
  deriving (Show)

data BinaryType
  = -- binary_type -> '<<' '>>'                  : {type, ?anno('$1'),binary,
    -- 					     [abstract2(0, ?anno('$1')),
    -- 					      abstract2(0, ?anno('$1'))]}.
    BinaryType0
  | -- binary_type -> '<<' bin_base_type '>>'    : {type, ?anno('$1'),binary,
    -- 					     ['$2', abstract2(0, ?anno('$1'))]}.
    BinaryType1 BinBaseType
  | -- binary_type -> '<<' bin_unit_type '>>'    : {type, ?anno('$1'),binary,
    --                                              [abstract2(0, ?anno('$1')), '$2']}.
    BinaryType2 BinUnitType
  | -- binary_type -> '<<' bin_base_type ',' bin_unit_type '>>'
    --                                     : {type, ?anno('$1'), binary, ['$2', '$4']}.
    BinaryType3 BinBaseType BinUnitType
  deriving (Show)

data BinBaseType
  = -- bin_base_type -> var ':' type          : build_bin_type(['$1'], '$3').
    BinBaseType Var Type
  deriving (Show)

data BinUnitType
  = -- bin_unit_type -> var ':' var '*' type  : build_bin_type(['$1', '$3'], '$5').
    BinUnitType Var Var Type
  deriving (Show)

data AttrVal
  = -- attr_val -> expr                     : ['$1'].
    AttrVal0 Expr
  | -- attr_val -> expr ',' exprs           : ['$1' | '$3'].
    -- attr_val -> '(' expr ',' exprs ')'   : ['$2' | '$4'].
    AttrVal1 Expr Exprs
  deriving (Show)

newtype Function
  = -- function -> function_clauses : build_function('$1').
    Function FunctionClauses
  deriving (Show)

data FunctionClauses
  = -- function_clauses -> function_clause : ['$1'].
    FunctionClauses0 FunctionClause
  | -- function_clauses -> function_clause ';' function_clauses : ['$1'|'$3'].
    FunctionClauses1 FunctionClause FunctionClauses
  deriving (Show)

data FunctionClause
  = -- function_clause -> atom clause_args clause_guard clause_body :
    -- 	{clause,?anno('$1'),element(3, '$1'),'$2','$3','$4'}.
    FunctionClause Atom ClauseArgs ClauseGuard ClauseBody
  deriving (Show)

newtype ClauseArgs
  = -- clause_args -> pat_argument_list : element(1, '$1').
    ClauseArgs PatArgumentList
  deriving (Show)

data ClauseGuard
  = -- clause_guard -> 'when' guard : '$2'.
    ClauseGuard0 Guard
  | -- clause_guard -> '$empty' : [].
    ClauseGuard1
  deriving (Show)

newtype ClauseBody
  = -- clause_body -> '->' exprs: '$2'.
    ClauseBody Exprs
  deriving (Show)

data Expr
  = -- expr -> 'catch' expr : {'catch',?anno('$1'),'$2'}.
    Expr0 Expr
  | -- expr -> expr '=' expr : {match,first_anno('$1'),'$1','$3'}.
    Expr1 Expr Expr
  | -- expr -> expr '!' expr : ?mkop2('$1', '$2', '$3').
    Expr2 Expr Expr
  | -- expr -> expr 'orelse' expr : ?mkop2('$1', '$2', '$3').
    Expr3 Expr Expr
  | -- expr -> expr 'andalso' expr : ?mkop2('$1', '$2', '$3').
    Expr4 Expr Expr
  | -- expr -> expr comp_op expr : ?mkop2('$1', '$2', '$3').
    Expr5 Expr CompOp Expr
  | -- expr -> expr list_op expr : ?mkop2('$1', '$2', '$3').
    Expr6 Expr ListOp Expr
  | -- expr -> expr add_op expr : ?mkop2('$1', '$2', '$3').
    Expr7 Expr AddOp Expr
  | -- expr -> expr mult_op expr : ?mkop2('$1', '$2', '$3').
    Expr8 Expr MultOp Expr
  | -- expr -> prefix_op expr : ?mkop1('$1', '$2').
    Expr9 PrefixOp Expr
  | -- expr -> map_expr : '$1'.
    Expr10 MapExpr
  | -- expr -> function_call : '$1'.
    Expr11 FunctionCall
  | -- expr -> record_expr : '$1'.
    Expr12 RecordExpr
  | -- expr -> expr_remote : '$1'.
    Expr13 ExprRemote
  deriving (Show)

data ExprRemote
  = -- expr_remote -> expr_max ':' expr_max : {remote,?anno('$2'),'$1','$3'}.
    ExprRemote0 ExprMax ExprMax
  | -- expr_remote -> expr_max : '$1'.
    ExprRemote1 ExprMax
  deriving (Show)

data ExprMax
  = -- expr_max -> var : '$1'.
    ExprMax0 Var
  | -- expr_max -> atomic : '$1'.
    ExprMax1 Atomic
  | -- expr_max -> list : '$1'.
    ExprMax2 List
  | -- expr_max -> binary : '$1'.
    ExprMax3 Binary
  | -- expr_max -> list_comprehension : '$1'.
    ExprMax4 ListComprehension
  | -- expr_max -> binary_comprehension : '$1'.
    ExprMax5 BinaryComprehension
  | -- expr_max -> tuple : '$1'.
    ExprMax6 Tuple
  | -- expr_max -> '(' expr ')' : '$2'.
    ExprMax7 Expr
  | -- expr_max -> 'begin' exprs 'end' : {block,?anno('$1'),'$2'}.
    ExprMax8 Exprs
  | -- expr_max -> if_expr : '$1'.
    ExprMax9 IfExpr
  | -- expr_max -> case_expr : '$1'.
    ExprMax10 CaseExpr
  | -- expr_max -> receive_expr : '$1'.
    ExprMax11 ReceiveExpr
  | -- expr_max -> fun_expr : '$1'.
    ExprMax12 FunExpr
  | -- expr_max -> try_expr : '$1'.
    ExprMax13 TryExpr
  deriving (Show)

data PatExpr
  = -- pat_expr -> pat_expr '=' pat_expr : {match,first_anno('$1'),'$1','$3'}.
    PatExpr0 PatExpr PatExpr
  | -- pat_expr -> pat_expr comp_op pat_expr : ?mkop2('$1', '$2', '$3').
    PatExpr1 PatExpr CompOp PatExpr
  | -- pat_expr -> pat_expr list_op pat_expr : ?mkop2('$1', '$2', '$3').
    PatExpr2 PatExpr ListOp PatExpr
  | -- pat_expr -> pat_expr add_op pat_expr : ?mkop2('$1', '$2', '$3').
    PatExpr3 PatExpr AddOp PatExpr
  | -- pat_expr -> pat_expr mult_op pat_expr : ?mkop2('$1', '$2', '$3').
    PatExpr4 PatExpr MultOp PatExpr
  | -- pat_expr -> prefix_op pat_expr : ?mkop1('$1', '$2').
    PatExpr5 PrefixOp PatExpr
  | -- pat_expr -> map_pat_expr : '$1'.
    PatExpr6 MapPatExpr
  | -- pat_expr -> record_pat_expr : '$1'.
    PatExpr7 RecordPatExpr
  | -- pat_expr -> pat_expr_max : '$1'.
    PatExpr8 PatExprMax
  deriving (Show)

data PatExprMax
  = -- pat_expr_max -> var : '$1'.
    PatExprMax0 Var
  | -- pat_expr_max -> atomic : '$1'.
    PatExprMax1 Atomic
  | -- pat_expr_max -> list : '$1'.
    PatExprMax2 List
  | -- pat_expr_max -> binary : '$1'.
    PatExprMax3 Binary
  | -- pat_expr_max -> tuple : '$1'.
    PatExprMax4 Tuple
  | -- pat_expr_max -> '(' pat_expr ')' : '$
    PatExprMax5 PatExpr
  deriving (Show)

data MapPatExpr
  = -- map_pat_expr -> '#' map_tuple :
    -- 	{map, ?anno('$1'),'$2'}.
    MapPatExpr0 MapTuple
  | -- map_pat_expr -> pat_expr_max '#' map_tuple :
    -- 	{map, ?anno('$2'),'$1','$3'}.
    MapPatExpr1 PatExprMax MapTuple
  | -- map_pat_expr -> map_pat_expr '#' map_tuple :
    -- 	{map, ?anno('$2'),'$1','$3'}.
    MapPatExpr2 MapPatExpr MapTuple
  deriving (Show)

data RecordPatExpr
  = -- record_pat_expr -> '#' atom '.' atom :
    -- 	{record_index,?anno('$1'),element(3, '$2'),'$4'}.
    RecordPatExpr0 Atom Atom
  | -- record_pat_expr -> '#' atom record_tuple :
    -- 	{record,?anno('$1'),element(3, '$2'),'$3'}.
    RecordPatExpr1 Atom RecordTuple
  deriving (Show)

data List
  = -- list -> '[' ']' : {nil,?anno('$1')}.
    List0
  | -- list -> '[' expr tail : {cons,?anno('$1'),'$2','$3'}.
    List1 Expr Tail
  deriving (Show)

data Tail
  = -- tail -> ']' : {nil,?anno('$1')}.
    Tail0
  | -- tail -> '|' expr ']' : '$2'.
    Tail1 Expr
  | -- tail -> ',' expr tail : {cons,first_anno('$2'),'$2','$3'}.
    Tail2 Expr Tail
  deriving (Show)

data Binary
  = -- binary -> '<<' '>>' : {bin,?anno('$1'),[]}.
    Binary0
  | -- binary -> '<<' bin_elements '>>' : {bin,?anno('$1'),'$2'}.
    Binary1 BinElements
  deriving (Show)

data BinElements
  = -- bin_elements -> bin_element : ['$1'].
    BinElements0 BinElement
  | -- bin_elements -> bin_element ',' bin_elements : ['$1'|'$3'].
    BinElements1 BinElement BinElements
  deriving (Show)

data BinElement
  = -- bin_element -> bit_expr opt_bit_size_expr opt_bit_type_list :
    -- 	{bin_element,first_anno('$1'),'$1','$2','$3'}.
    BinElement BitExpr OptBitSizeExpr OptBitTypeList
  deriving (Show)

data BitExpr
  = -- bit_expr -> prefix_op expr_max : ?mkop1('$1', '$2').
    BitExpr0 PrefixOp ExprMax
  | -- bit_expr -> expr_max : '$1'.
    BitExpr1 ExprMax
  deriving (Show)

data OptBitSizeExpr
  = -- opt_bit_size_expr -> ':' bit_size_expr : '$2'.
    OptBitSizeExpr0 BitSizeExpr
  | -- opt_bit_size_expr -> '$empty' : default.
    OptBitSizeExpr1
  deriving (Show)

data OptBitTypeList
  = -- opt_bit_type_list -> '/' bit_type_list : '$2'.
    OptBitTypeList0 BitTypeList
  | -- opt_bit_type_list -> '$empty' : default.
    OptBitTypeList1
  deriving (Show)

data BitTypeList
  = -- bit_type_list -> bit_type '-' bit_type_list : ['$1' | '$3'].
    BitTypeList0 BitType BitTypeList
  | -- bit_type_list -> bit_type : ['$1'].
    BitTypeList1 BitType
  deriving (Show)

data BitType
  = -- bit_type -> atom             : element(3,'$1').
    BitType0 Atom
  | -- bit_type -> atom ':' integer : { element(3,'$1'), element(3,'$3') }.
    BitType1 Atom Integer
  deriving (Show)

newtype BitSizeExpr
  = -- bit_size_expr -> expr_max : '$1'.
    BitSizeExpr ExprMax
  deriving (Show)

data ListComprehension
  = -- list_comprehension -> '[' expr '||' lc_exprs ']' :
    -- 	{lc,?anno('$1'),'$2','$4'}.
    ListComprehension Expr LcExprs
  deriving (Show)

data BinaryComprehension
  = -- binary_comprehension -> '<<' expr_max '||' lc_exprs '>>' :
    -- 	{bc,?anno('$1'),'$2','$4'}.
    BinaryComprehension ExprMax LcExprs
  deriving (Show)

data LcExprs
  = -- lc_exprs -> lc_expr : ['$1'].
    LcExprs0 LcExpr
  | -- lc_exprs -> lc_expr ',' lc_exprs : ['$1'|'$3'].
    LcExprs1 LcExpr LcExprs
  deriving (Show)

data LcExpr
  = -- lc_expr -> expr : '$1'.
    LcExpr0 Expr
  | -- lc_expr -> expr '<-' expr : {generate,?anno('$2'),'$1','$3'}.
    LcExpr1 Expr Expr
  | -- lc_expr -> binary '<=' expr : {b_generate,?anno('$2'),'$1','$3'}.
    LcExpr2 Binary Expr
  deriving (Show)

data Tuple
  = -- tuple -> '{' '}' : {tuple,?anno('$1'),[]}.
    Tuple0
  | -- tuple -> '{' exprs '}' : {tuple,?anno('$1'),'$2'}.
    Tuple1 Exprs
  deriving (Show)

data MapExpr
  = -- map_expr -> '#' map_tuple :
    -- 	{map, ?anno('$1'),'$2'}.
    MapExpr0 MapTuple
  | -- map_expr -> expr_max '#' map_tuple :
    -- 	{map, ?anno('$2'),'$1','$3'}.
    MapExpr1 ExprMax MapTuple
  | -- map_expr -> map_expr '#' map_tuple :
    -- 	{map, ?anno('$2'),'$1','$3'}.
    MapExpr2 MapExpr MapTuple
  deriving (Show)

data MapTuple
  = -- map_tuple -> '{' '}' : [].
    MapTuple0
  | -- map_tuple -> '{' map_fields '}' : '$2'.
    MapTuple1 MapFields
  deriving (Show)

data MapFields
  = -- map_fields -> map_field : ['$1'].
    MapFields0 MapField
  | -- map_fields -> map_field ',' map_fields : ['$1' | '$3'].
    MapFields1 MapField MapFields
  deriving (Show)

data MapField
  = -- map_field -> map_field_assoc : '$1'.
    MapField0 MapFieldAssoc
  | -- map_field -> map_field_exact : '$1'.
    MapField1 MapFieldExact
  deriving (Show)

data MapFieldAssoc
  = -- map_field_assoc -> map_key '=>' expr :
    -- 	{map_field_assoc,?anno('$2'),'$1','$3'}.
    MapFieldAssoc MapKey Expr
  deriving (Show)

data MapFieldExact
  = -- map_field_exact -> map_key ':=' expr :
    -- 	{map_field_exact,?anno('$2'),'$1','$3'}.
    MapFieldExact MapKey Expr
  deriving (Show)

newtype MapKey
  = -- map_key -> expr : '$1'.
    MapKey Expr
  deriving (Show)

data RecordExpr
  = -- record_expr -> '#' atom '.' atom :
    -- 	{record_index,?anno('$1'),element(3, '$2'),'$4'}.
    RecordExpr0 Atom Atom
  | -- record_expr -> '#' atom record_tuple :
    -- 	{record,?anno('$1'),element(3, '$2'),'$3'}.
    RecordExpr1 Atom RecordTuple
  | -- record_expr -> expr_max '#' atom '.' atom :
    -- 	{record_field,?anno('$2'),'$1',element(3, '$3'),'$5'}.
    RecordExpr2 ExprMax Atom Atom
  | -- record_expr -> expr_max '#' atom record_tuple :
    -- 	{record,?anno('$2'),'$1',element(3, '$3'),'$4'}.
    RecordExpr3 ExprMax Atom RecordTuple
  | -- record_expr -> record_expr '#' atom '.' atom :
    -- 	{record_field,?anno('$2'),'$1',element(3, '$3'),'$5'}.
    RecordExpr4 RecordExpr Atom Atom
  | -- record_expr -> record_expr '#' atom record_tuple :
    -- 	{record,?anno('$2'),'$1',element(3, '$3'),'$4'}.
    RecordExpr5 RecordExpr Atom RecordTuple
  deriving (Show)

data RecordTuple
  = -- record_tuple -> '{' '}' : [].
    RecordTuple0
  | -- record_tuple -> '{' record_fields '}' : '$2'.
    RecordTuple1 RecordFields
  deriving (Show)

data RecordFields
  = -- record_fields -> record_field : ['$1'].
    RecordFields0 RecordField
  | -- record_fields -> record_field ',' record_fields : ['$1' | '$3'].
    RecordFields1 RecordField RecordFields
  deriving (Show)

data RecordField
  = -- record_field -> var '=' expr : {record_field,?anno('$1'),'$1','$3'}.
    RecordField0 Var Expr
  | -- record_field -> atom '=' expr : {record_field,?anno('$1'),'$1','$3'}.
    RecordField1 Atom Expr
  deriving (Show)

data FunctionCall
  = -- function_call -> expr_remote argument_list :
    -- 	{call,first_anno('$1'),'$1',element(1, '$2')}.
    FunctionCall ExprRemote ArgumentList
  deriving (Show)

newtype IfExpr
  = -- if_expr -> 'if' if_clauses 'end' : {'if',?anno('$1'),'$2'}.
    IfExpr IfClauses
  deriving (Show)

data IfClauses
  = -- if_clauses -> if_clause : ['$1'].
    IfClauses0 IfClause
  | -- if_clauses -> if_clause ';' if_clauses : ['$1' | '$3'].
    IfClauses1 IfClause IfClauses
  deriving (Show)

data IfClause
  = -- if_clause -> guard clause_body :
    -- 	{clause,first_anno(hd(hd('$1'))),[],'$1','$2'}.
    IfClause Guard ClauseBody
  deriving (Show)

data CaseExpr
  = -- case_expr -> 'case' expr 'of' cr_clauses 'end' :
    -- 	{'case',?anno('$1'),'$2','$4'}.
    CaseExpr Expr CrClauses
  deriving (Show)

data CrClauses
  = -- cr_clauses -> cr_clause : ['$1'].
    CrClauses0 CrClause
  | -- cr_clauses -> cr_clause ';' cr_clauses : ['$1' | '$3'].
    CrClauses1 CrClause CrClauses
  deriving (Show)

data CrClause
  = -- cr_clause -> expr clause_guard clause_body :
    -- 	{clause,first_anno('$1'),['$1'],'$2','$3'}.
    CrClause Expr ClauseGuard ClauseBody
  deriving (Show)

data ReceiveExpr
  = -- receive_expr -> 'receive' cr_clauses 'end' :
    -- 	{'receive',?anno('$1'),'$2'}.
    ReceiveExpr0 CrClauses
  | -- receive_expr -> 'receive' 'after' expr clause_body 'end' :
    -- 	{'receive',?anno('$1'),[],'$3','$4'}.
    ReceiveExpr1 Expr ClauseBody
  | -- receive_expr -> 'receive' cr_clauses 'after' expr clause_body 'end' :
    -- 	{'receive',?anno('$1'),'$2','$4','$5'}.
    ReceiveExpr2 CrClauses Expr ClauseBody
  deriving (Show)

data FunExpr
  = -- fun_expr -> 'fun' atom '/' integer :
    -- 	{'fun',?anno('$1'),{function,element(3, '$2'),element(3, '$4')}}.
    FunExpr0 Atom Integer
  | -- fun_expr -> 'fun' atom_or_var ':' atom_or_var '/' integer_or_var :
    -- 	{'fun',?anno('$1'),{function,'$2','$4','$6'}}.
    FunExpr1 AtomOrVar AtomOrVar IntegerOrVar
  | -- fun_expr -> 'fun' fun_clauses 'end' :
    -- 	build_fun(?anno('$1'), '$2').
    FunExpr2 FunClauses
  deriving (Show)

data AtomOrVar
  = -- atom_or_var -> atom : '$1'.
    AtomOrVar0 Atom
  | -- atom_or_var -> var : '$1'.
    AtomOrVar1 Var
  deriving (Show)

data IntegerOrVar
  = -- integer_or_var -> integer : '$1'.
    IntegerOrVar0 Integer
  | -- integer_or_var -> var : '$1'.
    IntegerOrVar1 Var
  deriving (Show)

data FunClauses
  = -- fun_clauses -> fun_clause : ['$1'].
    FunClauses0 FunClause
  | -- fun_clauses -> fun_clause ';' fun_clauses : ['$1' | '$3'].
    FunClauses1 FunClause FunClauses
  deriving (Show)

data FunClause
  = -- fun_clause -> pat_argument_list clause_guard clause_body :
    -- 	{Args,Anno} = '$1',
    -- 	{clause,Anno,'fun',Args,'$2','$3'}.
    FunClause0 PatArgumentList ClauseGuard ClauseBody
  | -- fun_clause -> var pat_argument_list clause_guard clause_body :
    -- 	{clause,?anno('$1'),element(3, '$1'),element(1, '$2'),'$3','$4'}.
    FunClause1 Var PatArgumentList ClauseGuard ClauseBody
  deriving (Show)

data TryExpr
  = -- try_expr -> 'try' exprs 'of' cr_clauses try_catch :
    -- 	build_try(?anno('$1'),'$2','$4','$5').
    TryExpr0 Exprs CrClauses TryCatch
  | -- try_expr -> 'try' exprs try_catch :
    -- 	build_try(?anno('$1'),'$2',[],'$3').
    TryExpr1 Exprs TryCatch
  deriving (Show)

data TryCatch
  = -- try_catch -> 'catch' try_clauses 'end' :
    -- 	{'$2',[]}.
    TryCatch0 TryClauses
  | -- try_catch -> 'catch' try_clauses 'after' exprs 'end' :
    -- 	{'$2','$4'}.
    TryCatch1 TryClauses Exprs
  | -- try_catch -> 'after' exprs 'end' :
    -- 	{[],'$2'}.
    TryCatch2 Exprs
  deriving (Show)

data TryClauses
  = -- try_clauses -> try_clause : ['$1'].
    TryClauses0 TryClause
  | -- try_clauses -> try_clause ';' try_clauses : ['$1' | '$3'].
    TryClauses1 TryClause TryClauses
  deriving (Show)

data TryClause
  = -- try_clause -> pat_expr clause_guard clause_body :
    -- 	A = first_anno('$1'),
    --         Az = last_anno('$1'), % Good enough...
    -- 	{clause,A,[{tuple,A,[{atom,A,throw},'$1',{var,Az,'_'}]}],'$2','$3'}.
    TryClause0 PatExpr ClauseGuard ClauseBody
  | -- try_clause -> atom ':' pat_expr try_opt_stacktrace clause_guard clause_body :
    -- 	A = ?anno('$1'),
    -- 	T = case '$4' of '_' -> {var,last_anno('$3'),'_'}; V -> V end,
    -- 	{clause,A,[{tuple,A,['$1','$3',T]}],'$5','$6'}.
    TryClause1 Atom PatExpr TryOptStacktrace ClauseGuard ClauseBody
  | -- try_clause -> var ':' pat_expr try_opt_stacktrace clause_guard clause_body :
    -- 	A = ?anno('$1'),
    -- 	T = case '$4' of '_' -> {var,last_anno('$3'),'_'}; V -> V end,
    -- 	{clause,A,[{tuple,A,['$1','$3',T]}],'$5','$6'}.
    TryClause2 Var PatExpr TryOptStacktrace ClauseGuard ClauseBody
  deriving (Show)

data TryOptStacktrace
  = -- try_opt_stacktrace -> ':' var : '$2'.
    TryOptStacktrace0 Var
  | -- try_opt_stacktrace -> '$empty' : '_'.
    TryOptStacktrace1
  deriving (Show)

data ArgumentList
  = -- argument_list -> '(' ')' : {[],?anno('$1')}.
    ArgumentList0
  | -- argument_list -> '(' exprs ')' : {'$2',?anno('$1')}.
    ArgumentList1 Exprs
  deriving (Show)

data PatArgumentList
  = -- pat_argument_list -> '(' ')' : {[],?anno('$1')}.
    PatArgumentList0
  | -- pat_argument_list -> '(' pat_exprs ')' : {'$2',?anno('$1')}.
    PatArgumentList1 PatExprs
  deriving (Show)

data Exprs
  = -- exprs -> expr : ['$1'].
    Exprs0 Expr
  | -- exprs -> expr ',' exprs : ['$1' | '$3'].
    Exprs1 Expr Exprs
  deriving (Show)

data PatExprs
  = -- pat_exprs -> pat_expr : ['$1'].
    PatExprs0 PatExpr
  | -- pat_exprs -> pat_expr ',' pat_exprs : ['$1' | '$3'].
    PatExprs1 PatExpr PatExprs
  deriving (Show)

data Guard
  = -- guard -> exprs : ['$1'].
    Guard0 Exprs
  | -- guard -> exprs ';' guard : ['$1'|'$3'].
    Guard1 Exprs Guard
  deriving (Show)

data Atomic
  = -- atomic -> char : '$1'.
    Atomic0 Char
  | -- atomic -> integer : '$1'.
    Atomic1 Integer
  | Atomic11 String
  | -- atomic -> float : '$1'.
    Atomic2 Double
  | -- atomic -> atom : '$1'.
    Atomic3 Atom
  | -- atomic -> strings : '$1'.
    Atomic4 Strings
  deriving (Show)

data Strings
  = -- strings -> string : '$1'.
    Strings0 String
  | -- strings -> string strings :
    -- 	{string,?anno('$1'),element(3, '$1') ++ element(3, '$2')}.
    Strings1 String Strings
  deriving (Show)

data PrefixOp
  = -- prefix_op -> '+' : '$1'.
    PPlus
  | -- prefix_op -> '-' : '$1'.
    PSub
  | -- prefix_op -> 'bnot' : '$1'.
    PBnot
  | -- prefix_op -> 'not' : '$1'.
    PNot
  deriving (Show)

data MultOp
  = -- mult_op -> '/' : '$1'.
    Mx
  | -- mult_op -> '*' : '$1'.
    Mmult
  | -- mult_op -> 'div' : '$1'.
    Mdiv
  | -- mult_op -> 'rem' : '$1'.
    Mrem
  | -- mult_op -> 'band' : '$1'.
    Mband
  | -- mult_op -> 'and' : '$1'.
    Mand
  deriving (Show)

data AddOp
  = -- add_op -> '+' : '$1'.
    Aplus
  | -- add_op -> '-' : '$1'.
    Asub
  | -- add_op -> 'bor' : '$1'.
    Abor
  | -- add_op -> 'bxor' : '$1'.
    Abxor
  | -- add_op -> 'bsl' : '$1'.
    Absl
  | -- add_op -> 'bsr' : '$1'.
    Absr
  | -- add_op -> 'or' : '$1'.
    Aor
  | -- add_op -> 'xor' : '$1'.
    Axor
  deriving (Show)

data ListOp
  = -- list_op -> '++' : '$1'.
    Lpp
  | -- list_op -> '--' : '$1'.
    Lss
  deriving (Show)

data CompOp
  = -- comp_op -> '==' : '$1'.
    Ce
  | -- comp_op -> '/=' : '$1'.
    Cne
  | -- comp_op -> '=<' : '$1'.
    Cle
  | -- comp_op -> '<' : '$1'.
    Cl
  | -- comp_op -> '>=' : '$1'.
    Cge
  | -- comp_op -> '>' : '$1'.
    Cg
  | -- comp_op -> '=:=' : '$1'.
    Cme
  | -- comp_op -> '=/=' : '$1'.
    Cmn
  deriving (Show)
