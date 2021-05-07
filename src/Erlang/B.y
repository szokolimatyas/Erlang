{
module Erlang.B where
import Erlang.A
import Erlang.Type

}

%name calc
%tokentype { Token }

-- https://github.com/erlang/otp/blob/master/lib/stdlib/src/erl_parse.yrl

-- %Unary 'catch'.
%right '=' '!'
%right 'orelse'
%right  'andalso'
%nonassoc  CompOp
%right  ListOp
%left AddOp
%left MultOp
-- %Unary prefix_op
%nonassoc '#'
%nonassoc ':'

%right '::'
%left '|'
%nonassoc '..'
%nonassoc '*'

%monad { E } { thenE } { returnE }

-- TKeywords
%token
  'after'         { TKeywords "after" }
  'begin'         { TKeywords "begin" }
  'case'          { TKeywords "case" }
  'try'           { TKeywords "try" }
  'catch'         { TKeywords "catch" }
  'end'           { TKeywords "end" }
  'fun'           { TKeywords "fun" }
  'if'            { TKeywords "if" }
  'of'            { TKeywords "of" }
  'receive'       { TKeywords "receive" }
  'when'          { TKeywords "when" }
  'andalso'       { TKeywords "andalso" }
  'orelse'        { TKeywords "orelse" }
  'bnot'          { TKeywords "bnot" }
  'not'           { TKeywords "not" }
  '*'             { TKeywords "*" }
  '/'             { TKeywords "/" }
  'div'           { TKeywords "div" }
  'rem'           { TKeywords "rem" }
  'band'          { TKeywords "band" }
  'and'           { TKeywords "and" }
  '+'             { TKeywords "+" }
  '-'             { TKeywords "-" }
  'bor'           { TKeywords "bor" }
  'bxor'          { TKeywords "bxor" }
  'bsl'           { TKeywords "bsl" }
  'bsr'           { TKeywords "bsr" }
  'or'            { TKeywords "or" }
  'xor'           { TKeywords "xor" }
  '++'            { TKeywords "++" }
  '--'            { TKeywords "--" }
  '=='            { TKeywords "==" }
  '/='            { TKeywords "/=" }
  '=<'            { TKeywords "=<" }
  '<'             { TKeywords "<" }
  '>='            { TKeywords ">=" }
  '>'             { TKeywords ">" }
  '=:='           { TKeywords "=:=" }
  '=/='           { TKeywords "=/=" }
  '<='            { TKeywords "<=" }
  '=>'            { TKeywords "=>" }
  ':='            { TKeywords ":=" }
  '<<'            { TKeywords "<<" }
  '>>'            { TKeywords ">>" }
  '!'             { TKeywords "!" }
  '='             { TKeywords "=" }
  '::'            { TKeywords "::" }
  '..'            { TKeywords ".." }
  '...'           { TKeywords "..." }
  'spec'          { TKeywords "spec" }
  'callback'      { TKeywords "callback" }


  '('             { TSeparators "(" }
  ')'             { TSeparators ")" }
  ','             { TSeparators "," }
  '->'            { TSeparators "->" }
  '{'             { TSeparators "{" }
  '}'             { TSeparators "}" }
  '['             { TSeparators "[" }
  ']'             { TSeparators "]" }
  '|'             { TSeparators "|" }
  '||'            { TSeparators "||" }
  '<-'            { TSeparators "<-" }
  ';'             { TSeparators ";" }
  ':'             { TSeparators ":" }
  '#'             { TSeparators "#" }
  '.'             { TSeparators "." }


  int           { TInt     $$ }
  sint          { TSInt     $$ }
  float         { TFloat   $$ }
  atom          { TAtom    $$ }
  char          { TChar    $$ }
  string        { TString  $$ }
  var           { TVarName $$ }

%%


sep(a, s) :: { [a] }
  : {- empty -} { []         }
  | sep1(a, s)  { reverse $1 }

sep1(a, s) :: { [a] }
  : a { [$1] }
  | sep1(a, s) s a { $3 :   $1 }


Forms :: { Forms }
  : Form { Forms0 $1 }
  | Form Forms { Forms1 $1 $2 }

Form :: { Form }
  : Attribute '.' { Form0 $1 }
  | Function '.' { Form1 $1 }

Var :: { Var }
  : var  { Var $1 }

Atom :: { Atom }
  : atom { Atom $1 }
  | 'spec' { Atom "spec" }
  | 'callback' { Atom "callback" }


Attribute :: { Attribute }
  : '-' Atom AttrVal              { Attribute0 $2 $3 }
  | '-' Atom TypedAttrVal         { Attribute1 $2 $3 }
  | '-' Atom '(' TypedAttrVal ')' { Attribute1 $2 $4 }
  | '-' 'spec' TypeSpec           { Attribute2 $3 }
  | '-' 'callback' TypeSpec       { Attribute3 $3 }

TypeSpec :: { TypeSpec }
  : SpecFunc TypeSigs { TypeSpec $1 $2 }
  | '(' SpecFunc TypeSigs ')' { TypeSpec $2 $3 }

SpecFunc :: { SpecFunc }
  : Atom { SpecFunc0 $1 }
  |  Atom ':' Atom  { SpecFunc1 $1 $3}

TypedAttrVal :: { TypedAttrVal }
  : Expr ',' TypedRecordFields { TypedAttrVal0 $1 $3 } 
  | Expr '::' TopType { TypedAttrVal1 $1 $3 }

TypedRecordFields :: { TypedRecordFields } 
  : '{' TypedExprs '}' { TypedRecordFields $2 }

TypedExprs :: { TypedExprs }
  : TypedExpr { TypedExprs0 $1 }
  | TypedExpr ',' TypedExprs { TypedExprs1 $1 $3 }
  | Expr ',' TypedExprs { TypedExprs2 $1 $3 }
  | TypedExpr ',' Exprs { TypedExprs3 $1 $3 }

TypedExpr :: { TypedExpr }
  : Expr '::' TopType { TypedExpr $1 $3 }

TypeSigs :: { TypeSigs }
  : TypeSig { TypeSigs0 $1 }
  | TypeSig ';' TypeSigs { TypeSigs1 $1 $3 }

TypeSig :: { TypeSig }
  : FunType { TypeSig0 $1 }
  | FunType 'when' TypeGuards { TypeSig1 $1 $3 }

TypeGuards :: { TypeGuards }
  : TypeGuard { TypeGuards0 $1 }
  | TypeGuard ',' TypeGuards { TypeGuards1 $1 $3 }

TypeGuard :: { TypeGuard }
  : Atom '(' TopTypes ')' { TypeGuard0 $1 $3 }
  | Var '::' TopType { TypeGuard1 $1 $3 }

TopTypes :: { TopTypes }
  : TopType { TopTypes0 $1 }
  | TopType ',' TopTypes { TopTypes1 $1 $3 }

TopType :: { TopType }
  : Var '::' TopType { TopType0 $1 $3 }
  | Type '|' TopType { TopType1 $1 $3 }
  | Type { TopType2 $1 }

Type :: { Type }
  : Type '..' Type   { Type0 $1 $3 }
  | Type AddOp Type  { Type1 $1 $2 $3 }
  | Type MultOp Type { Type2 $1 $2 $3 }
  | PrefixOp Type    { Type3 $1 $2 }
  | '(' TopType ')'  { Type4 $2 }
  | Var              { Type5 $1 }
  | Atom             { Type6 $1 }
  | Atom '(' ')'     { Type7 $1 }
  | Atom '(' TopTypes ')' { Type8 $1 $3 }
  | Atom ':' Atom '(' ')' { Type9 $1 $3 }
  | Atom ':' Atom '(' TopTypes ')' { Type10 $1 $3 $5}
  | '[' ']' { Type11 }
  | '[' TopType ']' { Type12 $2 }
  | '[' TopType ',' '...' ']' { Type13 $2 }
  | '#' '{' '}' { Type14 }
  | '#' '{' MapPairTypes '}' { Type15 $3 }
  | '{' '}' { Type16 }
  | '{' TopTypes '}' { Type17 $2 }
  | '#' Atom '{' '}' { Type18 $2 }
  | '#' Atom '{' FieldTypes '}' { Type19 $2 $4 }
  | BinaryType { Type20 $1 }
  | int  { Type21 $1 }
  | char { Type22 $1 }
  | 'fun' '(' ')' { Type23 }
  | 'fun' '(' FunType ')' { Type24 $3 }

FunType :: { FunType }
  : '(' '...' ')' '->' TopType { FunType0 $5 }
  | '(' ')' '->' TopType { FunType1 $4 }
  | '(' TopTypes ')' '->' TopType { FunType2 $2 $5 }

MapPairTypes :: { MapPairTypes }
  : MapPairType { MapPairTypes0 $1 }
  | MapPairType ',' MapPairTypes { MapPairTypes1 $1 $3 }

MapPairType :: { MapPairType }
  : TopType '=>' TopType { MapPairType0 $1 $3 }
  | TopType ':=' TopType { MapPairType1 $1 $3 }

FieldTypes :: { FieldTypes }
  : FieldType { FieldTypes0 $1 }
  | FieldType ',' FieldTypes { FieldTypes1 $1 $3 }

FieldType :: { FieldType }
  : Atom '::' TopType { FieldType $1 $3 }

BinaryType :: { BinaryType }
  : '<<' '>>' { BinaryType0 }
  | '<<' BinBaseType '>>' { BinaryType1 $2 }
  | '<<' BinUnitType '>>' { BinaryType2 $2 }
  | '<<' BinBaseType ',' BinUnitType '>>' { BinaryType3 $2 $4 }

BinBaseType :: { BinBaseType }
  : Var ':' Type { BinBaseType $1 $3 } 

BinUnitType :: { BinUnitType }
  : Var ':' Var '*' Type  { BinUnitType $1 $3 $5 }

AttrVal :: { AttrVal }
  : Expr { AttrVal0 $1 }
  | Expr ',' Exprs { AttrVal1 $1 $3 }
  | '(' Expr ',' Exprs ')' { AttrVal1 $2 $4 }

Function :: { Function }
  : FunctionClauses { Function $1 }

FunctionClauses :: { FunctionClauses }
  : FunctionClause { FunctionClauses0 $1 }
  | FunctionClause ';' FunctionClauses { FunctionClauses1 $1 $3 }

FunctionClause :: { FunctionClause }
  : Atom ClauseArgs ClauseGuard ClauseBody { FunctionClause $1 $2 $3 $4 }

ClauseArgs :: { ClauseArgs }
  : PatArgumentList { ClauseArgs $1 }

ClauseGuard :: { ClauseGuard }
  : 'when' Guard { ClauseGuard0 $2 } 
  | {- empty -} { ClauseGuard1 }

ClauseBody :: { ClauseBody }
  : '->' Exprs { ClauseBody $2 }


Expr :: { Expr }
  : 'catch' Expr        { Expr0 $2 }
  | Expr '=' Expr       { Expr1 $1 $3 }
  | Expr '!' Expr       { Expr2 $1 $3 }
  | Expr 'orelse' Expr  { Expr3 $1 $3 }
  | Expr 'andalso' Expr { Expr4 $1 $3 }
  | Expr CompOp Expr    { Expr5 $1 $2 $3 }
  | Expr ListOp Expr    { Expr6 $1 $2 $3 }
  | Expr AddOp Expr     { Expr7 $1 $2 $3 }
  | Expr MultOp Expr    { Expr8 $1 $2 $3 }
  | PrefixOp Expr       { Expr9 $1 $2 }
  | MapExpr             { Expr10 $1 }
  | FunctionCall        { Expr11 $1 }
  | RecordExpr          { Expr12 $1 }
  | ExprRemote          { Expr13 $1 }

ExprRemote :: { ExprRemote }
  : ExprMax ':' ExprMax { ExprRemote0 $1 $3 }
  | ExprMax { ExprRemote1 $1 }

ExprMax :: { ExprMax }
  : Var                 { ExprMax0 $1 }
  | Atomic              { ExprMax1 $1 }
  | List                { ExprMax2 $1 }
  | Binary              { ExprMax3 $1 }
  | ListComprehension   { ExprMax4 $1 }
  | BinaryComprehension { ExprMax5 $1 }
  | Tuple               { ExprMax6 $1 }
  | '(' Expr ')'        { ExprMax7 $2 }
  | 'begin' Exprs 'end' { ExprMax8 $2 }
  | IfExpr              { ExprMax9 $1 }
  | CaseExpr            { ExprMax10 $1 }
  | ReceiveExpr         { ExprMax11 $1 }
  | FunExpr             { ExprMax12 $1 }
  | TryExpr             { ExprMax13 $1 }


PatExpr :: { PatExpr }
  : PatExpr '=' PatExpr    { PatExpr0 $1 $3 }
  | PatExpr CompOp PatExpr { PatExpr1 $1 $2 $3 }
  | PatExpr ListOp PatExpr { PatExpr2 $1 $2 $3 }
  | PatExpr AddOp PatExpr  { PatExpr3 $1 $2 $3 }
  | PatExpr MultOp PatExpr { PatExpr4 $1 $2 $3 }
  | PrefixOp PatExpr       { PatExpr5 $1 $2 }
  | MapPatExpr             { PatExpr6 $1 }
  | RecordPatExpr          { PatExpr7 $1 }
  | PatExprMax             { PatExpr8 $1 }

PatExprMax :: { PatExprMax }
  : Var             { PatExprMax0 $1 }
  | Atomic          { PatExprMax1 $1 }
  | List            { PatExprMax2 $1 }
  | Binary          { PatExprMax3 $1 }
  | Tuple           { PatExprMax4 $1 }
  | '(' PatExpr ')' { PatExprMax5 $2 }

MapPatExpr :: { MapPatExpr }
  : '#' MapTuple { MapPatExpr0 $2 }
  | PatExprMax '#' MapTuple { MapPatExpr1 $1 $3 }
  | MapPatExpr '#' MapTuple { MapPatExpr2 $1 $3 }

RecordPatExpr :: { RecordPatExpr }
  : '#' Atom '.' Atom { RecordPatExpr0 $2 $4 }
  | '#' Atom RecordTuple { RecordPatExpr1 $2 $3 }

List :: { List }
  : '[' ']' { List0 }
  | '[' Expr Tail { List1 $2 $3 }

Tail :: { Tail }
  : ']' { Tail0 }
  | '|' Expr ']'  { Tail1 $2 }
  | ',' Expr Tail { Tail2 $2 $3 }

Binary ::  { Binary }
  : '<<' '>>' { Binary0 }
  | '<<' BinElements '>>' { Binary1 $2 }

BinElements :: { BinElements }
  : BinElement { BinElements0 $1 }
  | BinElement ',' BinElements { BinElements1 $1 $3 }

BinElement :: { BinElement }
  : BitExpr OptBitSizeExpr OptBitTypeList { BinElement $1 $2 $3 }

BitExpr :: { BitExpr }
  : PrefixOp ExprMax { BitExpr0 $1 $2 }
  | ExprMax { BitExpr1 $1 }

OptBitSizeExpr ::  { OptBitSizeExpr }
  : ':' BitSizeExpr { OptBitSizeExpr0 $2 }
  | {- empty -} { OptBitSizeExpr1 }

OptBitTypeList :: { OptBitTypeList }
  : '/' BitTypeList { OptBitTypeList0 $2 } 
  | {- empty -} { OptBitTypeList1 }

BitTypeList :: { BitTypeList }
  : BitType '-' BitTypeList { BitTypeList0 $1 $3 }
  | BitType { BitTypeList1 $1 }

BitType :: { BitType }
  : Atom { BitType0 $1 }
  | Atom ':' int { BitType1 $1 $3 }

BitSizeExpr :: { BitSizeExpr }
  : ExprMax { BitSizeExpr $1 }

ListComprehension :: { ListComprehension }
  : '[' Expr '||' LcExprs ']'  { ListComprehension $2 $4 }

BinaryComprehension :: { BinaryComprehension }
  : '<<' ExprMax '||' LcExprs '>>' { BinaryComprehension $2 $4 }

LcExprs :: { LcExprs }
  : LcExpr { LcExprs0 $1 }
  | LcExpr ',' LcExprs { LcExprs1 $1 $3 }

LcExpr :: { LcExpr }
  : Expr { LcExpr0 $1 }
  | Expr '<-' Expr { LcExpr1 $1 $3 }
  | Binary '<=' Expr { LcExpr2 $1 $3 }

Tuple :: { Tuple }
  : '{' '}' { Tuple0 }
  | '{' Exprs '}' { Tuple1 $2 }

MapExpr :: { MapExpr }
  : '#' MapTuple { MapExpr0 $2 }
  | ExprMax '#' MapTuple { MapExpr1 $1 $3 }
  | MapExpr '#' MapTuple { MapExpr2 $1 $3 }

MapTuple :: { MapTuple }
  : '{' '}' { MapTuple0 }
  | '{' MapFields '}' { MapTuple1 $2 }

MapFields :: { MapFields }
  : MapField { MapFields0 $1 }
  | MapField ',' MapFields { MapFields1 $1 $3 } 

MapField :: { MapField }
  : MapFieldAssoc { MapField0 $1 }
  | MapFieldExact { MapField1 $1 }

MapFieldAssoc :: { MapFieldAssoc }
  : MapKey '=>' Expr { MapFieldAssoc $1 $3 }

MapFieldExact :: { MapFieldExact }
  : MapKey ':=' Expr { MapFieldExact $1 $3 }

MapKey :: { MapKey }
  : Expr { MapKey $1 } 

RecordExpr :: { RecordExpr }
  : '#' Atom '.' Atom  { RecordExpr0 $2 $4 }
  | '#' Atom RecordTuple { RecordExpr1 $2 $3 } 
  | ExprMax '#' Atom '.' Atom { RecordExpr2 $1 $3 $5 }
  | ExprMax '#' Atom RecordTuple { RecordExpr3 $1 $3 $4 }
  | RecordExpr '#' Atom '.' Atom { RecordExpr4 $1 $3 $5 }
  | RecordExpr '#' Atom RecordTuple { RecordExpr5 $1 $3 $4 }

RecordTuple :: { RecordTuple }
  : '{' '}' { RecordTuple0 }
  | '{' RecordFields '}' { RecordTuple1 $2 }

RecordFields :: { RecordFields }
  : RecordField { RecordFields0 $1 }
  | RecordField ',' RecordFields { RecordFields1 $1 $3 }

RecordField :: { RecordField }
  : Var '=' Expr { RecordField0 $1 $3 } 
  | Atom '=' Expr { RecordField1 $1 $3 }

FunctionCall :: { FunctionCall }
  : ExprRemote ArgumentList { FunctionCall $1 $2 }

IfExpr :: { IfExpr }
  : 'if' IfClauses 'end' { IfExpr $2 }

IfClauses :: { IfClauses }
  : IfClause { IfClauses0 $1}
  | IfClause ';' IfClauses { IfClauses1 $1 $3 }

IfClause :: { IfClause }
  : Guard ClauseBody { IfClause $1 $2 }

CaseExpr :: { CaseExpr }
  : 'case' Expr 'of' CrClauses 'end' { CaseExpr $2 $4 }

CrClauses :: { CrClauses }
  : CrClause { CrClauses0 $1 }
  | CrClause ';' CrClauses { CrClauses1 $1 $3 }

CrClause :: { CrClause }
  : Expr ClauseGuard ClauseBody { CrClause $1 $2 $3 }

ReceiveExpr :: { ReceiveExpr }
  : 'receive' CrClauses 'end' { ReceiveExpr0 $2 }
  | 'receive' 'after' Expr ClauseBody 'end' { ReceiveExpr1 $3 $4 }
  | 'receive' CrClauses 'after' Expr ClauseBody 'end' { ReceiveExpr2 $2 $4 $5 }

FunExpr :: { FunExpr }
  : 'fun' Atom '/' int { FunExpr0 $2 $4 }
  | 'fun' AtomOrVar ':' AtomOrVar '/' IntegerOrVar { FunExpr1 $2 $4 $6 }
  | 'fun' FunClauses 'end' { FunExpr2 $2 }

AtomOrVar :: { AtomOrVar }
  : Atom { AtomOrVar0 $1 }
  | Var { AtomOrVar1 $1 }

IntegerOrVar :: { IntegerOrVar }
  : int { IntegerOrVar0 $1 }
  | Var { IntegerOrVar1 $1 }

FunClauses :: { FunClauses }
  : FunClause { FunClauses0 $1 }
  | FunClause ';' FunClauses { FunClauses1 $1 $3 }

FunClause :: { FunClause }
  : PatArgumentList ClauseGuard ClauseBody { FunClause0 $1 $2 $3 }
  | Var PatArgumentList ClauseGuard ClauseBody { FunClause1 $1 $2 $3 $4 }

TryExpr :: { TryExpr }
  : 'try' Exprs 'of' CrClauses TryCatch { TryExpr0 $2 $4 $5 }
  | 'try' Exprs TryCatch { TryExpr1 $2 $3 }

TryCatch :: { TryCatch }
  : 'catch' TryClauses 'end' { TryCatch0 $2 }
  | 'catch' TryClauses 'after' Exprs 'end' { TryCatch1 $2 $4 }
  | 'after' Exprs 'end' { TryCatch2 $2 }

TryClauses :: { TryClauses }
  : TryClause { TryClauses0 $1 }
  | TryClause ';' TryClauses { TryClauses1 $1 $3 }

TryClause :: { TryClause }
  : PatExpr ClauseGuard ClauseBody { TryClause0 $1 $2 $3 }
  | Atom ':' PatExpr TryOptStacktrace ClauseGuard ClauseBody
       { TryClause1 $1 $3 $4 $5 $6 }
  | Var ':' PatExpr TryOptStacktrace ClauseGuard ClauseBody
       { TryClause2 $1 $3 $4 $5 $6 }

TryOptStacktrace :: { TryOptStacktrace }
  : ':' Var { TryOptStacktrace0 $2 }
  | {- empty -} { TryOptStacktrace1 }

ArgumentList :: { ArgumentList }
  : '(' ')' { ArgumentList0 }
  | '(' Exprs ')' { ArgumentList1 $2}

PatArgumentList :: { PatArgumentList }
  : '(' ')' { PatArgumentList0 }
  | '(' PatExprs ')' { PatArgumentList1 $2 }

Exprs :: { Exprs } 
  : Expr { Exprs0 $1}
  | Expr ',' Exprs { Exprs1 $1 $3 }

PatExprs :: { PatExprs }
  : PatExpr { PatExprs0 $1}
  | PatExpr ',' PatExprs { PatExprs1 $1 $3 }

Guard :: { Guard }
  : Exprs { Guard0 $1 }
  | Exprs ';' Guard { Guard1 $1 $3 }

Atomic :: { Atomic }
  : char { Atomic0 $1 }
  | int { Atomic1 $1 }
  | sint { Atomic11 $1 }
  | float { Atomic2 $1 }
  | Atom { Atomic3 $1 }
  | Strings { Atomic4 $1 }

Strings :: { Strings }
  : string { Strings0 $1 }
  | string Strings { Strings1 $1 $2 }

PrefixOp :: { PrefixOp }
  : '+' { PPlus }
  | '-' { PSub }
  | 'bnot' { PBnot }
  | 'not' { PNot }

MultOp :: { MultOp }
  : '/' { Mx }
  | '*' { Mmult }
  | 'div' { Mdiv }
  | 'rem' { Mrem }
  | 'band' { Mband }
  | 'and' { Mand }

AddOp :: { AddOp }
  : '+' { Aplus }
  | '-' { Asub }
  | 'bor' { Abor }
  | 'bxor' { Abxor }
  | 'bsl' { Absl }
  | 'bsr' { Absr }
  | 'or' { Aor }
  | 'xor' { Axor }

ListOp :: { ListOp }
  : '++' { Lpp }
  | '--' { Lss }

CompOp :: { CompOp }
  : '==' { Ce }
  | '/=' { Cne }
  | '=<' { Cle }
  | '<'  { Cl }
  | '>=' { Cge }
  | '>'  { Cg }
  | '=:=' { Cme }
  | '=/=' { Cmn }




{

data E a = OK a | Failed String 

thenE :: E a -> (a -> E b) -> E b
m `thenE` k = case m of
  OK a -> k a
  Failed e -> Failed e

returnE :: a -> E a
returnE a = OK a

failE :: String -> E a
failE err = Failed err

catchE :: E a -> (String -> E a) -> E a
catchE m k = case m of
  OK a -> OK a
  Failed e -> k e

runCalc :: String -> E Forms
runCalc = calc . alexScanTokens

happyError :: [Token] -> a
happyError tks = error ("Parse error " ++ show (take 20 tks) ++ " \n")


}
