{
module CoreErlang.B where
import CoreErlang.A
import CoreErlang.Type
}

%name calc
%tokentype { Token }


-- ( ) { } [ ] <  >
-- | # , : / = -> -|


%token
  'after'       { TKeywords "after"      }
  'catch'       { TKeywords "catch"      }
  'let'         { TKeywords "let"        }
  'receive'     { TKeywords "receive"    }
  'apply'       { TKeywords "apply"      }
  'do'          { TKeywords "do"         }
  'letrec'      { TKeywords "letrec"     }
  'try'         { TKeywords "try"        }
  'attributes'  { TKeywords "attributes" }
  'end'         { TKeywords "end"        }
  'module'      { TKeywords "module"     }
  'when'        { TKeywords "when"       }
  'call'        { TKeywords "call"       }
  'fun'         { TKeywords "fun"        }
  'of'          { TKeywords "of"         }
  'case'        { TKeywords "case"       }
  'in'          { TKeywords "in"         }
  'primop'      { TKeywords "primop"     }

  '('           { TSeparators "(" }
  ')'           { TSeparators ")" }
  '{'           { TSeparators "{" }
  '}'           { TSeparators "}" }
  '['           { TSeparators "[" }
  ']'           { TSeparators "]" }
  '<'           { TSeparators "<" }
  '>'           { TSeparators ">" }
  '|'           { TSeparators "|" }
  '#'           { TSeparators "#" }
  ','           { TSeparators "," }
  ':'           { TSeparators ":" }
  '/'           { TSeparators "/" }
  '='           { TSeparators "=" }
  '->'          { TSeparators "->" }
  '-|'          { TSeparators "-|" }
  '~'           { TSeparators "~" }
  '=>'          { TSeparators "=>" }
  ':='          { TSeparators ":=" }

  int           { TInt     $$ }
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


many(a) :: { [a] }
  : {- empty -} { []       }
  | many1(a)  { reverse $1 }

many1(a) :: { [a] }
  : a { [$1] }
  | many1(a) a { $2 : $1 }


ann(a) :: { Ann a }
  : a { NoAnn $1 }
  | '(' a '-|' '[' sep(Constant, ',') ']' ')' { Ann $2 $5 }

AnnotatedModule :: { AnnotatedModule }
  : ann(Module) { $1 }

VariableName :: { VariableName }
  : var { VariableName $1 }

Atom :: { Atom }
  : atom { Atom $1 }

Module :: { Module }
  : 'module' Atom ModuleHeader ModuleBody 'end' { Module $2 $3 $4 }

ModuleHeader :: { ModuleHeader }
  : Exports Attributes { ModuleHeader $1 $2 } 

Exports :: { Exports }
  : '[' sep(FunctionName, ',') ']' { Exports $2 }

FunctionName :: { FunctionName }
  : Atom '/' int { FunctionName $1 $3 }

Attributes :: { Attributes }
  : 'attributes' '[' sep(ModuleAttribute, ',') ']' { Attributes $3 }

ModuleAttribute :: { ModuleAttribute }
  : Atom '=' Constant { ModuleAttribute $1 $3 }

ModuleBody :: { ModuleBody }
  : many(FunctionDefinition) { ModuleBody $1 }

FunctionDefinition :: { FunctionDefinition }
  : AnnotatedFunctionName '=' AnnotatedFun { FunctionDefinition $1 $3 }

AnnotatedFunctionName :: { AnnotatedFunctionName }
  : ann(FunctionName) { $1 }

AnnotatedFun :: { AnnotatedFun }
  : ann(Fun) { $1 }

Constant :: { Constant }
  : AtomicLiteral { ConstantAtomicLiteral $1 }
  | '{' sep(Constant, ',') '}' { ConstantT $2 }
  | '[' sep(Constant, ',') ']' { ConstantL $2 }
  | '[' sep(Constant, ',') '|' Constant ']' { ConstantP $2 $4 }

AtomicLiteral :: { AtomicLiteral }
  : int      { LInteger $1 }
  | float    { LFloat $1   }
  | Atom     { LAtom $1    }
  | '[' ']'  { LNil }
  | char     { LChar $1    }
  | string   { LString $1  }

AnnotatedVariable :: { AnnotatedVariable }
  : ann(VariableName) { $1 }

AnnotatedPattern :: { AnnotatedPattern }
  : AnnotatedVariable { AnnotatedPatternVariable $1 }
  | ann(Pattern) { AnnotatedPatternPattern $1 }

Pattern :: { Pattern }
  : AtomicLiteral { PatternAtomicLiteral $1 }
  | '{' sep(AnnotatedPattern, ',') '}'  { PatternT $2 }
  | '[' sep(AnnotatedPattern, ',') ']'  { PatternL $2 }
  | '[' sep(AnnotatedPattern, ',') '|' AnnotatedPattern ']'  { PatternP $2 $4 }
  | '#' '{' sep(AnnBitstringPattern,',') '}' '#'  { PatternBitstringPattern $3 }
  | PMap { PatternMap $1 }
  | AnnotatedVariable '=' AnnotatedPattern { PatternAlias $1 $3 }

PMMap :: { PMMap }
  : AnnotatedPattern ':=' AnnotatedPattern { PMMap $1 $3 }

AnnPMMap :: { Ann PMMap }
  : ann(PMMap) { $1 }

PMap :: { PMap }
  : '~' '{' sep(AnnPMMap, ',') '}' '~' { PMap $3 }
  | '~' '{' sep(AnnPMMap, ',') '|' AnnotatedPattern '}' '~' { PMapP $3 $5}

AnnBitstringPattern :: {Ann BitstringPattern}
  : ann(BitstringPattern) { $1 }

BitstringPattern :: { BitstringPattern }
  : '#' '<' AnnotatedPattern '>' '(' sep(Expression, ',') ')' { BitstringPattern $3 $6 }

Expression :: { Expression }
  : AnnotatedValueList { ExpressionValueList $1 }
  | AnnotatedSingleExpression { ExpressionSingleExpression $1 }

AnnotatedValueList :: { AnnotatedValueList }
  : ann(ValueList) { $1 }

ValueList :: { ValueList }
  : '<' sep(AnnotatedSingleExpression, ',') '>' { ValueList $2 }

AnnotatedSingleExpression :: { AnnotatedSingleExpression }
  : ann(SingleExpression) { $1 }

SingleExpression :: { SingleExpression }
  : AtomicLiteral     { SEAtomicLiteral $1 }
  | VariableName      { SEVariableName $1 }
  | FunctionName      { SEFunctionName $1 }
  | Tuple             { SETuple $1 }
  | List              { SEList $1 }
  | Map               { SEMap $1 }
  | Binary            { SEBinary $1 }
  | Let               { SELet $1 }
  | Case              { SECase $1 }
  | Fun               { SEFun $1 }
  | Letrec            { SELetrec $1 }
  | Application       { SEApplication $1 }
  | InterModuleCall   { SEInterModuleCall $1 }
  | PrimOpCall        { SEPrimOpCall $1 }
  | Try               { SETry $1 }
  | Receive           { SEReceive $1 }
  | Sequencing        { SESequencing $1 }
  | Catch             { SECatch $1 }


Tuple :: { Tuple }
  : '{' sep(Expression, ',') '}' { Tuple $2 }

List :: { List }
  : '[' sep(Expression, ',') ']' { ListL $2 }
  | '[' sep(Expression, ',') '|' Expression ']' { ListP $2 $4 }

MMap :: { MMap }
  : Expression '=>' Expression { InsertM $1 $3 }
  | Expression ':=' Expression { UpdateM $1 $3 }

AnnMMap :: { Ann MMap }
  : ann(MMap) { $1 }

Map :: { Map }
  : '~' '{' sep(AnnMMap, ',') '}' '~' { Map $3 }
  | '~' '{' sep(AnnMMap, ',') '|' Expression '}' '~' { MapP $3 $5}

Binary :: { Binary }
  : '#' '{' sep(AnnBitstring, ',') '}' '#' { Binary $3 }

AnnBitstring :: { Ann Bitstring }
  : ann(Bitstring) { $1 }

Bitstring :: { Bitstring }
  : '#' '<' Expression '>' '(' sep(Expression, ',') ')' { Bitstring $3 $6 }

Let :: { Let }
  : 'let' Variables '=' Expression 'in' Expression { Let $2 $4 $6 }

Variables :: { Variables }
  : AnnotatedVariable { VariablesS $1 }
  | '<' sep(AnnotatedVariable, ',') '>' { VariablesM $2 }

Case :: { Case }
  : 'case' Expression 'of' many(AnnotatedClause) 'end' { Case $2 $4 }

AnnotatedClause :: { AnnotatedClause }
  : ann(Clause) { $1 }

Clause :: { Clause }
  : Patterns Guard '->' Expression { Clause $1 $2 $4 }

Patterns :: { Patterns }
  : AnnotatedPattern { PatternS $1 }
  | '<' sep(AnnotatedPattern, ',') '>' { PatternM $2 }

Guard :: { Guard }
  : 'when' Expression { Guard $2 }

Fun :: { Fun }
  : 'fun' '(' sep(AnnotatedVariable, ',') ')' '->' Expression { Fun $3 $6 }
  | 'fun' ann(Atom) ':' AnnotatedFunctionName { ExtFun $2 $4 }

Letrec :: { Letrec }
  : 'letrec' many(FunctionDefinition) 'in' Expression { Letrec $2 $4 }

Application :: { Application }
  : 'apply' Expression '(' sep(Expression, ',') ')' { Application $2 $4 }

InterModuleCall :: { InterModuleCall }
  : 'call' Expression ':' Expression '(' sep(Expression, ',') ')' { InterModuleCall $2 $4 $6 }

PrimOpCall :: { PrimOpCall }
  : 'primop' ann(Atom) '(' sep(Expression, ',') ')' { PrimOpCall $2 $4 }


Try :: { Try }
  : 'try'  Expression 'of' Variables '->' Expression 'catch' Variables '->' Expression { Try $2 $4 $6 $8 $10 } 

Receive :: { Receive }
  : 'receive' many(AnnotatedClause) Timeout { Receive $2 $3 }

Timeout :: { Timeout }
  : 'after' Expression '->' Expression { Timeout $2 $4 }

Sequencing :: { Sequencing }
  : 'do' Expression Expression { Sequencing $2 $3 }

Catch :: { Catch }
  : 'catch' Expression { Catch $2 }

{

runCalc :: String -> AnnotatedModule
runCalc = calc . alexScanTokens

happyError :: [Token] -> a
happyError tks = error ("Parse error " ++ show (take 20 tks) ++ " \n")
}
