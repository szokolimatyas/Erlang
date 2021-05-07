module CoreErlang.SimpleType where

type Expression = [SingleExpression]

type Atom = String

type VariableName = String

type Constant = AtomicLit

-- Variables:
--   < v 1 , . . . , v n > (n ≥ 0)
type Variables = [VariableName]

-- Module:
--   module a ModuleHeader ModuleBody end
data Module = Module Atom ModuleHeader ModuleBody
  deriving (Show)

-- ModuleBody:
--   FunctionDefinition 1 · · · FunctionDefinition n (n ≥ 0)
data ModuleHeader = ModuleHeader [FunctionName] [(Atom, Constant)]
  deriving (Show)

newtype ModuleBody = ModuleBody [FunctionDefinition]
  deriving (Show)

-- FunctionDefinition:
--   fun ( v 1 , . . . , v n ) -> e (n ≥ 0)
data FunctionDefinition = FunctionDefinition FunctionName [VariableName] Expression
  deriving (Show)

-- Pattern:
data Pattern
  = --   v
    PatternVarName VariableName
  | --   AtomicLiteral
    PatternAtomicLiteral AtomicLit
  | --T  { p 1 , . . . , p n } (n ≥ 0)
    PatternT [Pattern]
  | --L  [ p 1 , . . . , p n ] (n ≥ 1)
    PatternL [Pattern]
  | --P  [ p 1 , . . . , p n−1 | p n ] (n ≥ 2)
    PatternP [Pattern] Pattern
  | -- PMap
    PatternMap PMap
  | --   # { BitstringPattern 1 , . . . , BitstringPattern n } # (n ≥ 0)
    PatternBitstringPattern [BitstringPattern]
  | --   v = p
    --   where the last form v = p is called an alias pattern.
    PatternAlias VariableName Pattern
  deriving (Show)

-- PMap
--   ~{ k1 := v1, .. kn -> vn }~
--   ~{ k1 := v2 , .. | ek }~
data PMap
  = PMap [(Pattern, Pattern)]
  | PMapP [(Pattern, Pattern)] Pattern
  deriving (Show)

-- BitstringPattern:
--   # < p > ( e 1 , . . . , e n ) (n ≥ 0)
data BitstringPattern = BitstringPattern Pattern [Expression]
  deriving (Show)

--   a / i
--   where a is called the identifier, and i the arity.
data FunctionName = FunctionName Atom Integer
  deriving (Show)

data AtomicLit
  = LInteger Integer
  | LFloat Double
  | LAtom Atom
  | LNil -- [ ]
  | LChar Char
  | LString String
  deriving (Show)

-- SingleExpression:
data SingleExpression
  = SEAtomicLiteral AtomicLit
  | SEVariableName VariableName
  | SEFunctionName FunctionName
  | --   { e 1 , . . . , e n }  (n ≥ 0)
    --   Note that this includes the 0-tuple { } and 1-tuples {x}.
    SETuple [Expression]
  | SEList List
  | SEMap Map
  | --   # { Bitstring 1 , . . . , Bitstring n } # (n ≥ 0)
    SEBinary [Bitstring]
  | --   let Variables = e 1 in e 2
    SELet Variables Expression Expression
  | -- case e of AnnotatedClause 1 · · · AnnotatedClause n end (n ≥ 1)
    SECase Expression [Clause]
  | --   fun ( v 1 , . . . , v n ) -> e (n ≥ 0)
    --   Note that there is no end keyword terminating the expression.
    SEFun [VariableName] Expression
  | --   letrec FunctionDefinition 1 · · · FunctionDefinition n in e (n ≥ 0)
    SELetrec [FunctionDefinition] Expression
  | --   apply e 0 ( e 1 , . . . , e n ) (n ≥ 0)
    SEApplication Expression [Expression]
  | --   call e 0 1 : e 0 2 ( e 1 , . . . , e n ) (n ≥ 0)
    SEInterModuleCall Expression Expression [Expression]
  | --   primop a ( e 1 , . . . , e n ) (n ≥ 0)
    SEPrimOpCall Atom [Expression]
  | --   try e 1 of Variables -> e 2
    --   catch Variables -> e 3 (m, n ≥ 0)
    SETry Expression Variables Expression Variables Expression
  | --   receive AnnotatedClause1 · · · AnnotatedClausen Timeout (n ≥ 0)
    --   after e 1 -> e 2
    --   where e 1 is called the expiry expression and e 2 the expiry body.
    SEReceive [Clause] Expression Expression
  | --   do e 1 e 2
    SESequencing Expression Expression
  | --   catch e
    SECatch Expression
  deriving (Show)

-- List:
--L  [ e 1 , . . . , e n ] (n ≥ 1)
--P  [ e 1 , . . . , e n−1 | e n ] (n ≥ 2)
data List
  = ListL [Expression]
  | ListP [Expression] Expression
  deriving (Show)

data MMap
  = InsertM Expression Expression
  | UpdateM Expression Expression
  deriving (Show)

-- Map
--   ~{ k1 (=> or :=) v1, .. kn -> vn }~
--   ~{ e1 (=> or :=) e2 , .. | ek }~
data Map
  = Map [MMap]
  | MapP [MMap] Expression
  deriving (Show)

-- Bitstring:
--   # < e 0 > ( e 1 , . . . , e n ) (n ≥ 0)
data Bitstring = Bitstring Expression [Expression]
  deriving (Show)

-- Clause:
--   Patterns -> e
data Clause = Clause [Pattern] Expression
  deriving (Show)
