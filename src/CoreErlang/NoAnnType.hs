module CoreErlang.NoAnnType where

import CoreErlang.Type (Atom, AtomicLiteral, Attributes, Constant, Exports, FunctionName, ModuleAttribute, ModuleHeader, VariableName)

-- Module:
--   module a ModuleHeader ModuleBody end
data Module = Module Atom ModuleHeader ModuleBody
  deriving (Show)

-- ModuleBody:
--   FunctionDefinition 1 · · · FunctionDefinition n (n ≥ 0)
newtype ModuleBody = ModuleBody [FunctionDefinition]
  deriving (Show)

-- FunctionDefinition:
--   AnnotatedFunctionName = AnnotatedFun
data FunctionDefinition = FunctionDefinition FunctionName Fun
  deriving (Show)

-- AnnotatedPattern (p):
--   v
--   Pattern
--   ( Pattern -| [ c 1 , . . . , c n ] ) (n ≥ 0)
data AnnotatedPattern -- p
  = AnnotatedPatternVariable VariableName
  | AnnotatedPatternPattern Pattern
  deriving (Show)

-- Pattern:
--   AtomicLiteral
--T  { p 1 , . . . , p n } (n ≥ 0)
--L  [ p 1 , . . . , p n ] (n ≥ 1)
--P  [ p 1 , . . . , p n−1 | p n ] (n ≥ 2)
--   # { BitstringPattern 1 , . . . , BitstringPattern n } # (n ≥ 0)
--   v = p
--   where the last form v = p is called an alias pattern.
data Pattern
  = PatternAtomicLiteral AtomicLiteral
  | PatternT [AnnotatedPattern]
  | PatternL [AnnotatedPattern]
  | PatternP [AnnotatedPattern] AnnotatedPattern
  | PatternBitstringPattern [BitstringPattern]
  | PatternAlias VariableName AnnotatedPattern
  deriving (Show)

-- BitstringPattern:
--   # < p > ( e 1 , . . . , e n ) (n ≥ 0)
data BitstringPattern = BitstringPattern AnnotatedPattern [Expression]
  deriving (Show)

-- Expression (e):
--   AnnotatedValueList
--   AnnotatedSingleExpression
data Expression -- e
  = ExpressionValueList ValueList
  | ExpressionSingleExpression SingleExpression
  deriving (Show)

-- ValueList:
--   < AnnotatedSingleExpression 1 , . . . ,
--   AnnotatedSingleExpression n > (n ≥ 0)
newtype ValueList = ValueList [SingleExpression]
  deriving (Show)

-- SingleExpression:
--   AtomicLiteral
--   VariableName
--   FunctionName
--   Tuple
--   List
--   Binary
--   Let
--   Case
--   Fun
--   Letrec
--   Application
--   InterModuleCall
--   PrimOpCall
--   Try
--   Receive
--   Sequencing
--   Catch
data SingleExpression
  = SEAtomicLiteral AtomicLiteral
  | SEVariableName VariableName
  | SEFunctionName FunctionName
  | SETuple Tuple
  | SEList List
  | SEBinary Binary
  | SELet Let
  | SECase Case
  | SEFun Fun
  | SELetrec Letrec
  | SEApplication Application
  | SEInterModuleCall InterModuleCall
  | SEPrimOpCall PrimOpCall
  | SETry Try
  | SEReceive Receive
  | SESequencing Sequencing
  | SECatch Catch
  deriving (Show)

-- Tuple:
--   { e 1 , . . . , e n }  (n ≥ 0)
--   Note that this includes the 0-tuple { } and 1-tuples {x}.
newtype Tuple = Tuple [Expression]
  deriving (Show)

-- List:
--L  [ e 1 , . . . , e n ] (n ≥ 1)
--P  [ e 1 , . . . , e n−1 | e n ] (n ≥ 2)
data List
  = ListL [Expression]
  | ListP [Expression] Expression
  deriving (Show)

-- Binary:
--   # { Bitstring 1 , . . . , Bitstring n } # (n ≥ 0)
newtype Binary = Binary [Bitstring]
  deriving (Show)

-- Bitstring:
--   # < e 0 > ( e 1 , . . . , e n ) (n ≥ 0)
data Bitstring = Bitstring Expression [Expression]
  deriving (Show)

-- Let:
--   let Variables = e 1 in e 2
data Let = Let Variables Expression Expression
  deriving (Show)

-- Variables:
--   v
--   < v 1 , . . . , v n > (n ≥ 0)
data Variables
  = VariablesS VariableName
  | VariablesM [VariableName]
  deriving (Show)

-- case e of AnnotatedClause 1 · · · AnnotatedClause n end (n ≥ 1)
data Case = Case Expression [Clause]
  deriving (Show)

-- Clause:
--   Patterns Guard -> e
data Clause = Clause Patterns Guard Expression
  deriving (Show)

-- Patterns:
--   p
--   < p 1 , . . . , p n > (n ≥ 0)
data Patterns
  = PatternS AnnotatedPattern
  | PatternM [AnnotatedPattern]
  deriving (Show)

-- Guard :
--   when e
newtype Guard = Guard Expression
  deriving (Show)

-- Fun:
--   fun ( v 1 , . . . , v n ) -> e (n ≥ 0)
--   Note that there is no end keyword terminating the expression.
data Fun = Fun [VariableName] Expression
  deriving (Show)

-- Letrec:
--   letrec FunctionDefinition 1 · · · FunctionDefinition n in e (n ≥ 0)
data Letrec = Letrec [FunctionDefinition] Expression
  deriving (Show)

-- Application:
--   apply e 0 ( e 1 , . . . , e n ) (n ≥ 0)
data Application = Application Expression [Expression]
  deriving (Show)

-- InterModuleCall :
--   call e 0 1 : e 0 2 ( e 1 , . . . , e n ) (n ≥ 0)
data InterModuleCall = InterModuleCall Expression Expression [Expression]
  deriving (Show)

-- PrimOpCall :
--   primop a ( e 1 , . . . , e n ) (n ≥ 0)
data PrimOpCall = PrimOpCall Atom [Expression]
  deriving (Show)

-- Try:
--   try e 1 of Variables -> e 2
--   catch Variables -> e 3 (m, n ≥ 0)
data Try = Try Expression Variables Expression Variables Expression
  deriving (Show)

-- Receive:
--   receive AnnotatedClause 1 · · · AnnotatedClause n Timeout (n ≥ 0)
data Receive = Receive [Clause] Timeout
  deriving (Show)

-- Timeout:
--   after e 1 -> e 2
--   where e 1 is called the expiry expression and e 2 the expiry body.
data Timeout = Timeout Expression Expression
  deriving (Show)

-- Sequencing:
--   do e 1 e 2
data Sequencing = Sequencing Expression Expression
  deriving (Show)

-- Catch:
--   catch e
newtype Catch = Catch Expression
  deriving (Show)
