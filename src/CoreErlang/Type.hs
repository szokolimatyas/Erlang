{-# LANGUAGE DeriveFoldable #-}
{-# LANGUAGE DeriveFunctor #-}
{-# LANGUAGE DeriveTraversable #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module CoreErlang.Type where

import Data.Functor.Foldable.TH (makeBaseFunctor)

newtype Atom = Atom String -- a
  deriving (Show)

newtype VariableName = VariableName String
  deriving (Show)

data Ann a
  = -- ( • -| [ c 1 , . . ., c n ] )
    Ann a [Constant]
  | -- No Annotated
    NoAnn a
  deriving (Show)

-- AnnotatedModule:
--   Module
--   ( Module -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedModule = Ann Module

-- Module:
--   module a ModuleHeader ModuleBody end
data Module = Module Atom ModuleHeader ModuleBody
  deriving (Show)

-- ModuleHeader :
--   Exports Attributes
data ModuleHeader = ModuleHeader Exports Attributes
  deriving (Show)

-- Exports:
--   [ FunctionName 1 , . . . , FunctionName n ] (n ≥ 0)
newtype Exports = Exports [FunctionName]
  deriving (Show)

-- FunctionName (a/i):
--   a / i
--   where a is called the identifier, and i the arity.
data FunctionName = FunctionName Atom Integer
  deriving (Show)

-- attributes [ ModuleAttribute 1 , . . . , ModuleAttribute n ] (n ≥ 0)
newtype Attributes = Attributes [ModuleAttribute]
  deriving (Show)

-- ModuleAttribute:
--   a = c
--   where a is called the key, and c the value of the attribute.
data ModuleAttribute = ModuleAttribute Atom Constant
  deriving (Show)

-- ModuleBody:
--   FunctionDefinition 1 · · · FunctionDefinition n (n ≥ 0)
newtype ModuleBody = ModuleBody [FunctionDefinition]
  deriving (Show)

-- FunctionDefinition:
--   AnnotatedFunctionName = AnnotatedFun
data FunctionDefinition = FunctionDefinition AnnotatedFunctionName AnnotatedFun
  deriving (Show)

-- AnnotatedFunctionName:
--   FunctionName
--   ( FunctionName -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedFunctionName = Ann FunctionName

-- AnnotatedFun:
--   Fun
--   ( Fun -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedFun = Ann Fun

-- Constant (c):
--   AtomicLiteral
--T  { c 1 , . . . , c n } (n ≥ 0)
--L  [ c 1 , . . . , c n ] (n ≥ 1)
--P  [ c 1 , . . . , c n−1 | c n ] (n ≥ 2)
data Constant -- c
  = ConstantAtomicLiteral AtomicLiteral
  | ConstantT [Constant]
  | ConstantL [Constant]
  | ConstantP [Constant] Constant
  deriving (Show)

-- AtomicLiteral :
--   Integer
--   Float
--   Atom
--   Nil
--   Char
--   String
data AtomicLiteral
  = LInteger Integer
  | LFloat Double
  | LAtom Atom
  | LNil -- [ ]
  | LChar Char
  | LString String
  deriving (Show)

-- AnnotatedVariable (v):
--   VariableName
--   ( VariableName -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedVariable = Ann VariableName --v

-- AnnotatedPattern (p):
--   v
--   Pattern
--   ( Pattern -| [ c 1 , . . . , c n ] ) (n ≥ 0)
data AnnotatedPattern -- p
  = AnnotatedPatternVariable AnnotatedVariable
  | AnnotatedPatternPattern (Ann Pattern)
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
  | PatternMap PMap
  | PatternBitstringPattern [Ann BitstringPattern]
  | PatternAlias AnnotatedVariable AnnotatedPattern
  deriving (Show)

data PMMap
  = PMMap AnnotatedPattern AnnotatedPattern
  deriving (Show)

-- PMap
--   ~{ k1 := v1, .. kn -> vn }~
--   ~{ k1 := v2 , .. | ek }~
data PMap
  = PMap [Ann PMMap]
  | PMapP [Ann PMMap] AnnotatedPattern
  deriving (Show)

-- BitstringPattern:
--   # < p > ( e 1 , . . . , e n ) (n ≥ 0)
data BitstringPattern = BitstringPattern AnnotatedPattern [Expression]
  deriving (Show)

-- Expression (e):
--   AnnotatedValueList
--   AnnotatedSingleExpression
data Expression -- e
  = ExpressionValueList AnnotatedValueList
  | ExpressionSingleExpression AnnotatedSingleExpression
  deriving (Show)

-- AnnotatedValueList:
--   ValueList
--   ( ValueList -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedValueList = Ann ValueList

-- ValueList:
--   < AnnotatedSingleExpression 1 , . . . ,
--   AnnotatedSingleExpression n > (n ≥ 0)
newtype ValueList = ValueList [AnnotatedSingleExpression]
  deriving (Show)

-- AnnotatedSingleExpression:
--   SingleExpression
--   ( SingleExpression -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedSingleExpression = Ann SingleExpression

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
  | SEMap Map
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

-- k1 (=> or :=) v1
data MMap
  = InsertM Expression Expression
  | UpdateM Expression Expression
  deriving (Show)

-- Map
--   ~{ k1 (=> or :=) v1, .. kn -> vn }~
--   ~{ e1 (=> or :=) e2 , .. | ek }~
data Map
  = Map [Ann MMap]
  | MapP [Ann MMap] Expression
  deriving (Show)

-- Binary:
--   # { Bitstring 1 , . . . , Bitstring n } # (n ≥ 0)
newtype Binary = Binary [Ann Bitstring]
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
  = VariablesS AnnotatedVariable
  | VariablesM [AnnotatedVariable]
  deriving (Show)

-- case e of AnnotatedClause 1 · · · AnnotatedClause n end (n ≥ 1)
data Case = Case Expression [AnnotatedClause]
  deriving (Show)

-- AnnotatedClause:
--   Clause
--   ( Clause -| [ c 1 , . . . , c n ] ) (n ≥ 0)
type AnnotatedClause = Ann Clause

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
--   fun a : AnnotatedFunctionName
--   Note that there is no end keyword terminating the expression.
data Fun
  = Fun [AnnotatedVariable] Expression
  | ExtFun (Ann Atom) AnnotatedFunctionName
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
data PrimOpCall = PrimOpCall (Ann Atom) [Expression]
  deriving (Show)

-- Try:
--   try e 1 of Variables -> e 2
--   catch Variables -> e 3 (m, n ≥ 0)
data Try = Try Expression Variables Expression Variables Expression
  deriving (Show)

-- Receive:
--   receive AnnotatedClause 1 · · · AnnotatedClause n Timeout (n ≥ 0)
data Receive = Receive [AnnotatedClause] Timeout
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

makeBaseFunctor ''Constant
