module CoreErlang.Translate where

import CoreErlang.NoAnnType
import CoreErlang.Type (Ann (..))
import qualified CoreErlang.Type as T

lModule :: Module -> T.AnnotatedModule
lModule = NoAnn . tModule

tModule :: Module -> T.Module
tModule (Module a b c) = T.Module a b (tModuleBody c)

tModuleBody :: ModuleBody -> T.ModuleBody
tModuleBody (ModuleBody ls) = T.ModuleBody (map tFunctionDefinition ls)

tFunctionDefinition :: FunctionDefinition -> T.FunctionDefinition
tFunctionDefinition (FunctionDefinition n f) = T.FunctionDefinition (NoAnn n) (NoAnn $ tFun f)

tAnnotatedPattern :: AnnotatedPattern -> T.AnnotatedPattern
tAnnotatedPattern (AnnotatedPatternVariable v) = T.AnnotatedPatternVariable (NoAnn v)
tAnnotatedPattern (AnnotatedPatternPattern p) = T.AnnotatedPatternPattern (NoAnn $ tPattern p)

tPattern :: Pattern -> T.Pattern
tPattern (PatternAtomicLiteral l) = T.PatternAtomicLiteral l
tPattern (PatternT t) = T.PatternT (map tAnnotatedPattern t)
tPattern (PatternL t) = T.PatternL (map tAnnotatedPattern t)
tPattern (PatternP t p) = T.PatternP (map tAnnotatedPattern t) (tAnnotatedPattern p)
tPattern (PatternBitstringPattern ls) = T.PatternBitstringPattern (map (NoAnn . tBitstringPattern) ls)
tPattern (PatternAlias v p) = T.PatternAlias (NoAnn v) (tAnnotatedPattern p)

tBitstringPattern :: BitstringPattern -> T.BitstringPattern
tBitstringPattern (BitstringPattern p es) = T.BitstringPattern (tAnnotatedPattern p) (map tExpression es)

tExpression :: Expression -> T.Expression
tExpression (ExpressionValueList vl) = T.ExpressionValueList (NoAnn $ tValueList vl)
tExpression (ExpressionSingleExpression s) = T.ExpressionSingleExpression (NoAnn $ tSingleExpression s)

tValueList :: ValueList -> T.ValueList
tValueList (ValueList ls) = T.ValueList $ map (NoAnn . tSingleExpression) ls

tSingleExpression :: SingleExpression -> T.SingleExpression
tSingleExpression (SEAtomicLiteral a) = T.SEAtomicLiteral a
tSingleExpression (SEVariableName v) = T.SEVariableName v
tSingleExpression (SEFunctionName f) = T.SEFunctionName f
tSingleExpression (SETuple t) = T.SETuple $ tTuple t
tSingleExpression (SEList l) = T.SEList (tList l)
tSingleExpression (SEBinary b) = T.SEBinary (tBinary b)
tSingleExpression (SELet l) = T.SELet (tLet l)
tSingleExpression (SECase c) = T.SECase (tCase c)
tSingleExpression (SEFun f) = T.SEFun (tFun f)
tSingleExpression (SELetrec l) = T.SELetrec (tLetrec l)
tSingleExpression (SEApplication a) = T.SEApplication (tApplication a)
tSingleExpression (SEInterModuleCall i) = T.SEInterModuleCall (tInterModuleCall i)
tSingleExpression (SEPrimOpCall p) = T.SEPrimOpCall (tPrimOpCall p)
tSingleExpression (SETry t) = T.SETry (tTry t)
tSingleExpression (SEReceive r) = T.SEReceive (tReceive r)
tSingleExpression (SESequencing s) = T.SESequencing (tSequencing s)
tSingleExpression (SECatch c) = T.SECatch (tCatch c)

tTuple :: Tuple -> T.Tuple
tTuple (Tuple ls) = T.Tuple (map tExpression ls)

tList :: List -> T.List
tList (ListL ls) = T.ListL (map tExpression ls)
tList (ListP ls e) = T.ListP (map tExpression ls) (tExpression e)

tBinary :: Binary -> T.Binary
tBinary (Binary ls) = T.Binary (map (NoAnn . tBitstring) ls)

tBitstring :: Bitstring -> T.Bitstring
tBitstring (Bitstring e es) = T.Bitstring (tExpression e) (map tExpression es)

tLet :: Let -> T.Let
tLet (Let vs e e1) = T.Let (tVariables vs) (tExpression e) (tExpression e1)

tVariables :: Variables -> T.Variables
tVariables (VariablesS v) = T.VariablesS $ NoAnn v
tVariables (VariablesM ls) = T.VariablesM $ map NoAnn ls

tCase :: Case -> T.Case
tCase (Case e cs) = T.Case (tExpression e) (map (NoAnn . tClause) cs)

tClause :: Clause -> T.Clause
tClause (Clause p g e) = T.Clause (tPatterns p) (tGuard g) (tExpression e)

tPatterns :: Patterns -> T.Patterns
tPatterns (PatternS ap) = T.PatternS (tAnnotatedPattern ap)
tPatterns (PatternM ls) = T.PatternM (map tAnnotatedPattern ls)

tGuard :: Guard -> T.Guard
tGuard (Guard e) = T.Guard $ tExpression e

tFun :: Fun -> T.Fun
tFun (Fun vs e) = T.Fun (map NoAnn vs) (tExpression e)

tLetrec :: Letrec -> T.Letrec
tLetrec (Letrec fs e) = T.Letrec (map tFunctionDefinition fs) (tExpression e)

tApplication :: Application -> T.Application
tApplication (Application e es) = T.Application (tExpression e) (map tExpression es)

tInterModuleCall :: InterModuleCall -> T.InterModuleCall
tInterModuleCall (InterModuleCall e e1 es) = T.InterModuleCall (tExpression e) (tExpression e1) (map tExpression es)

tPrimOpCall :: PrimOpCall -> T.PrimOpCall
tPrimOpCall (PrimOpCall a ls) = T.PrimOpCall (NoAnn a) (map tExpression ls)

tTry :: Try -> T.Try
tTry (Try e v e1 v1 e2) = T.Try (tExpression e) (tVariables v) (tExpression e1) (tVariables v1) (tExpression e2)

tReceive :: Receive -> T.Receive
tReceive (Receive cs t) = T.Receive (map (NoAnn . tClause) cs) (tTimeout t)

tTimeout :: Timeout -> T.Timeout
tTimeout (Timeout e e1) = T.Timeout (tExpression e) (tExpression e1)

tSequencing :: Sequencing -> T.Sequencing
tSequencing (Sequencing e e1) = T.Sequencing (tExpression e) (tExpression e1)

tCatch :: Catch -> T.Catch
tCatch (Catch e) = T.Catch (tExpression e)
