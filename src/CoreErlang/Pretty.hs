{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module CoreErlang.Pretty where

import Data.Functor.Foldable
import Data.Text (Text)
import Text.DocLayout
import CoreErlang.Type
import Utils

instance Pretty Atom where
  pretty (Atom s) = quotes (text s)

instance Pretty VariableName where
  pretty (VariableName v) = text v

instance (Pretty a) => Pretty (Ann a) where
  pretty (NoAnn a) = pretty a
  pretty (Ann a cs) = parens (pretty a <> " -| " <> brackets (mSepD $ map pretty cs))

instance Pretty Module where
  pretty (Module a mh mb) = "module" <> space <> pretty a <> space <> nest 4 (pretty mh) <> cr <> pretty mb <> cr <> "end"

instance Pretty ModuleHeader where
  pretty (ModuleHeader es as) = pretty es <> cr <> pretty as

instance Pretty Exports where
  pretty (Exports fns) = brackets (mSepDCr $ map pretty fns)

instance Pretty FunctionName where
  pretty (FunctionName a i) = pretty a <> "/" <> text (show i)

instance Pretty Attributes where
  pretty (Attributes mas) = "attributes" <> space <> brackets (mSepDCr $ map pretty mas)

instance Pretty ModuleAttribute where
  pretty (ModuleAttribute a c) = pretty a <> " = " <> cr <> nest 4 (pretty c)

instance Pretty ModuleBody where
  pretty (ModuleBody fds) = mManyCr $ map pretty fds

instance Pretty FunctionDefinition where
  pretty (FunctionDefinition an af) = pretty an <> " = " <> cr <> nest 4 (pretty af)

instance Pretty Constant where
  pretty = cata go
    where
      go (ConstantAtomicLiteralF a) = pretty a
      go (ConstantTF cs) = braces (mSepD cs)
      go (ConstantLF cs) = brackets (mSepD cs)
      go (ConstantPF cs c) = brackets (mSepD cs <> "|" <> c)

instance Pretty AtomicLiteral where
  pretty (LInteger i) = text $ show i
  pretty (LFloat d) = text $ show d
  pretty (LAtom a) = pretty a
  pretty LNil = brackets empty
  pretty (LChar c) = char c
  pretty (LString s) = text s

instance Pretty AnnotatedPattern where
  pretty (AnnotatedPatternVariable av) = pretty av
  pretty (AnnotatedPatternPattern ap) = pretty ap

instance Pretty Pattern where
  pretty (PatternAtomicLiteral al) = pretty al
  pretty (PatternT aps) = braces (mSepD $ map pretty aps)
  pretty (PatternL aps) = brackets (mSepD $ map pretty aps)
  pretty (PatternP aps ap) = brackets (mSepD (map pretty aps) <> " | " <> pretty ap)
  pretty (PatternMap m) = pretty m
  pretty (PatternBitstringPattern bps) = inside "#{" "}#" (mSepD (map pretty bps))
  pretty (PatternAlias av ap) = pretty av <> "=" <> pretty ap

instance Pretty BitstringPattern where
  pretty (BitstringPattern ap es) = inside "#<" ">" (pretty ap) <> parens (mSepD $ map pretty es)

instance Pretty Expression where
  pretty (ExpressionValueList av) = pretty av
  pretty (ExpressionSingleExpression ase) = pretty ase

instance Pretty ValueList where
  pretty (ValueList vls) = inside "<" ">" (mSepD $ map pretty vls)

instance Pretty SingleExpression where
  pretty (SEAtomicLiteral a) = pretty a
  pretty (SEVariableName a) = pretty a
  pretty (SEFunctionName a) = pretty a
  pretty (SETuple a) = pretty a
  pretty (SEList a) = pretty a
  pretty (SEMap a) = pretty a
  pretty (SEBinary a) = pretty a
  pretty (SELet a) = pretty a
  pretty (SECase a) = pretty a
  pretty (SEFun a) = pretty a
  pretty (SELetrec a) = pretty a
  pretty (SEApplication a) = pretty a
  pretty (SEInterModuleCall a) = pretty a
  pretty (SEPrimOpCall a) = pretty a
  pretty (SETry a) = pretty a
  pretty (SEReceive a) = pretty a
  pretty (SESequencing a) = pretty a
  pretty (SECatch a) = pretty a

instance Pretty Tuple where
  pretty (Tuple es) = inside "{" "}" (mSepD $ map pretty es)

instance Pretty List where
  pretty (ListL es) = brackets (mSepD $ map pretty es)
  pretty (ListP es e) = brackets (mSepD (map pretty es) <> " | " <> pretty e)

instance Pretty MMap where
  pretty (InsertM e e1) = pretty e <> " => " <> pretty e1
  pretty (UpdateM e e1) = pretty e <> " := " <> pretty e1

instance Pretty Map where
  pretty (Map mms) = inside "~{" "}~" (mSepD $ map pretty mms)
  pretty (MapP mms e) = inside "~{" "}~" (mSepD (map pretty mms) <> " | " <> pretty e)


instance Pretty PMMap where
  pretty (PMMap ap ap1) = pretty ap <> " := " <> pretty ap1

instance Pretty PMap where
  pretty (PMap mms) = inside "~{" "}~" (mSepD $ map pretty mms)
  pretty (PMapP mms e) = inside "~{" "}~" (mSepD (map pretty mms) <> " | " <> pretty e)

instance Pretty Binary where
  pretty (Binary bs) = inside "#{" "}#" (mSepD $ map pretty bs)

instance Pretty Bitstring where
  pretty (Bitstring e es) = inside "#<" ">" (pretty e) <> parens (mSepD $ map pretty es)

instance Pretty Let where
  pretty (Let v e e1) = "let " <> pretty v <> " = " <> pretty e <> cr <> " in " <> pretty e1

instance Pretty Variables where
  pretty (VariablesS av) = pretty av
  pretty (VariablesM avs) = inside "<" ">" (mSepD $ map pretty avs)

instance Pretty Case where
  pretty (Case e acs) = cr <> "case " <> pretty e <> " of " <> cr <> nest 4 (mManyCr (map pretty acs)) <> cr <> "end" <> cr

instance Pretty Clause where
  pretty (Clause p g e) = pretty p <> cr <> pretty g <> " -> " <> cr <> nest 4 (pretty e)

instance Pretty Patterns where
  pretty (PatternS ap) = pretty ap
  pretty (PatternM aps) = inside "<" ">" (mSepD $ map pretty aps)

instance Pretty Guard where
  pretty (Guard e) = nest 4 ("when " <> pretty e)

instance Pretty Fun where
  pretty (Fun avs e) = "fun " <> parens (mSepD $ map pretty avs) <> " -> " <> cr <> nest 4 (pretty e)
  pretty (ExtFun a fn) = "fun " <> pretty a <> " : " <> pretty fn
instance Pretty Letrec where
  pretty (Letrec fds e) = "letrec " <> nest 4 (mManyCr (map pretty fds)) <> cr <> "in " <> pretty e

instance Pretty Application where
  pretty (Application e es) = "apply " <> pretty e <> parens (mSepD $ map pretty es)

instance Pretty InterModuleCall where
  pretty (InterModuleCall e e1 es) = "call " <> pretty e <> ":" <> pretty e1 <> space <> parens (mSepD $ map pretty es)

instance Pretty PrimOpCall where
  pretty (PrimOpCall a es) = "primop " <> pretty a <> space <> parens (mSepD $ map pretty es)

instance Pretty Try where
  pretty (Try e v e1 v1 e2) = "try " <> pretty e <> " of " <> pretty v <> " -> " <> pretty e1 <> cr <> "catch " <> pretty v1 <> " -> " <> pretty e2

instance Pretty Receive where
  pretty (Receive acs t) = "receive " <> nest 4 (mManyCr $ map pretty acs) <> cr <> nest 4 (pretty t)

instance Pretty Timeout where
  pretty (Timeout e e1) = "after " <> pretty e <> " -> " <> pretty e1

instance Pretty Sequencing where
  pretty (Sequencing e e1) = "do" <> cr <> nest 4 (pretty e) <> cr <> nest 4 (pretty e1) <> cr

instance Pretty Catch where
  pretty (Catch e) = "catch " <> pretty e

