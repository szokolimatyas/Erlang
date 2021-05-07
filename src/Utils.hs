{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}

module Utils where

import Data.Text (Text)
import Text.DocLayout


insertFun :: Doc a -> Doc a -> Doc a -> Doc a
insertFun c x y
  | isEmpty x = y
  | isEmpty y = x
  | otherwise = x <> c <> y

mSep :: Doc a -> [Doc a] -> Doc a
mSep d = foldr (insertFun d) empty

mSepD :: HasChars a => [Doc a] -> Doc a
mSepD = mSep ", "

mSepDCr :: HasChars a => [Doc a] -> Doc a
mSepDCr = mSep ("," <> cr)

mMany :: [Doc a] -> Doc a
mMany = mSep space

mManyCr :: [Doc a] -> Doc a
mManyCr = mSep blankline

t1 :: HasChars a => [Doc a]
t1 = ["aaa", "aaa", "aaa"]

bracesWithCr :: HasChars a => Doc a -> Doc a
bracesWithCr = inside (char '{') (cr <> char '}')

bracketsWithCr :: HasChars a => Doc a -> Doc a
bracketsWithCr = inside (char '[') (cr <> char ']')

parensWithCr :: HasChars a => Doc a -> Doc a
parensWithCr = inside (char '(') (cr <> char ')')

class Pretty v where
  pretty :: HasChars a => v -> Doc a

