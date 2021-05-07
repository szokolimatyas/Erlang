module Erlang.T where

import Erlang.A
import Erlang.B

t :: IO ()
t = do
  con <- readFile "./test/data/jsx/jsx_encoder.erl"
  print $ length con
  print $ alexScanTokens con
  -- print $ runCalc con


