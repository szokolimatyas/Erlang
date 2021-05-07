{-# LANGUAGE TypeApplications #-}

module Main (main) where

import Control.Monad (forM, forM_, when)
import CoreErlang.A
import CoreErlang.B
import CoreErlang.Pretty
import qualified Erlang.A as E
import qualified Erlang.B as E
import qualified Erlang.Pretty as E
import System.Directory
import System.FilePath.Posix
import Text.DocLayout
import Utils

main :: IO ()
main = do
  -- coreErlangTest
  erlangTest

mfindFiles :: String -> FilePath -> IO [FilePath]
mfindFiles pa baseFp = do
  list <- listDirectory baseFp
  v <- forM list $ \fp -> do
    let newFp = baseFp </> fp
    isDir <- doesDirectoryExist newFp
    if isDir
      then mfindFiles pa newFp
      else do
        if take (length pa) (reverse fp) == reverse pa
          then return [newFp]
          else return []
  return $ concat v

findCoreFile :: FilePath -> IO [FilePath]
findCoreFile = mfindFiles ".core"

findErlangFile :: FilePath -> IO [FilePath]
findErlangFile = mfindFiles ".P"

coreErlangTest :: IO ()
coreErlangTest = do
  fs <- findCoreFile "./test/data"
  print fs
  forM_ fs $ \fp -> do
    print $ "start: " ++ fp
    fileCon <- readFile fp
    let r = render @String (Just 150) (pretty $ runCalc fileCon)
    writeFile ("./test/generate" </> drop 2 fp) r
    print $ "finish: " ++ fp

erlangTest :: IO ()
erlangTest = do
  fs <- findErlangFile "./test/data"
  print fs
  forM_ fs $ \fp -> do
    print $ "start: " ++ fp
    con <- readFile fp
    -- let r = render @String (Just 150) $ pretty $ getResult $ E.runCalc con
    let r = render @String Nothing $ pretty $ getResult $ E.runCalc con
    writeFile (reverse (drop 2 $ reverse ("./test/generate" </> drop 2 fp)) <> ".erl") r
    print $ "finish:            " ++ fp

getResult :: E.E a -> a
getResult (E.OK a) = a
getResult (E.Failed a) = error a
