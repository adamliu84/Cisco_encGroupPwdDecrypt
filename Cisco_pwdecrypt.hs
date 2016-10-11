-- Haskell script on DES3 decrypt for cisco VPN enc_GroupPwd
-- Taking reference from: https://github.com/axcheron/cisco_pwdecrypt/blob/master/cisco_pwdecrypt.py

{-# LANGUAGE PackageImports #-}
import qualified Data.ByteString.Char8 as C8
import Data.ByteString.Base16 (decode)
import Data.ByteString.Lazy (toStrict, fromStrict)
import Data.Digest.Pure.SHA (bytestringDigest, sha1)
import Data.Char as C (isAlphaNum, isPunctuation)
import Crypto.Cipher (makeKey, makeIV, cipherInit, DES_EDE3, cbcDecrypt)
import Numeric (readHex)
import Data.Bits (xor)
import Data.Char (chr)

-- Testing crypted string with pure key reveal for enc_GroupPwd
encsample1 = "9196FE0075E359E6A2486905A1EFAE9A11D652B2C588EF3FBA15574237302B74C194EC7D0DD16645CB534D94CE85FEC4" --letmein
encsample2 = "A39CADD77ED72A9C75467D0F5A5C88BFCD75370DD63E3388D3F402AF50C4E5029071B0965C343B99B6D6636A8698562DDB2EE51020D87EA3" --HelloWorld
encsample3 = "886E2FC74BFCD8B6FAF47784C386A50D0C1A5D0528D1E682B7EBAB6B2E91E792E389914767193F9114FA26C1E192034754F85FC97ED36509" --Th!sIsMyK3y#
enclist = [encsample1, encsample2, encsample3]

takeRightkey :: Show a => Either a b -> b
takeRightkey (Left y) = error $ show y
takeRightkey (Right x) = x

decryptCiscoGroupPassword :: String -> String
decryptCiscoGroupPassword encrypttext = let bin_str = C8.group.fst.decode.C8.pack $ encrypttext 
                                            ht = Prelude.take 20 bin_str
                                            enc = Prelude.drop 40 bin_str
                                            iv = bin_str
                                            
                                            ht1 = (Prelude.take 19 ht) ++ [C8.singleton.succ.C8.maximum $ ht !! 19] ++ (Prelude.drop 20 ht)                                                    
                                            h2  = shadigest ht1
                                            
                                            ht2 = (Prelude.take 19 ht1) ++ [C8.singleton.succ.succ.C8.maximum $ ht1 !! 19] ++ (Prelude.drop 20 ht1)                                            
                                            h3  = shadigest ht2
                                            
                                            keyString = h2 ++ (Prelude.take 4 h3)
                                            
                                            -- http://stackoverflow.com/questions/19509175/how-to-aes-ecb-mode-encrypt-using-cryptocipher  
                                            key = takeRightkey $ makeKey.C8.concat $ keyString
                                            ivv = maybe (error "invalid IV") id $ makeIV $ C8.concat.Prelude.take 8 $ iv
                                            desede3 = cipherInit key :: DES_EDE3
                                            ctext = cbcDecrypt desede3 ivv (C8.concat enc)
                                        in C8.unpack $ C8.takeWhile (\x-> isAlphaNum x || isPunctuation x) ctext
                                        where shadigest = C8.group.toStrict.bytestringDigest.sha1.fromStrict.C8.concat

-- Testing crypted string with pure key reveal for Type 7
type7sample1 = "046E1803362E595C260E0B240619050A2D" --UseYourOwnString
type7sample2 = "01270E454822152238671D105A" --Th!sIsMyK3y#
type7list = [type7sample1, type7sample2]
    
xlat :: [Int]    
xlat = [0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,  0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53, 0x55, 0x42]

getxlat :: Int -> Int -> String -> Char
getxlat x y z = let a = xlat !! (x + y)
                    b = fst $ (readHex(z)!!0)                    
                    char = chr $ (xor a b)
                in char
                                        
pairBy2 :: String -> [String]
pairBy2 (x:y:zz) = [x:[y]] ++ pairBy2 zz
pairBy2 [] = []
                         
decryptCiscoType7Password :: String -> String                         
decryptCiscoType7Password x = let   index = read(take 2 x)::Int
                                    enc_pwd = drop 2 x
                                    pwd_hex = pairBy2 enc_pwd        
                                    zpwd_hex = zip [0,1..] pwd_hex
                                    cleartext = map (\(x,y) -> getxlat index x y) zpwd_hex
                              in cleartext                   

main = do
        print "enc_GroupPwd"
        mapM_ (putStrLn.decryptCiscoGroupPassword) enclist
        print "Type 7"
        mapM_ (putStrLn.decryptCiscoType7Password) type7list