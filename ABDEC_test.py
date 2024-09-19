from Crypto.Util.Padding import pad, unpad
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.hash_module import Hash, int2Bytes, integer
import math
from ABDEC import ABDEC
import time

def main():
    d = 10
    trial = 50
    Test_PKISetup = True
    Test_KeyGen = True
    Test_Encrypt = True
    Test_Decrypt = True
    Test_ReEncryption = True

    group = PairingGroup('SS512')
    
    abdec = ABDEC(group)

    
    attr_list = ['', '', '', '']
    h1 = lambda x: group.hash((x, 1), ZR)
    params = abdec.PKISetup(attr_list)
    if Test_PKISetup:
        d=10      
        NN = 50
        print ("PKISetup Bench")
        f = open('PKISetup.txt', 'w+')
        while d <= NN:
            print(d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(d):
                attr_list.append(str(params['h1'](str(i))))
            for i in range(trial):
                start = time.time()
                params = abdec.PKISetup(attr_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n") 
            d += 10
        f.close()
        
      
        
    ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
    if Test_KeyGen:
        d=10      
        NN = 50
        print ("KeyGen Bench")
        f = open('Keygen.txt', 'w+')
        while d <= NN:
            print(d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(d):
                attr_list.append(str(params['h1'](str(i))))
            for i in range(trial):
                start = time.time()
                ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n") 
            d += 10
        f.close()              


    
    ck = group.random(GT)
    print('original_ck: ', ck)
    
    policy_str = '( 537652053081268538405298426501177745558478376277 and 665532480585348179794866828126495254730776514361 ) OR ( 9160528266715565656600774122297260167147113869 and 603517283893112572826815108813007875548551170107 )'
    ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)

    if Test_Encrypt:
        d=10     
        NN = 50
        print ("Encrypt Bench")
        f = open('Encrypt.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            policy_str = ''
            for i in range(2*d+1):
                attr_list.append(str(params['h1'](str(i))))
            ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+ str(params['h1'](str(2*j))) + " and "+ str(params['h1'](str(2*j+1))) +" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(params['h1'](str(2*j))) + " and " + str(params['h1'](str(2*j+1))) + " )"
            
            for i in range(trial):
                start = time.time()
                (CF ,s) = abdec.Encryption(params, ck, PK, policy_str,  O)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    Z =  abdec.PreDe( CF, params, ak)
    (decrypted_message) = abdec.Decryption(CF, params, ak, du, Z)

    if Test_Decrypt:
        d=10     
        NN = 50
        print ("Decrypt Bench")
        f = open('decrypt.txt', 'w+')
        while d < NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            for i in range(2*d+1):
                attr_list.append(str(params['h1'](str(i))))
            ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
            policy_str=""
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+ str(params['h1'](str(2*j))) + " and "+ str(params['h1'](str(2*j+1))) +" )" + " OR "
                else:
                    policy_str = policy_str + "( "+ str(params['h1'](str(2*j))) + " and "+ str(params['h1'](str(2*j+1))) +" )"
            
            
            (CF ,s) = abdec.Encryption(params, ck, PK,  policy_str,  O)
            for i in range(trial):
                start = time.time()
                (decrypted_message) = abdec.Decryption(CF, params, ak, du, Z)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()
    Z =  abdec.PreDe( CF, params, ak)
    (decrypted_message) = abdec.Decryption(CF, params, ak, du, Z)
    print('decrypted_ck: ', decrypted_message)        
        
        
    policy_str = '( 537652053081268538405298426501177745558478376277 and 665532480585348179794866828126495254730776514361 ) OR ( 9160528266715565656600774122297260167147113869 and 603517283893112572826815108813007875548551170107 )'
    ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
    if Test_ReEncryption:
        d=10     
        NN = 50
        print ("ReEncryption Bench")
        f = open('ReEncryption.txt', 'w+')
        while d <= NN:
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            attr_list = []
            policy_str = ''
            for i in range(2*d+1):
                attr_list.append(str(params['h1'](str(i))))
            ( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
            for j in range(d):
                if j!=d-1:
                    policy_str = policy_str + "( "+ str(params['h1'](str(2*j))) + " and "+ str(params['h1'](str(2*j+1))) +" )" + " OR "
                else:
                    policy_str = policy_str + "( " + str(params['h1'](str(2*j))) + " and " + str(params['h1'](str(2*j+1))) + " )"
            (CF ,s) = abdec.Encryption(params, ck, PK, policy_str,  O)
            for i in range(trial):
                start = time.time()
                (CF_prim) = abdec.ReEncryption(params, policy_str, PK)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial
            f.write(str(T) + ")\n")
            d += 10
        f.close()


if __name__ == "__main__":
    debug = True
    main()

