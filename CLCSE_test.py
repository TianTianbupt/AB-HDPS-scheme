from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from CLCSEFinally import CLCSE
import time

def main():
    trial = 100
    attr1_list = []
    attr2_list = []
    attrm_list = []
    Test_KeyGen1 = True
    Test_KeyGen2 = True
    Test_Encryption = True
    Test_Trapdoor = True
    Test_Test = True
    # instantiate a bilinear pairing map
    group = PairingGroup('SS512')
    
    clcse = CLCSE(group)
    PP, params2, msk = clcse.Setup()
    PK_o, SK_o = clcse.KeyGen1(PP, msk)
    PK_j, SK_j = clcse.KeyGen2(params2)
    Cw = clcse.Encryption(PP, params2, PK_o, SK_o, attr1_list, attrm_list)
    Tw = clcse.Trapdoor(Cw, PP, PK_o, SK_j, attr2_list)


    if Test_KeyGen1:
            d=10      
            NN = 50
            print ("KeyGen1 Bench")
            f = open('KeyGen1.txt', 'w+')
            while d <= NN:
                print(d)
                f.write("(" + str(d) + ",")
                T = 0
                Temp = 0
                start = 0
                end = 0
                 
                for i in range(trial):
                    start = time.time()
                    PK_o, SK_o = clcse.KeyGen1(PP, msk)
                    end = time.time()
                    Temp = end - start
                    T += Temp
                T = T / trial  
                
                f.write(str(T) + ")\n")
                d += 10
            f.close()



    if Test_KeyGen2:
            d=10      
            NN = 50
            print ("KeyGen2 Bench")
            f = open('KeyGen2.txt', 'w+')
            while d <= NN:
                print(d)
                f.write("(" + str(d) + ",")
                T = 0
                Temp = 0
                start = 0
                end = 0
                 
                for i in range(trial):
                    start = time.time()
                    PK_j, SK_j = clcse.KeyGen2(params2)
                    end = time.time()
                    Temp = end - start
                    T += Temp
                T = T / trial  
                
                f.write(str(T) + ")\n")
                d += 10
            f.close()



    if Test_Encryption:
        d = 10     
        NN = 50
        print ("Encryption Bench")
        f = open('keyword_Encryption.txt', 'w+')
        while d <= NN:
            print(d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            
            for i in range(d):
                attr1_list.append(str(i))
            for i in range(trial): 
                start = time.time()
                Cw = clcse.Encryption(PP, params2, PK_o, SK_o, attr1_list, attrm_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial  
            print ('W', attr1_list)
            f.write(str(T) + ")\n")
            d += 10
            attr1_list = []
        f.close()



    if Test_Trapdoor:
        d = 10     
        NN = 50 
        print ("Trapdoor Bench")
        f = open('Trapdoor.txt', 'w+')
        while d <= NN:
            print(d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            
            for j in range(d):
                attr2_list.append(str(j))
            for j in range(trial): 
                start = time.time()
                Tw = clcse.Trapdoor(Cw, PP, PK_o, SK_j, attr2_list)
                end = time.time()
                Temp = end - start
                T += Temp
            T = T / trial  
            print ('WU', attr2_list)
            f.write(str(T) + ")\n")
            d += 10
            attr2_list = []
        f.close()



    if Test_Test:
        d = 10     
        NN = 50   
        print ("Test Bench")
        f = open('keyword_Match.txt', 'w+')
        while d <= NN:
            print(d)
            f.write("(" + str(d) + ",")
            T = 0
            Temp = 0
            start = 0
            end = 0
            
            for i in range(d):
                attr1_list.append(str(i))
                attr2_list.append(str(i))  
            for j in range(trial):
                Cw = clcse.Encryption(PP, params2, PK_o, SK_o, attr1_list, attrm_list)
                Tw = clcse.Trapdoor(Cw, PP, PK_o, SK_j, attr2_list)
                (TEST1,TEST2) = clcse.Test(Tw, Cw, PK_j) 
    
                start = time.time()
                (TEST1,TEST2) = clcse.Test(Tw, Cw, PK_j) 
                end = time.time()
                Temp = end - start
                T += Temp    
            T = T / trial  
            print ('W', attr1_list)
            print ('WU', attr2_list)
            f.write(str(T) + ")\n")
            if TEST1 == TEST2:
                    print("Success")      
            else:
                    print("Fail")
            d += 10
            attr1_list = []
            attr2_list = []
        f.close()
    


if __name__ == "__main__":
    debug = True
    main()
