from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.PREnc import PREnc
from charm.toolbox.hash_module import Hash, int2Bytes, integer
import time

debug = False

class CLCSE():
   
    def __init__(self, groupObj, verbose=False):
        self.group = groupObj
        self.util = SecretUtil(self.group, verbose)

    
        
    def Setup(self):
        P1, P2 = self.group.random(G1), self.group.random(G2)
        s = self.group.random(ZR)
        P_pub = P1 ** s
        H1 = lambda data, string_ID: self.group.hash((data, string_ID), ZR)
        H2 = lambda string: self.group.hash(string, ZR)
        H3 = lambda data1, data2, data3: self.group.hash((data1, data2, data3), ZR)
        H4 = lambda gdata: self.group.hash((gdata, 1), ZR)
        
        PP = {'P1': P1, 'P_pub': P_pub, 'H1': H1, 'H2': H2, 'H3': H3,'H4': H4}
        params2= {'P2': P2}
        msk = {'s': s}

        return PP,params2,msk
    
     
     
    def KeyGen1(self, PP, msk):
        r_o = self.group.random(ZR)
        d_o = self.group.random(ZR)
        T_o = PP['P1'] ** r_o
        input_string_ID= "0101010101"
        input_data = T_o 
        eta_o = PP['H1'](input_data, input_string_ID)
        u_o = r_o + msk['s'] * eta_o
        PPK_o = PP['P1'] ** d_o
        PK_o = {'T_o': T_o, 'PPK_o': PPK_o, 'eta_o': eta_o}
        SK_o = {'u_o': u_o, 'd_o': d_o}


        return PK_o,SK_o 

     
     
    def KeyGen2(self, params2):
        d=10
        public_keys = []
        for i in range (d):
            d_r = self.group.random(ZR) 
        
            PK_j = params2['P2']**d_r
            SK_j = d_r
            public_keys.append(PK_j)
        return PK_j, SK_j, public_keys
     
     
     
    def Encryption(self, PP, params2, PK_o, SK_o, attr1_list, attrm_list):

       
        r_1= self.group.random(ZR)
        k = (r_1)*(SK_o['d_o'] + SK_o['u_o']) 
        Temp1 = 0
        Hw = 0
        
        for  i  in   range(len(attr1_list)):
            
            Hwa = PP['H2'](str(i))
            Temp1 = Hwa 
            Hw += Temp1
           
        input1_data = PK_o ['T_o']
        input2_data = PK_o ['PPK_o']
        gdata = self.group.random(G1)
        fx_i = PP['H4'](gdata) 
        for  i in range(100):
            fx_i = PP['H4'](fx_i)
            attrm_list.append(fx_i)
            
        h_w= PP['H3'](input1_data, input2_data, Hw)
        D_p=  fx_i   
       
        C1 = params2['P2']**(k*(h_w+D_p))
        C2 = params2['P2'] ** r_1
        C3 = PP['P1'] ** (r_1*(h_w+D_p))
       
        Cw = { 'C1': C1, 'C2': C2, 'C3': C3, 'D_p': D_p}
        
        return Cw



    def Trapdoor(self, Cw, PP, PK_o, SK_j, attr2_list):
        
        r_2= self.group.random(ZR)
        
        Temp2 = 0
        Hw_u = 0

        for  j in range(len(attr2_list)): 
            
            Hwb = PP['H2'](str(j))
            Temp2 = Hwb 
            Hw_u += Temp2

        h_wu= PP['H3'](PK_o['T_o'], PK_o ['PPK_o'], Hw_u) 
        W = PK_o['PPK_o'] * PK_o['T_o'] * (PP['P_pub']** PK_o['eta_o'])   # w
        
        T1 = PP['P1'] ** SK_j * (W ** r_2) *  (Cw['D_p'] + h_wu) 
        T2 = PP['P1'] ** r_2
        Tw = {'T1': T1, 'T2': T2}
        return Tw
    


    def Test(self, Tw, Cw, PK_j):
        
        TEST1 = pair(Tw['T1'],  Cw['C2']) 
        TEST2 = pair(Cw['C3'],  PK_j) * pair(Tw['T2'],  Cw['C1']) 
        return TEST1,TEST2
 
    def FileInsert(self, PP, params2, PK_o, SK_o, attr1_list, attrm_list):

       
        r_1= self.group.random(ZR)
        k = (r_1)*(SK_o['d_o'] + SK_o['u_o']) 
        Temp1 = 0
        Hw = 0
        
        for  i  in   range(len(attr1_list)):
            
            Hwa = PP['H2'](str(i))
            Temp1 = Hwa 
            Hw += Temp1
           
        input1_data = PK_o ['T_o']
        input2_data = PK_o ['PPK_o']
        gdata = self.group.random(G1)
        fx_i = PP['H4'](gdata)
        t = 5
        if t <= 0 or t > len(attrm_list):
            return None
        fx_prim = attrm_list[-t]
            
        h_w= PP['H3'](input1_data, input2_data, Hw)
        D_p=  fx_prim   
        C1_prime = params2['P2']**(k*(h_w+D_p))
        C2_prime = params2['P2'] ** r_1
        C3_prime = PP['P1'] ** (r_1*(h_w+D_p))
       
        Cw_prime = { 'C1_prime':C1_prime, 'C2_prime': C2_prime, 'C3_prime': C3_prime, 'D_p': D_p}
        
        return Cw_prime
    
          
# 创建 CLCSE 实例并获取参数
group = PairingGroup('MNT224')
clcse = CLCSE(group)
attr1_list = ['0', '1', '2', '3', '4', '5']
attr2_list = ['0', '1', '2', '3', '4', '5']
attrm_list = []

PP, params2, msk = clcse.Setup()
PK_o, SK_o = clcse.KeyGen1(PP, msk)
PK_j, SK_j, public_keys = clcse.KeyGen2(params2)
Cw = clcse.Encryption(PP, params2, PK_o, SK_o, attr1_list, attrm_list)
Tw = clcse.Trapdoor(Cw, PP, PK_o, SK_j, attr2_list)
PK_o, SK_o = clcse.KeyGen1(PP, msk)
PK_j, SK_j, public_keys = clcse.KeyGen2(params2)
(TEST1,TEST2) = clcse.Test(Tw, Cw, PK_j) 
Cw_prime = clcse.FileInsert(PP, params2, PK_o, SK_o, attr1_list, attrm_list)


