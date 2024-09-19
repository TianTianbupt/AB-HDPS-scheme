from Crypto.Util.Padding import pad, unpad
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.hash_module import Hash, int2Bytes, integer
import math

debug = False


class ABDEC():
    def __init__(self, group, verbose=False):
        self.group = group
        self.util = SecretUtil(group, verbose)
    
    
    def PKISetup(self, attr_list):
        g = self.group.random(G1)
        egg = pair(g, g)
        h1 = lambda x: self.group.hash((x, 1), ZR)
        h2 = lambda data: self.group.hash((data, 1), G1)
        params = {'g': g, 'h1': h1, 'h2': h2,  'egg': egg}
        
        
        if debug:
            print("PKISetup")
            print(params)
        return params
    
    
    
    def KeyGen(self, params,  attr_list):
       
        
        PK_2 = 1
        alpha = 0
        for  i  in   range(len(attr_list)):
            alpha_i = self.group.random(ZR) 
            alpha += alpha_i
            PK_2i = params['g'] ** alpha_i
            PK_2 *= PK_2i 
        PK_2test = params['g'] ** alpha 
            
        PK_1 = 1
        gamma = 0
        beta = 0
        D_1 = 1
        D_2 = 1
        for  i  in   range(len(attr_list)):
            beta_i = self.group.random(ZR)
            gamma_i = self.group.random(ZR)
            PK_1i = params['egg'] ** beta_i
            D_i1 = (params['g'] ** beta_i) * ((params['g'] *alpha) ** gamma_i)
            #D_i1 = (params['g'] ** beta_i) * (PK_2 ** gamma_i)
            D_i2 = params['g'] **  gamma_i
            gamma += gamma_i
            beta += beta_i
            PK_1 *= PK_1i 
            D_1 *= D_i1 
            D_2 *= D_i2           
        
        """
        The following   calculation can be calculated offline.
        """
        d = 4
        O = {}
        for  attr  in   attr_list:
            A_i = self.group.random(ZR)
            R_il =PK_1 ** A_i
            R_i1 = params['g'] ** A_i
            for  l  in   range(d):
                temp = R_il
                R_il= pair(R_i1,params['h2'](temp))
            O[attr] = params['h2'](R_il) 
        
        D = {}
        du = self.group.random(ZR)  
        D2 =  D_2 ** du
        for attr in attr_list:
            if attr in O:  
                
                D_i = ((params['g']**(params['h1'](attr))) * O[attr])
                D_attr = D_i ** (gamma * du)
                D[attr] = D_attr
            else:

                print(f"Warning: {attr} not found in O")       
           
               
        ak = {'attr_list': attr_list,  'D_1': D_1, 'D2': D2, 'D_attr': D_attr, 'D': D}
        PK = {'PK_1':PK_1, 'PK_2':PK_2}  
        return O, ak, PK,  du
    
    
    
    def Encryption(self, params, ck, PK,  policy_str, O):
        """
        Encrypt symmetric key under an access policy
        :return the encrypted message
        """
        s = self.group.random(ZR) 
        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)
        secret_shares = self.util.calculateSharesDict(s, policy)        
            
        C =  ck * (PK['PK_1'] ** (s))
        
        C0 = params['g'] ** (s ) 
        C1, C2, C3 = {}, {}, {}
        for attr in attribute_list:
            r_i = self.group.random(ZR)
            if attr in O:
                C1[attr] = (PK['PK_2'] ** secret_shares[attr]) * (params['g'] **(params['h1'](attr) * (-r_i)) )
                C2[attr] = params['g'] ** (r_i) 
                C3[attr] = O[attr] ** (-r_i) 
            else:
                print(f"Warning: Attribute {attr} not found in O")
            
           
        CF = {'policy': policy_str, 'C': C,  'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3}
        
        return CF, s   
    
        

    def PreDe(self, CF, params, ak):
        """Decrypt the ciphertext using the secret keys of user"""
        
        
        policy = self.util.createPolicy(CF['policy'])
        coefficients = self.util.getCoefficients(policy)
        pruned_list = self.util.prune(policy, ak['attr_list'])
        

        if not pruned_list:
            print ("Policy not satisfied")
            return None
        
        Z = self.group.init(GT, 1) 

        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()
            y = pruned_list[i].getAttributeAndIndex()
            Z *= (pair(CF['C1'][x] * CF['C3'][x] , ak['D2']) * pair(CF['C2'][x], ak['D'][x]) ) ** coefficients[y]
        
        
        return   Z
    
    
    
    def Decryption(self, CF, params, ak, du, Z):
        """Decrypt the ciphertext using the secret keys of user"""
        
        du_inv = du ** -1 
        decrypted_message = ((CF['C'] ) * ( Z ** (du_inv )) )/ (pair(CF['C0'], ak['D_1']) )
        
        return   decrypted_message  
    
    
        
    def ReEncryption(self, params, policy_str, PK):
        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)
        d_prim = 5
        O_prim, C3_prim = {}, {}
        
        for attr in attribute_list:
            A_prim_i = self.group.random(ZR)
            R_prim_il =PK['PK_1'] ** A_prim_i
            R_prim_i1 = params['g'] ** A_prim_i
            for  l  in   range(d_prim):
                temp = R_prim_il
                R_prim_il= pair(R_prim_i1,params['h2'](temp))
            O_prim[attr] = params['h2'](R_prim_il)     
            r_i1 = self.group.random(ZR)
            r_i2 = self.group.random(ZR)
            C3_prim[attr] = O_prim[attr] ** (-r_i1 * r_i2) 
        CF_prim = {'policy': policy_str, 'C3_prim': C3_prim}
    
        return CF_prim
    
    
group = PairingGroup('SS512')
abdec = ABDEC(group)
ck = group.random(GT)
print("ck", ck)
attr_list = ['537652053081268538405298426501177745558478376277', '665532480585348179794866828126495254730776514361', '9160528266715565656600774122297260167147113869', '603517283893112572826815108813007875548551170107', '668350290265321042803037432266561185836542120498', '499218126776459930021938577749114426591885184914', '172086221441326730379452840842101510678583143454', '470764948916168309649157180652239485461664787344', '542772832184318343088263244387979624992886839645', '697205962249594416625055542969162214613419607102', '565974517647420453368905061627512532336238475181', '701830408555514787175769974511858533358358464406', '25379015043070720380478498225622379682721976203', '455423283850879051450868763953896457127681271817', '491803532074114660566658475625403394668799325283', '627377649545009942203089014321250292378592929129', '231540328458082392486953926763079311916287804245', '542779649111441660287597935758185612788037642940', '448942095092964262434492324876166300579956931385', '459017303243869235046626918419983809325629731930', '442638234306209015291241431281375550369627781426']
params = abdec.PKISetup(attr_list)
( O, ak, PK,  du) = abdec.KeyGen(params, attr_list)
policy_str = '( 537652053081268538405298426501177745558478376277 and 665532480585348179794866828126495254730776514361 ) OR ( 9160528266715565656600774122297260167147113869 and 603517283893112572826815108813007875548551170107 ) OR ( 668350290265321042803037432266561185836542120498 and 499218126776459930021938577749114426591885184914 ) OR ( 172086221441326730379452840842101510678583143454 and 470764948916168309649157180652239485461664787344 ) OR ( 542772832184318343088263244387979624992886839645 and 697205962249594416625055542969162214613419607102 ) OR ( 565974517647420453368905061627512532336238475181 and 701830408555514787175769974511858533358358464406 ) OR ( 25379015043070720380478498225622379682721976203 and 455423283850879051450868763953896457127681271817 ) OR ( 491803532074114660566658475625403394668799325283 and 627377649545009942203089014321250292378592929129 ) OR ( 231540328458082392486953926763079311916287804245 and 542779649111441660287597935758185612788037642940 ) OR ( 448942095092964262434492324876166300579956931385 and 459017303243869235046626918419983809325629731930 )'
(CF ,s) = abdec.Encryption(params, ck, PK,  policy_str,  O)
( Z) = abdec.PreDe(CF, params, ak)
(decrypted_message) = abdec.Decryption(CF, params, ak, du, Z)
(CF_prim) = abdec.ReEncryption( params,  policy_str, PK)
print("decrypted_message", decrypted_message)
