import math
import random

class CalEntropyMethods():
    def __init__(self, k_value):
        self.k_value = k_value
        self.method_dic = dict(
            est_square16384_affine40_remainder_origin=self.calEntropy_estTable_square16384_affine40_remainder_origin,
            est_square16384_affine40_mersenne_stageTableEnd=self.calEntropy_estTable_square16384_affine40_mersenne_stageTableEnd,
            est_pingli=self.calEntropy_pingli
        )

    def do(self, method):
        return self.method_dic[method]
    
    def calEntropy_estTable_square16384_affine40_remainder_origin(self, container):
        # parameter
        all_entropy = []
        result_entropy = 0
        square_size = 8192
        
        # function
        def hash_affine(in_data, square_size):
            para_a = [
                0x177510d1, 0xda1e0f42, 0x964fbf1e, 0x269df1e6, 0x916cc092,
                0x7931bd51, 0x12a504fc, 0x76100f01, 0xc246978c, 0x87f2cc91, 
                0x97910a77, 0x49a930b6, 0x3c48cc20, 0xbbbbff4e, 0xca2d6493, 
                0xfabac315, 0xefbb19dd, 0x954361d, 0x5bff105e, 0x1ad1e815, 
                0xa4d41053, 0xa5507e69, 0x9f571b50, 0x5f03492f, 0x35b3e590, 
                0x426796b6, 0x1a462f78, 0x5f7404e2, 0xcb5e5215, 0x8f081cb7, 
                0x95ab0a84, 0x7d2fd9ba, 0xd7d748db, 0x2c3137eb, 0x8c0c1e71, 
                0x7eeab7d9, 0x4297c61f, 0xbaeec404, 0x55e56436, 0xe281d41a
            ]
            para_b = [
                0x930874a7, 0x7df6e6b4, 0xc3e1046a, 0x289efd5b, 0xbe9694c1, 
                0x2d85c18e, 0x3bfbe5bc, 0xb0e2d294, 0x5031b9cf, 0xe554adbb, 
                0x7a6ea2de, 0x829a2955, 0x6b80de1d, 0x6cf04e75, 0x277f56b1, 
                0x301c379c, 0xf65eeac1, 0xd7ab0949, 0xef0ded41, 0xf2cba001, 
                0xe50f46da, 0xae65910f, 0xb2ec9527, 0x5241b84f, 0x6eb745dc, 
                0x8b14934a, 0xe3087d58, 0xac7035bc, 0xac6c7471, 0xd0a517bc, 
                0x71d65fe2, 0xbab80ff2, 0x224de591, 0xe433876b, 0x7485409b, 
                0x7f067133, 0xa97e19bf, 0x9f3a5ff9, 0x5a545530, 0x6a115f65
            ]
            mod_m = 2**13-1
            hash_result = []
            for i in range(self.k_value):
                result = (para_a[i]*in_data + para_b[i])%mod_m
                key_a = result
                result = (para_a[i+20]*in_data + para_b[i+20])%mod_m
                key_b = result
                hash_result.append( (key_a, key_b) )
            return hash_result
        
        # get entropy of each table
        ## parameter
        k_register = [0,] * self.k_value
        total_item_cnt = 0
        entropy = 0
        
        ## read results and calculate
        for item, cnt in container.most_common():
            # total cnt
            total_item_cnt += cnt
            # hash
            hash_result = hash_affine(item, square_size)
            # query table
            query_result = []
            for key in hash_result:
                # skewed stable distribution F(x; 1,−1, π/2, 0)
                u1 = (key[0]+1) / (square_size)
                u2 = (key[1]+1) / (square_size)
                w1 = math.pi * (u1-0.5)
                w2 = -math.log(u2)
                ran1 = math.tan(w1) * (math.pi/2 - w1)
                ran2 = math.log( w2 * math.cos(w1) / (math.pi/2-w1) )
                ran = ran1 + ran2
                
                # store k value
                query_result.append( int(ran) )
            # store k value
            for i in range(self.k_value):
                k_register[i] += query_result[i] * cnt
        ## est entropy
        if total_item_cnt ==0 or total_item_cnt == 1: return None
        else: 
            for i in range(self.k_value):
                k_register[i] /= total_item_cnt
                entropy += math.exp(k_register[i])
            entropy /= self.k_value
            entropy = -math.log(entropy)
            entropy /= math.log(total_item_cnt)
            all_entropy.append(entropy)
        
        
        # calculate average entropy
        for item in all_entropy: result_entropy += item
        result_entropy /= len(all_entropy)
        return result_entropy

    def calEntropy_estTable_square16384_affine40_mersenne_stageTableEnd(self, container):
        # parameter
        all_entropy = []
        result_entropy = 0
        square_size = 16384
        
        # function
        def hash_affine(in_data, square_size):
            para_a = [
                0x177510d1, 0xda1e0f42, 0x964fbf1e, 0x269df1e6, 0x916cc092,
                0x7931bd51, 0x12a504fc, 0x76100f01, 0xc246978c, 0x87f2cc91, 
                0x97910a77, 0x49a930b6, 0x3c48cc20, 0xbbbbff4e, 0xca2d6493, 
                0xfabac315, 0xefbb19dd, 0x954361d, 0x5bff105e, 0x1ad1e815, 
                0xa4d41053, 0xa5507e69, 0x9f571b50, 0x5f03492f, 0x35b3e590, 
                0x426796b6, 0x1a462f78, 0x5f7404e2, 0xcb5e5215, 0x8f081cb7, 
                0x95ab0a84, 0x7d2fd9ba, 0xd7d748db, 0x2c3137eb, 0x8c0c1e71, 
                0x7eeab7d9, 0x4297c61f, 0xbaeec404, 0x55e56436, 0xe281d41a
            ]
            para_b = [
                0x930874a7, 0x7df6e6b4, 0xc3e1046a, 0x289efd5b, 0xbe9694c1, 
                0x2d85c18e, 0x3bfbe5bc, 0xb0e2d294, 0x5031b9cf, 0xe554adbb, 
                0x7a6ea2de, 0x829a2955, 0x6b80de1d, 0x6cf04e75, 0x277f56b1, 
                0x301c379c, 0xf65eeac1, 0xd7ab0949, 0xef0ded41, 0xf2cba001, 
                0xe50f46da, 0xae65910f, 0xb2ec9527, 0x5241b84f, 0x6eb745dc, 
                0x8b14934a, 0xe3087d58, 0xac7035bc, 0xac6c7471, 0xd0a517bc, 
                0x71d65fe2, 0xbab80ff2, 0x224de591, 0xe433876b, 0x7485409b, 
                0x7f067133, 0xa97e19bf, 0x9f3a5ff9, 0x5a545530, 0x6a115f65
            ]
            mod_m = 2**31-1
            hash_result = []
            for i in range(self.k_value):
                result = (para_a[i]*in_data + para_b[i])%mod_m
                key_a = result % square_size
                result = (para_a[i+20]*in_data + para_b[i+20])%mod_m
                key_b = result % square_size
                hash_result.append( (key_a, key_b) )
            return hash_result
        
        ## parameter
        k_register = [0,] * self.k_value
        total_item_cnt = 0
        entropy = 0
        
        ## read results and calculate
        for item, cnt in container.most_common():
            # total cnt
            total_item_cnt += cnt
            # hash
            hash_result = hash_affine(item, square_size)
            # query table
            query_result = []
            for key in hash_result:
                ## table head
                u1 = (key[0]+1) / (square_size+1)
                u2 = 1 / (square_size+1)
                w1 = math.pi * (u1-0.5)
                w2 = -math.log(u2)
                ran1 = math.tan(w1) * (math.pi/2 - w1)
                ran2 = math.log( w2 * math.cos(w1) / (math.pi/2-w1) )
                ran = ran1 + ran2
                
                ### store k value
                table_head = round(ran)
                ## table end
                table_end_key = key[1] + 1
                if table_end_key <= 185: table_end_correction = 0
                elif table_end_key <= 3150: table_end_correction = -1
                elif table_end_key <= 8933: table_end_correction = -2
                elif table_end_key <= 13108: table_end_correction = -3
                elif table_end_key <= 15093: table_end_correction = -4
                elif table_end_key <= 15897: table_end_correction = -5
                elif table_end_key <= 16203: table_end_correction = -6
                elif table_end_key <= 16318: table_end_correction = -7
                elif table_end_key <= 16360: table_end_correction = -8
                elif table_end_key <= 16375: table_end_correction = -9
                elif table_end_key <= 16381: table_end_correction = -10
                elif table_end_key <= 16383: table_end_correction = -11
                elif table_end_key <= 16384: table_end_correction = -12
                query_result.append( table_head + table_end_correction )
            # store k value
            for i in range(self.k_value):
                k_register[i] += query_result[i] * cnt
        ## est entropy
        if total_item_cnt ==0 or total_item_cnt == 1: return None
        else: 
            for i in range(self.k_value):
                k_register[i] /= total_item_cnt
                entropy += math.exp(k_register[i])
            entropy /= self.k_value
            entropy = -math.log(entropy)
            entropy /= math.log(total_item_cnt)
            all_entropy.append(entropy)
        
        
        # calculate average entropy
        for item in all_entropy: result_entropy += item
        result_entropy /= len(all_entropy)
        return result_entropy

    def calEntropy_pingli(self, container):
        # method parameter
        alpha = 0.999999
        delta = 1 - alpha

        
        # get entropy of each table
        ## parameter
        x_register = [0,] * self.k_value
        entropy = 0
        total_item_cnt = 0

        ## read results and calculate
        for item, cnt in container.most_common():
            ### total cnt
            total_item_cnt += cnt

            ### set seed
            random.seed(item)

            for i in range(self.k_value):
                v = random.uniform(0, math.pi)
                w = -math.log( random.uniform(0, 1) ) # here log is ln
                
                r_1 = math.sin(alpha * v)
                r_2 = pow( math.sin(v), (1/alpha) )
                r_3_1 = math.sin(v * delta)
                r_3 = pow( (r_3_1/w), (delta/alpha) )
                r = (r_1/r_2) * (r_3)

                x_register[i] += r * cnt
        
        ## cal j_value
        j_1 = delta / self.k_value
        j_2 = 0
        for i in range(self.k_value): j_2 += pow( x_register[i], (-alpha/delta) )
        j_value = j_1 * j_2

        ## est entropy
        h_1 = -math.log2(j_value)
        h_2_1 = 1/delta
        h_2_2 = math.log2(total_item_cnt)
        h_2 = h_2_1 * h_2_2
        entropy = h_1 - h_2

        return entropy
