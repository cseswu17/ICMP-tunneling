import json
import sys
import base64

j = 1
encryptedstr=''
with open('../packet/packet4.json') as json_file:
    json_data = json.load(json_file)
    for i in json_data:
        if (j==len(json_data)):
            break
        sequence = json_data[j-1]["_source"]["layers"]["icmp"]["icmp.seq_le"]
        if (sequence == str(j)):
            encryptedstr+=json_data[j-1]["_source"]["layers"]["icmp"]["data"]["data.data"]  
            j = j + 1
        elif (sequence != str(j)):
            # success flag
            flag = False
            for h in range(0,len(json_data)) :
                if(str(j) == json_data[h]["_source"]["layers"]["icmp"]["icmp.seq_le"]):
                    encryptedstr+=json_data[h]["_source"]["layers"]["icmp"]["data"]["data.data"]
                    j = j + 1
                    flag = True
                    break
            if (not flag):
                print("[*] " + str(j) +" is not recevied!!!")
                sys.exit(0)
    
# : 문자 삭제
encryptedstr=encryptedstr.replace(":","")
# hex to bytes
encryptedstr = bytes.fromhex(encryptedstr)
# b32 decode
encryptedstr = base64.b32decode(encryptedstr)   
# 파일 저장
file = open('../decryption/decryption_Data_leak_testcode.z02', 'wb')
file.write(encryptedstr)
file.close
print("[*] Successfully saved decrypted file!")