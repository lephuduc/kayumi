import sys

f = open(sys.argv[1], "rb")
payload = f.read()
f.close()

newpayload = [0 for i in range(len(payload) * 2)]
payloadsize = len(payload)

for i in range(payloadsize):
    newpayload[i] = (payload[i] & 0xf0)>> 4 
    newpayload[i  + payloadsize] = payload[i] & 0xf

with open(sys.argv[2],'wb') as f:
    f.write(bytes(newpayload))
