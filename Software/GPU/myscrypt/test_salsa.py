# 4-8-12-0
x = [
0xe9ff2138,
0xb950b9c6,
0x9e197995,
0xcfee0c57,
0xf8ebe179,
0x8ff3599e,
0x9b2117d9,
0x3a797793,
0xb1674ca3,
0x03fb7309,
0xcea97827,
0x825d83b2,
0xd15e60cc,
0x38f6f8b6,
0xe5afdc59,
0xac35c677]

mask = 0xffffffff
print(hex(x[4]))
print(hex(x[12]))
print(hex(x[0]))
sum = (x[12] + x[0]) & mask
print(hex(sum))
rotr = (sum<<7)&mask | (sum>>32-7)
print("rotr",hex(rotr))
res = x[4]^rotr
print(hex(res))