"""Offline EDC17C46 decoder arithmetic, translated from the verified firmware.
No files, vehicle interfaces, or network are accessed by this module.
"""

def bit(v,n):return (v>>n)&1

def cpu_seed(uid):
    assert len(uid)>=8
    indices=[(0,1,4),(1,2,3),(0,2,5),(0,3,4),(2,3,6),
             (1,4,5),(4,5,6),(2,5,7),(4,6,7),(0,6,7)]
    return bytes(uid[a]^uid[b]^uid[c] for a,b,c in indices)

class Cipher:
    def __init__(self,word,seed,flash):
        self.flash=flash
        self.seed=seed
        self.s=[word&255,word>>8,word&255,word>>8,seed[0],seed[1]]
    def nonlinear(self):
        a,b,c,d,e,f=self.s
        indices=[bit(a,1)+2*bit(a,2)+4*bit(a,4)+8*bit(a,5),
                 bit(b,0)+2*bit(b,1)+4*bit(b,3)+8*bit(b,7),
                 bit(d,5)+2*bit(c,0)+4*bit(c,2)+8*bit(c,6),
                 bit(e,6)+2*bit(d,0)+4*bit(d,2)+8*bit(d,3),
                 bit(f,1)+2*bit(f,3)+4*bit(f,4)+8*bit(e,5)]
        tables=[0x11aee,0x11afe,0x11afe,0x11afe,0x11aee]
        combined=0
        for off,idx in zip(tables,indices):combined=((combined<<1)|self.flash[off+idx])&255
        return self.flash[0x11b0e+combined]
    def shift(self,x):
        self.s=[((self.s[i]<<1)|(self.s[i+1]>>7))&255 for i in range(5)]+[((self.s[5]<<1)|x)&255]
    def feedback(self):
        taps=[(5,0),(5,4),(5,5),(5,6),(3,1),(3,5),(2,0),(2,1),
              (2,7),(1,7),(0,0),(0,1),(0,4),(0,7),(0,5),(5,1)]
        r=0
        for byte,pos in taps:r^=bit(self.s[byte],pos)
        return r
    def output(self):
        for i in range(4):
            for k in range(7,-1,-1):
                self.shift(self.nonlinear()^bit(self.seed[i+6],k)^bit(self.seed[i+2],k))
        out=0
        for _ in range(16):
            self.shift(self.feedback())
            out=(out<<1)|self.nonlinear()
        return out

def masks(uid,flash):
    seed=cpu_seed(uid)
    words=[int.from_bytes(flash[0x9b1a0+i*2:0x9b1a2+i*2],'little') for i in range(33)]
    return [Cipher(word,seed,flash).output() for word in words]

def header_crc(record):
    crc=int.from_bytes(record[:2],'little')
    for i in range(4,128,4):
        crc=(int.from_bytes(record[i:i+4],'little') ^ ((crc<<1)|((crc&0xedb88320).bit_count()&1)))&0xffffffff
    return crc&65535

