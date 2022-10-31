
sport      : ShortEnumField                      = 20              (20)
dport      : ShortEnumField                      = 80              (80)
seq        : IntField                            = 0               (0)
ack        : IntField                            = 0               (0)
dataofs    : BitField (4 bits)                   = None            (None)
reserved   : BitField (3 bits)                   = 0               (0)
flags      : FlagsField (9 bits)                 = 2               (2)
window     : ShortField                          = 8192            (8192)
chksum     : XShortField                         = None            (None)
urgptr     : ShortField                          = 0               (0)
options    : TCPOptionsField                     = {}              ({})

>>> ls(IP())
version    : BitField (4 bits)                   = 4               (4)
ihl        : BitField (4 bits)                   = None            (None)
tos        : XByteField                          = 0               (0)
len        : ShortField                          = None            (None)
id         : ShortField                          = 1               (1)
flags      : FlagsField (3 bits)                 = 0               (0)
frag       : BitField (13 bits)                  = 0               (0)
ttl        : ByteField                           = 64              (64)
proto      : ByteEnumField                       = 0               (0)
chksum     : XShortField                         = None            (None)
src        : SourceIPField (Emph)                = '127.0.0.1'     (None)
dst        : DestIPField (Emph)                  = '127.0.0.1'     (None)
options    : PacketListField                     = []              ([])

###[ Ethernet ]###
  dst       = 00:15:5d:70:f4:6c
  src       = 00:15:5d:aa:a6:c6
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 52
     id        = 37638
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0xb759
     src       = 192.168.144.1
     dst       = 192.168.159.17
     \options   \
###[ TCP ]###
        sport     = 1217
        dport     = http_alt
        seq       = 3799026242
        ack       = 0
        dataofs   = 8
        reserved  = 0
        flags     = S
        window    = 64240
        chksum    = 0x32b7
        urgptr    = 0
        options   = [('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None), ('NOP', None), ('SAckOK', b'')]

None
###[ Ethernet ]###
  dst       = 00:15:5d:aa:a6:c6
  src       = 00:15:5d:70:f4:6c
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 52
     id        = 0
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x8a60
     src       = 192.168.159.17
     dst       = 192.168.144.1
     \options   \
###[ TCP ]###
        sport     = http_alt
        dport     = 1217
        seq       = 115001688
        ack       = 3799026243
        dataofs   = 8
        reserved  = 0
        flags     = SA
        window    = 64240
        chksum    = 0xb08a
        urgptr    = 0
        options   = [('MSS', 1460), ('NOP', None), ('NOP', None), ('SAckOK', b''), ('NOP', None), ('WScale', 7)]

None
###[ Ethernet ]###
  dst       = 00:15:5d:70:f4:6c
  src       = 00:15:5d:aa:a6:c6
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 40
     id        = 37639
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0xb764
     src       = 192.168.144.1
     dst       = 192.168.159.17
     \options   \
###[ TCP ]###
        sport     = 1217
        dport     = http_alt
        seq       = 3799026243
        ack       = 115001689
        dataofs   = 5
        reserved  = 0
        flags     = A
        window    = 8212
        chksum    = 0x7e23
        urgptr    = 0
        options   = ''

None
###[ Ethernet ]###
  dst       = 00:15:5d:aa:a6:c6
  src       = 00:15:5d:70:f4:6c
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 46
     id        = 54174
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0xb6c7
     src       = 192.168.159.17
     dst       = 192.168.144.1
     \options   \
###[ TCP ]###
        sport     = http_alt
        dport     = 1217
        seq       = 115001689
        ack       = 3799026243
        dataofs   = 5
        reserved  = 0
        flags     = PA
        window    = 502
        chksum    = 0xb084
        urgptr    = 0
        options   = []
###[ Raw ]###
           load      = 'hello\n'

None
###[ Ethernet ]###
  dst       = 00:15:5d:70:f4:6c
  src       = 00:15:5d:aa:a6:c6
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 40
     id        = 37640
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0xb763
     src       = 192.168.144.1
     dst       = 192.168.159.17
     \options   \
###[ TCP ]###
        sport     = 1217
        dport     = http_alt
        seq       = 3799026243
        ack       = 115001695
        dataofs   = 5
        reserved  = 0
        flags     = A
        window    = 8212
        chksum    = 0x7e1d
        urgptr    = 0
        options   = ''

None
###[ Ethernet ]###
  dst       = 00:15:5d:70:f4:6c
  src       = 00:15:5d:aa:a6:c6
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 46
     id        = 37641
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0xb75c
     src       = 192.168.144.1
     dst       = 192.168.159.17
     \options   \
###[ TCP ]###
        sport     = 1217
        dport     = http_alt
        seq       = 3799026243
        ack       = 115001695
        dataofs   = 5
        reserved  = 0
        flags     = PA
        window    = 8212
        chksum    = 0x3a33
        urgptr    = 0
        options   = []
###[ Raw ]###
           load      = 'hello\n'

None
###[ Ethernet ]###
  dst       = 00:15:5d:aa:a6:c6
  src       = 00:15:5d:70:f4:6c
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 40
     id        = 54175
     flags     = DF
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0xb6cc
     src       = 192.168.159.17
     dst       = 192.168.144.1
     \options   \
###[ TCP ]###
        sport     = http_alt
        dport     = 1217
        seq       = 115001695
        ack       = 3799026249
        dataofs   = 5
        reserved  = 0
        flags     = A
        window    = 502
        chksum    = 0xb07e
        urgptr    = 0
        options   = ''

None
###[ Ethernet ]###
  dst       = 00:15:5d:70:f4:6c
  src       = 00:15:5d:aa:a6:c6
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 40
     id        = 37642
     flags     = DF
     frag      = 0
     ttl       = 128
     proto     = tcp
     chksum    = 0xb761
     src       = 192.168.144.1
     dst       = 192.168.159.17
     \options   \
###[ TCP ]###
        sport     = 1217
        dport     = http_alt
        seq       = 3799026249
        ack       = 115001695
        dataofs   = 5
        reserved  = 0
        flags     = RA
        window    = 0
        chksum    = 0x9e27
        urgptr    = 0
        options   = ''

None