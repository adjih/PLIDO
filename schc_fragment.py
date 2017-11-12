import sys
import struct
import binascii

SCHC_TTL = 60   # 60 seconds

# fragmentation parameters
#"mode": "win-ack-error",
#"mode": "no-ack",

fp_ietf100_win = {
    # 0|0|12345678|12345678
    "mode": "win-ack-always",
    "hdr_size": 16,
    "ack_hdr_size": 16,
    "rid_size": 0,
    "rid_shift": 0,
    "rid_mask": 0x0000,
    "dtag_size": 0,
    "dtag_shift": 0,
    "dtag_mask": 0x0000,
    "win_size": 8,
    "win_shift": 8,
    "win_mask": 0xff00,
    "fcn_size": 8,
    "fcn_shift": 0,
    "fcn_mask": 0x00ff,
    "bitmap_size": 8,
    "bitmap_shift": 0,
    }

fp = fp_ietf100_win

def int_to_str(n, length, endianess='big'):
    '''
    pycom doesn't support str.to_bytes() and __mul__ of str.
    '''
    h = '%x' % n
    s = binascii.unhexlify(
        "".join(["0" for i in range(length*2-len(h))]) + h)
    return s if endianess == 'big' else s[::-1]

def str_to_int(b):
    n = 0
    for i in b:
        n = (n<<8)+ord(i)
    return n

class fragment:

    pos = 0

    def __init__(self, srcbuf, rid, dtag):
        self.srcbuf = srcbuf
        # check rule_id size
        if rid > 2**fp["rid_size"] - 1:
            raise ValueError("rule_id is too big for the rule id field.")
        #
        self.max_fcn = fp["bitmap_size"]-1  # XXX need to be reviewd
        #
        self.fcn = self.max_fcn
        self.end_of_fragment = (1<<fp["fcn_size"])-1
        #
        print("rule_id =", rid, "dtag =", dtag)
        h_rid = (rid<<fp["rid_shift"])&fp["rid_mask"]
        h_dtag = (dtag<<fp["dtag_shift"])&fp["dtag_mask"]
        # here don't care window bit anyway
        # the room of the bit is reserved by the *_shift.
        self.win = 0
        self.base_hdr = h_rid + h_dtag

    def next_fragment(self, l2_size):
        rest_size = l2_size
        ret = 1
        if self.pos + l2_size >= len(self.srcbuf):
            self.fcn = self.end_of_fragment
            rest_size = len(self.srcbuf) - self.pos
            ret = 0
        elif self.fcn == 0:
            self.fcn = self.max_fcn
        #
        hdr = self.base_hdr + (self.fcn<<fp["fcn_shift"])&fp["fcn_mask"]
        #
        h = int_to_str(hdr, int(fp["hdr_size"]/8))
        if fp["mode"] != "no-ack":
            print("win =", self.win, "fcn =", self.fcn, "pos = ", self.pos, "rest =", rest_size)
        else:
            print("fcn =", self.fcn, "pos = ", self.pos, "rest =", rest_size)
        #
        piece = h + self.srcbuf[self.pos:self.pos+rest_size]
        self.pos += rest_size
        self.fcn -= 1
        return ret, piece

    def check_ack(self, recvbuf):
        hdr_size_byte = int(fp["hdr_size"]/8)
        hdr = str_to_int(recvbuf[:hdr_size_byte])
        dtag = (hdr&fp["dtag_mask"])>>fp["dtag_shift"]
        bitmap = hdr&fp["bitmap_mask"]
        piece = recvbuf[hdr_size_byte:]
        print("dtag=", dtag, "fcn=", fcn, "piece=", repr(piece))
        #
        # XXX need to be fixed
        self.win += 1
        return True

SCHC_DEFRAG_DONE = 0
SCHC_DEFRAG_NOTYET = 1
SCHC_DEFRAG_ACK = 2
SCHC_DEFRAG_ERROR = -1

class defragment_message():
    '''
    defragment fragments into a message
    '''
    fragment_list = {}
    ttl = SCHC_TTL

    def __init__(self, rid, dtag, win, fcn, piece):
        self.rid = rid
        self.dtag = dtag
        self.win = win
        self.bitmap = 1<<(fcn+1)
        self.defrag(fcn, piece)

    def defrag(self, fcn, piece):
        s = self.fragment_list.get(fcn)
        if s:
            # it's received already.
            return SCHC_DEFRAG_ERROR
        # set new piece
        self.fragment_list[fcn] = piece
        self.bitmap |= 1<<(fcn+1)
        return SCHC_DEFRAG_NOTYET

    def assemble(self, fcn):
        return "".join([self.fragment_list[str(i)] for i in
                         range(len(self.fragment_list))])

    def make_ack(self):
        print("rule_id =", self.rid, "dtag =", self.dtag)
        h_rid = (self.rid<<fp["rid_shift"])&fp["rid_mask"]
        h_dtag = (self.dtag<<fp["dtag_shift"])&fp["dtag_mask"]
        h_win = (self.win<<fp["win_shift"])&fp["win_mask"]
        # because the bit0 is reserved for all-bit-1
        h = int_to_str(h_rid + h_dtag + h_win + self.bitmap, int(fp["ack_hdr_size"]/8))
        # XXX need padding
        return h

    def is_alive(self):
        self.ttl -= 1
        if self.ttl > 0:
            return True
        return False

class defragment_factory():
    msg_list = {}

    def __init__(self):
        self.end_of_fragment = (1<<fp["fcn_size"])-1

    def defrag(self, recvbuf):
        # XXX no thread safe
        hdr_size_byte = int(fp["hdr_size"]/8)
        hdr = str_to_int(recvbuf[:hdr_size_byte])
        rid = (hdr&fp["rid_mask"])>>fp["rid_shift"]
        dtag = (hdr&fp["dtag_mask"])>>fp["dtag_shift"]
        print("rid=", rid, "dtag=", dtag)
        # XXX ietf100 hack
        win_ack_always = True # XXX win-ack-always in ietf100 hackathon
        if win_ack_always == True:
            win = (hdr&fp["win_mask"])>>fp["win_shift"]
            fcn = (hdr&fp["fcn_mask"])>>fp["fcn_shift"]
            piece = recvbuf[hdr_size_byte:]
            bitmap = None   # just for sure
            print("win=", win, "fcn=", fcn, "piece=", repr(piece))
        elif rid == 1:
            win = (hdr&fp["win_mask"])>>fp["win_shift"]
            piece = None    # just for sure
            bitmap = recvbuf[hdr_size_byte:]
            print("win=", win, "bitmap=", repr(bitmap))
        else:
            print("not supported")
            return SCHC_DEFRAG_NOTYET
        #
        #
        m = self.msg_list.get(dtag)
        if m:
            ret = m.defrag(fcn, piece)
            if ret == SCHC_DEFRAG_ERROR:
                print("ERROR")
                return ret, None
            if fcn == self.end_of_fragment:
                return SCHC_DEFRAG_DONE, m.assemble()
            if win_ack_always and fcn == 0:
                return SCHC_DEFRAG_ACK, m.make_ack()
            return SCHC_DEFRAG_NOTYET, None
        else:
            # if the piece is the end of fragment, don't put to the list.
            if fcn == self.end_of_fragment:
                return SCHC_DEFRAG_DONE, piece
            # otherwise, put it into the list.
            self.msg_list[dtag] = defragment_message(rid, dtag, win, fcn, piece)
            return SCHC_DEFRAG_NOTYET, None

    def purge(self):
        # XXX no thread safe
        for dtag in self.msg_list.iterkeys():
            if self.msg_list[dtag].is_alive():
                continue
            # delete it
            self.msg_list.pop(dtag)

#
# test code
#
def test_defrag(sent_buf):
    import time
    dfg = defragment_factory()
    for i in sent_buf:
        print("piece=", repr(i))
        ret, buf = dfg.defrag(i)
        if ret == SCHC_DEFRAG_NOTYET:
            print("not yet")
        elif ret == SCHC_DEFRAG_DONE:
            print("done")
            print(repr(buf))
            break
        else:
            print("error")
        #
        # purge the members if possible.
        dfg.purge()
        time.sleep(1)

if __name__ == "__main__" :
    sent_buf = []
    #
    #buf = struct.pack(">HHHHBBBBHH",1,2,3,4,5,6,7,8,9,10)
    message = "Hello LoRa"
    fmt = ">%ds" % len(message)
    buf = struct.pack(fmt, message)
    fg = fragment(buf, 0, 0, window_size=1)
    l2_size = len(message)  # it must be set in each sending message.
    #l2_size = 4
    while True:
        ret, piece, = fg.next_fragment(l2_size)
        print("fragment", binascii.hexlify(piece), "%s"%piece)
        sent_buf.append(piece)
        if ret == 0:
            break

    if True:
        print("=== defrag test")
        test_defrag(sent_buf)

