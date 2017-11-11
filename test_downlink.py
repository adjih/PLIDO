from network import LoRa
import socket
import time
import binascii
import pycom
import struct
import fragment

lora = LoRa(mode=LoRa.LORAWAN)
app_eui = binascii.unhexlify('00 00 00 00 00 00 00 00'.replace(' ',''))
app_key = binascii.unhexlify('11 22 33 44 55 66 77 88 11 22 33 44 55 66 77 88'.replace(' ',''))
lora.join(activation=LoRa.OTAA, auth=(app_eui, app_key),  timeout=0)

while not lora.has_joined():
    time.sleep(2.5)
    print('Not yet joined...')

s = socket.socket(socket.AF_LORA, socket.SOCK_RAW)
s.setsockopt(socket.SOL_LORA, socket.SO_DR, 5)
s.setsockopt(socket.SOL_LORA,  socket.SO_CONFIRMED,  False)

pycom.heartbeat(False)

# create a message for the trigger.
message = "Hello LoRa"
fmt = ">%ds" % len(message)
buf = struct.pack(fmt, message)
l2_size = len(message)  # it must be set in each sending message.
s.send(buf)

# fragment instance
# XXX rule_id and dtag are zero for the ietf100 testing.
fg = fragment.fragment(buf, 0, 0, window_size=1)

dfg = fragment.defragment_factory()

while True:
    pycom.rgbled(0xFF0000)
    s.setblocking(True)
    s.settimeout(10)

    # waiting somethign from the server
    try:
        rx_data = s.recv(64)
        print("received:", rx_data)
        # trying to defrag
        ret, buf = dfg.defrag(rx_data)
        if ret == _SCHC_DEFRAG_NOTYET:
            print("not yet")
        elif ret == _SCHC_DEFRAG_DONE:
            print(repr(rx_data))
            # XXX taking the fcn
            bitmap = rx_data[1]&0xff
            if bitmap == 1:
                print("done")
                break
            #
            print("sending ack")
            # XXX taking the bitmap
            win = rx_data[0]&0x1
            tx_piece = struct.pack(">BB", win, 1)
            try:
                s.send(tx_piece)
            except:
                print ('timeout in sending')
            pycom.rgbled(0x00FF00)
        else:
            print("error")

        pycom.rgbled(0x0000FF)
    except:
        print ('timeout in receive')
        pycom.rgbled(0x000000)

    s.setblocking(False)
    time.sleep (29)
