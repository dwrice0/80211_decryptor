from Crypto.Cipher import AES
from scapy.all import *

def build_pn(packet):
    pn = packet.PN5.to_bytes(1, "big") + packet.PN4.to_bytes(1, "big") + packet.PN3.to_bytes(1, "big") + packet.PN2.to_bytes(1, "big") + packet.PN1.to_bytes(1, "big") + packet.PN0.to_bytes(1, "big")
    print(f'PN={pn.hex()}')
    return pn

def build_AAD(packet):
    p = bytes(packet.payload)
    offset = 0
    FCarray = bytearray(p[offset:offset+2])
    offset += 4
    FCarray[0] = FCarray[0] & 0x8f
    if packet.haslayer(Dot11QoS):
        FCarray[1] = (FCarray[1] & 0x47) | 0x40
    else:
        FCarray[1] = (FCarray[1] & 0xc7) | 0x40
    FC = bytes(FCarray)
    print(f'FC = {FC.hex()}')
    A1 = p[offset:offset+6]
    offset += 6
    print(f'A1 = {A1.hex()}')
    A2 = p[offset:offset+6]
    offset += 6
    print(f'A2 = {A2.hex()}')
    A3 = p[offset:offset+6]
    offset += 6
    print(f'A3 = {A3.hex()}')
    SCarray = bytearray(p[offset:offset+2])
    offset += 2
    SCarray[0] = SCarray[0] & 0x0f
    SCarray[1] = SCarray[1] & 0x00
    SC = bytes(SCarray)
    print(f'SC = {SC.hex()}')
    A4 = b''
    if packet.addr4 != None:
        A4 = p[offset:offset+6]
        offset += 6
        print(f'A4 = {A4.hex()}')
    QC = b''
    if packet.haslayer(Dot11QoS):
        QCarray = bytearray(p[offset:offset+2])
        QCarray[0] = QCarray[0] & 0x0f
        QCarray[1] = QCarray[1] & 0x00
        QC = bytes(QCarray)
        print(f'QC = {QC.hex()}')
    AAD = FC + A1 + A2 + A3 + SC + A4 + QC
    return AAD

def build_nonce(packet):
    offset = 24
    p = bytes(packet.payload)
    if packet.addr4 != None:
        offset = offset + 6

    if packet.haslayer(Dot11QoS):
        priority_byte_array = bytearray(p[offset:offset+1])
        priority_byte_array[0] = priority_byte_array[0] & 0x0f
    else:
        priority_byte_array = bytearray(b'\x00')
    
    A2 = p[10:16]
    PN = build_pn(packet)
    nonce = bytes(priority_byte_array) + A2 + PN
    print(f'nonce = {nonce.hex()}')

    return nonce

def build_clear_Frame(packet, data):
    return None

def decrypt_frame(packet, key):
    print(f'key = {key.hex()}')
    print(f'add1 = {packet.addr1}')
    print(f'add2 = {packet.addr2}')
    print(f'add3 = {packet.addr3}')
    print(f'add4 = {packet.addr4}')

    AAD = build_AAD(packet)
    print(f'AAD = {AAD.hex()}')
    #print(f'AADlen = {len(AAD)}')

    nonce = build_nonce(packet)

    rawdata = bytes(packet.data)
    print(f'rawdata    = {rawdata.hex()}')
    print(f'rawdatalen = {len(rawdata)}')
    cipherdata = rawdata[:-12]
    print(f'cipherdata = {cipherdata.hex()}')
    print(f'cipeherdatalen = {len(cipherdata)}')
    tag = rawdata[len(rawdata)-12:len(rawdata)-4]
    print(f'tag = {tag.hex()}')

    cipher = AES.new(key, AES.MODE_CCM, nonce, mac_len=8)
    cipher.update(AAD)
    try:
        data = cipher.decrypt_and_verify(cipherdata, tag)
        print(f'cleardata = {data.hex()}')
        #clearpacket = build_clear_frame(packet, data)
        return None
    except Exception as ex:
        print(ex)
        return None
