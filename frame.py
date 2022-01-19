from Crypto.Cipher import AES
from scapy.all import *

def build_pn(packet):
    pn = packet.PN5.to_bytes(1, "big") + packet.PN4.to_bytes(1, "big") + packet.PN3.to_bytes(1, "big") + packet.PN2.to_bytes(1, "big") + packet.PN1.to_bytes(1, "big") + packet.PN0.to_bytes(1, "big")
    return pn

def build_AAD(packet):
    p = bytes(packet.payload)
    offset = 0
    FC = p[offset:offset+2]
    offset += 4
    #print(f'FC-before = {FC.hex()}')
    #fc_and_mask_str = '1111000111100010'
    fc_and_mask_str = '0000111101000111'
    #fc_and_mask_str = '1000111101000111'
    fc_and_mask_int = int(fc_and_mask_str, 2)
    fc_and_mask_hex = fc_and_mask_int.to_bytes(2, "big")
    print(f'FC-before = {FC.hex()}')
    print(f'fc_and_mask = {fc_and_mask_hex.hex()}')
    FC = bytes([a & b for a,b in zip(FC, fc_and_mask_hex)])
    #print(f'FCand = {FC.hex()}')
    #fc_or_mask_str = '0000000000000010'
    fc_or_mask_str = '0000000001000000'
    fc_or_mask_int = int(fc_or_mask_str, 2)
    fc_or_mask_hex = fc_or_mask_int.to_bytes(2,"big")
    print(f'fc_or_mask = {fc_or_mask_hex.hex()}')
    FC = bytes([a | b for a,b in zip(FC, fc_or_mask_hex)])
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
    SC = p[offset:offset+2]
    offset += 2
    print(f'SC-before = {SC.hex()}')
    sc_and_mask_str = '0000111100000000'
    sc_and_mask_int = int(sc_and_mask_str, 2)
    sc_and_mask_hex = sc_and_mask_int.to_bytes(2, "big")
    print(f'sc_and_mask = {sc_and_mask_hex.hex()}')
    SC = bytes([a & b for a,b in zip(SC, sc_and_mask_hex)])
    print(f'SC = {SC.hex()}')
    A4 = b''
    if packet.addr4 != None:
        A4 = p[offset:offset+6]
        offset += 6
        print(f'A4 = {A4.hex()}')
    QC = b''
    if packet.haslayer(Dot11QoS):
        QC = p[offset:offset+2]
        print(f'QC-before = {QC.hex()}')
        qc_and_mask_str = '0000111100000000'
        qc_and_mask_int = int(qc_and_mask_str, 2)
        qc_and_mask_hex = qc_and_mask_int.to_bytes(2, "big")
        QC = bytes([a & b for a,b in zip(QC, qc_and_mask_hex)])
        print(f'QC = {QC.hex()}')
    AAD = FC + A1 + A2 + A3 + SC + A4 + QC
    return AAD

def build_nonce(packet):
    offset = 24
    p = bytes(packet.payload)
    if packet.addr4 != None:
        offset = offset + 6

    priority_byte = b'\x00'
    priority_mask_str = '00000000'
    if packet.haslayer(Dot11QoS):
        priority_byte = p[offset:offset+1]
        priority_mask_str = '00001111'
    
    print(f'priority_byte before = {priority_byte.hex()}')
    priority_mask_int = int(priority_mask_str, 2)
    priority_mask_hex = priority_mask_int.to_bytes(1, "big")
    print(f'priority_mask = {priority_mask_hex.hex()}')
    priority_byte = bytes([a & b for a,b in zip(priority_byte, priority_mask_hex)])
    print(f'priority_byte = {priority_byte.hex()}')
    #priority_int = int.from_bytes(priority_byte,byteorder='big')
    #print(f'priority_int = {priority_int}')
    #priority_int = priority_int << 4
    #print(f'priority_int shifted = {priority_int}')
    #priority_byte = priority_int.to_bytes(1, byteorder='big')
    #print(f'priority_byte shifted = {priority_byte.hex()}')
    A2 = p[10:16]
    PN = build_pn(packet)
    nonce = priority_byte + A2 + PN
    print(f'nonce = {nonce.hex()}')
    #print(f'noncelen = {len(nonce)}')

    return nonce

def build_clear_Frame(packet, data):
    return None

def decrypt_frame(packet, key):
    print(f'key = {key.hex()}')
    print("Got Data Frame")
    print(f'add1 = {packet.addr1}')
    print(f'add2 = {packet.addr2}')
    print(f'add3 = {packet.addr3}')
    print(f'add4 = {packet.addr4}')

    PN = build_pn(packet)
    print(f'PN = {PN.hex()}')

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
