from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import binascii
import json

def send_apdu(connection, apdu):
    data, sw1, sw2 = connection.transmit(apdu)
    return data, sw1, sw2

def select_app(connection, aid_hex):
    aid = toBytes(aid_hex)
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]
    return send_apdu(connection, apdu)

def get_processing_options(connection, pdol=None):
    if pdol:
        pdol_data = toBytes(pdol)
        gpo_data = [0x83, len(pdol_data)] + pdol_data
    else:
        gpo_data = [0x83, 0x00]
    apdu = [0x80, 0xA8, 0x00, 0x00, len(gpo_data)] + gpo_data + [0x00]
    return send_apdu(connection, apdu)

def read_record(connection, sfi, record):
    apdu = [0x00, 0xB2, record, (sfi << 3) | 4, 0x00]
    return send_apdu(connection, apdu)

def parse_tlv(data):
    i = 0
    result = {}
    while i < len(data):
        first_byte = data[i]
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:  # Multi-byte tag
            while i < len(data) and data[i] & 0x80:
                tag = (tag << 8) | data[i]
                i += 1
            tag = (tag << 8) | data[i]
            i += 1
        length = data[i]
        i += 1
        if length & 0x80:  # Multi-byte length
            length_bytes = length & 0x7F
            length = 0
            for _ in range(length_bytes):
                length = (length << 8) | data[i]
                i += 1
        value = data[i:i + length]
        i += length
        tag_hex = f"{tag:02X}" if tag <= 0xFF else f"{tag:04X}"
        if first_byte & 0x20:  # Constructed tag
            parsed_value = parse_tlv(value)
        else:
            parsed_value = ''.join(f"{b:02X}" for b in value)
        # Handle duplicate tags by converting to a list
        if tag_hex in result:
            if isinstance(result[tag_hex], list):
                result[tag_hex].append(parsed_value)
            else:
                result[tag_hex] = [result[tag_hex], parsed_value]
        else:
            result[tag_hex] = parsed_value
    return result

def extract_aids(tlv):
    directory_entries = tlv.get('6F', {}).get('A5', {}).get('BF0C', {}).get('61', [])
    if not isinstance(directory_entries, list):
        directory_entries = [directory_entries]
    aids = []
    for entry in directory_entries:
        if not isinstance(entry, dict):
            continue
        aid = entry.get('4F')
        label_hex = entry.get('50', '')
        label = binascii.unhexlify(label_hex).decode('ascii', errors='ignore')
        priority = entry.get('87', 'N/A')
        if aid:
            aids.append({'aid': aid, 'label': label, 'priority': priority})
    return aids

def process_afl(connection, afl_data, script):
    afl_bytes = toBytes(afl_data)
    for i in range(0, len(afl_bytes), 4):
        entry = afl_bytes[i:i + 4]
        sfi = entry[0] >> 3
        start_rec = entry[1]
        end_rec = entry[2]
        for rec in range(start_rec, end_rec + 1):
            resp, sw1, sw2 = read_record(connection, sfi, rec)
            if sw1 == 0x90 and sw2 == 0x00:
                script.append({
                    "apdu": toHexString([0x00, 0xB2, rec, (sfi << 3) | 4, 0x00]).replace(" ", "").lower(),
                    "response": toHexString(resp).replace(" ", "")
                })
                print(f"Record {rec:02X} from SFI {sfi:02X}: {toHexString(resp)}")
    return script

def generate_arqc(connection, amount="000000000100", additional_data=""):
    # Standard EMV ARQC data format
    gen_ac_data = (
        "9F0206" + amount +  # Amount
        "5F2A020076" +      # Transaction Currency Code (Euro)
        "9A032311019C0100" +  # Transaction Date and Type
        "9F370412345678"    # Unpredictable Number
    )
    gen_ac_apdu = [0x80, 0xAE, 0x80, 0x00, len(toBytes(gen_ac_data))] + toBytes(gen_ac_data) + [0x00]
    resp, sw1, sw2 = send_apdu(connection, gen_ac_apdu)
    if sw1 != 0x90 or sw2 != 0x00:
        print(f"ARQC failed: SW1={sw1:02X}, SW2={sw2:02X}")
    return resp, sw1, sw2

def get_processing_options(connection, pdol=None):
    if pdol:
        pdol_data = "9F0206000000000100"  # Default amount if PDOL is present
        gpo_data = [0x83, len(toBytes(pdol_data))] + toBytes(pdol_data)
    else:
        gpo_data = [0x83, 0x00]
    apdu = [0x80, 0xA8, 0x00, 0x00, len(gpo_data)] + gpo_data + [0x00]
    resp, sw1, sw2 = send_apdu(connection, apdu)
    if sw1 != 0x90 or sw2 != 0x00:
        print(f"GPO failed: SW1={sw1:02X}, SW2={sw2:02X}")
    return resp, sw1, sw2

def main():
    r = readers()
    if not r:
        print("Nenhum leitor NFC encontrado.")
        return
    reader = r[0]
    connection = reader.createConnection()
    connection.connect()
    script = []

    # Step 1: SELECT PPSE
    select_ppse = [0x00, 0xA4, 0x04, 0x00, 0x0E] + list(b"2PAY.SYS.DDF01") + [0x00]
    resp, sw1, sw2 = send_apdu(connection, select_ppse)
    script.append({"apdu": toHexString(select_ppse).replace(" ", "").lower(),
                   "response": toHexString(resp).replace(" ", "")})

    tlv = parse_tlv(resp)
    aids = extract_aids(tlv)
    print(aids)
    if not aids:
        print("AID não encontrado na resposta da PPSE.")
        return

    # Use the first AID found
    aid = aids[0]['aid']
    app_label = aids[0]['label']

    # Step 2: SELECT AID
    aid_bytes = toBytes(aid)
    select_aid = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + aid_bytes + [0x00]
    resp, sw1, sw2 = send_apdu(connection, select_aid)
    script.append({"apdu": toHexString(select_aid).replace(" ", "").lower(),
                   "response": toHexString(resp).replace(" ", "")})

    tlv = parse_tlv(resp)
    pdol = tlv.get("9F38", None)
    

    # Step 3: GPO
    resp, sw1, sw2 = get_processing_options(connection, pdol)
    gpo_apdu = [0x80, 0xA8, 0x00, 0x00]
    if pdol:
        gpo_apdu += [len(toBytes(pdol)), 0x83, len(toBytes(pdol))] + toBytes(pdol) + [0x00]
    else:
        gpo_apdu += [0x02, 0x83, 0x00, 0x00]
    script.append({"apdu": toHexString(gpo_apdu).replace(" ", "").lower(),
                   "response": toHexString(resp).replace(" ", "")})

    # Process AFL if present
    gpo_tlv = parse_tlv(resp)
    afl = None
    if '77' in gpo_tlv:
        afl = gpo_tlv['77'].get('94', None)
    elif '80' in gpo_tlv:
        response_data = gpo_tlv['80']
        if len(response_data) > 4:
            afl = response_data[4:]

    if afl:
        script = process_afl(connection, afl, script)

    try:
    # Generate ARQC
        resp, sw1, sw2 = generate_arqc(connection)
        script.append({
            "apdu": toHexString([0x80, 0xAE, 0x80, 0x00]).replace(" ", "").lower(),
            "response": toHexString(resp).replace(" ", "")
        })
    except:
        pass
    iad = parse_tlv(resp).get("9F10", "")

    # Extract card data from records
    app_name = None
    country_code = None
    cvm_list = None
    ctq_data = None

    for record in script:
        try:
            record_tlv = parse_tlv(bytes.fromhex(record['response']))
            if '70' in record_tlv:
                record_data = record_tlv['70']
                
                # Country code (tag 5F28)
                if '5F28' in record_data:
                    country_code = record_data['5F28']
                
                # CVM List (tag 8E)
                if '8E' in record_data:
                    cvm_list = record_data['8E']
                
                # Card Transaction Qualifiers (tag 9F6C)
                if '9F6C' in record_data:
                    ctq_data = record_data['9F6C']

        except Exception as e:
            print(f"Error parsing record: {e}")
            continue


    # Create dumps directory if it doesn't exist
    import os
    if not os.path.exists('dumps'):
        os.makedirs('dumps')

    # Get Track2 data from AFL records if available
    track2 = None
    for record in script:
        try:
            record_tlv = parse_tlv(bytes.fromhex(record['response']))
            if '70' in record_tlv and '57' in record_tlv['70']:
                track2 = record_tlv['70']['57']
                break
        except Exception as e:
            print(f"Error parsing record: {e}")
            continue
    
    output = {
        "name": f"{app_label}_{track2[:6]}]",
        "appName": app_label,
        "aid": aid,
        "pdol": pdol.lower() if pdol else None,
        "cvmVisa": cvm_list if aid.startswith('A000000003') else None,
        "cvmMaster": cvm_list if aid.startswith('A000000004') else None,
        "script": script,
        "country": country_code or "",
        "ctq": ctq_data or "0000",
        "iad": iad
    }
    # Generate filename
    filename = f"{track2 or 'notrack2'}_{aid}.json"
    filepath = os.path.join('dumps', filename)
    
    # Save to file
    with open(filepath, 'w') as f:
        f.write(json.dumps(output, indent=4, ensure_ascii=False))
    
    print(f"Output saved to: {filepath}")
    print(json.dumps(output, indent=4, ensure_ascii=False))

if __name__ == "__main__":
    main()