from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import binascii
import json
import os
import time

def send_apdu(connection, apdu):
    print("APDU:", toHexString(apdu).replace(" ", "").lower())
    data, sw1, sw2 = connection.transmit(apdu)
    print("Response:", toHexString(data).replace(" ", "").lower())
    return data, sw1, sw2

def select_app(connection, aid_hex):
    aid = toBytes(aid_hex)
    apdu = [0x00, 0xA4, 0x04, 0x00, len(aid)] + aid + [0x00]
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
        if tag_hex in result:
            if isinstance(result[tag_hex], list):
                result[tag_hex].append(parsed_value)
            else:
                result[tag_hex] = [result[tag_hex], parsed_value]
        else:
            result[tag_hex] = parsed_value
    return result

def find_tag(tlv_data, target_tag):
    results = []
    if isinstance(tlv_data, dict):
        for tag, value in tlv_data.items():
            if tag == target_tag:
                results.append(value)
            results.extend(find_tag(value, target_tag))
    elif isinstance(tlv_data, list):
        for item in tlv_data:
            results.extend(find_tag(item, target_tag))
    return results

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
            apdu = [0x00, 0xB2, rec, (sfi << 3) | 4, 0x00]
            resp, sw1, sw2 = send_apdu(connection, apdu)
            if sw1 == 0x90 and sw2 == 0x00:
                script.append({
                    "apdu": toHexString(apdu).replace(" ", "").lower(),
                    "response": toHexString(resp).replace(" ", "")
                })
                print(f"Record {rec:02X} from SFI {sfi:02X}: {toHexString(resp)}")
    return script

def generate_arqc(connection, amount="000000000100"):
    gen_ac_data = (
        "9F0206" + amount +       # Amount
        "5F2A020076" +           # Currency (EUR: 0076)
        "9A03250328" +          # Date: 2025-03-28
        "9C0100" +              # Type: Purchase (00)
        "9F370412345678"         # Unpredictable Number
    )
    gen_ac_apdu = [0x80, 0xAE, 0x80, 0x00, len(toBytes(gen_ac_data))] + toBytes(gen_ac_data) + [0x00]
    resp, sw1, sw2 = send_apdu(connection, gen_ac_apdu)
    if sw1 != 0x90 or sw2 != 0x00:
        print(f"ARQC failed: SW1={sw1:02X}, SW2={sw2:02X}")
    return resp, sw1, sw2

def parse_pdol(pdol_str):
    pdol_bytes = toBytes(pdol_str)
    i = 0
    pdol_list = []
    while i < len(pdol_bytes):
        tag_bytes = [pdol_bytes[i]]
        i += 1
        if tag_bytes[0] & 0x1F == 0x1F:  # Multi-byte tag
            while i < len(pdol_bytes) and pdol_bytes[i] & 0x80:
                tag_bytes.append(pdol_bytes[i])
                i += 1
            tag_bytes.append(pdol_bytes[i])
            i += 1
        tag_hex = ''.join(f"{b:02X}" for b in tag_bytes)
        length = pdol_bytes[i]
        i += 1
        pdol_list.append((tag_hex, length))
    return pdol_list

def build_pdol_data(pdol_list):
    default_values = {
        "9F1D": [0x00] * 8,        # Terminal Risk Management Data (8 bytes)
        "9F1A": [0x00, 0x76],      # Terminal Country Code: Portugal (0076)
        "9F35": [0x22],            # Terminal Type: Online POS (22)
    }
    pdol_data = []
    for tag, length in pdol_list:
        if tag in default_values:
            value = default_values[tag]
            if len(value) != length:
                print(f"Warning: Default value for {tag} has length {len(value)}, expected {length}")
                value = value[:length] + [0x00] * (length - len(value)) if len(value) < length else value[:length]
        else:
            print(f"Warning: No default value for {tag}, using zeros")
            value = [0x00] * length
        pdol_data.extend(value)
    return pdol_data

def get_processing_options(connection, pdol=None):
    if pdol:
        pdol_list = parse_pdol(pdol)
        pdol_data_bytes = build_pdol_data(pdol_list)
        gpo_data = [0x83, len(pdol_data_bytes)] + pdol_data_bytes
    else:
        gpo_data = [0x83, 0x00]
    apdu = [0x80, 0xA8, 0x00, 0x00, len(gpo_data)] + gpo_data + [0x00]
    resp, sw1, sw2 = send_apdu(connection, apdu)
    if sw1 != 0x90 or sw2 != 0x00:
        print(f"GPO failed: SW1={sw1:02X}, SW2={sw2:02X}")
    return apdu, resp, sw1, sw2

def wait_for_card():
    max_attempts = 10
    attempt = 0
    while attempt < max_attempts:
        r = readers()
        if r:
            try:
                reader = r[0]
                connection = reader.createConnection()
                connection.connect()
                print("Card connected successfully!")
                return connection
            except Exception as e:
                print(f"Waiting for card... (Attempt {attempt + 1}/{max_attempts})")
                attempt += 1
                time.sleep(2)
        else:
            print("No NFC reader found.")
            return None
    print("Timeout waiting for card.")
    return None

def extractApplication(aid, app_label):
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

    # Step 2: SELECT AID
    aid_bytes = toBytes(aid)
    select_aid = [0x00, 0xA4, 0x04, 0x00, len(aid_bytes)] + aid_bytes + [0x00]
    resp, sw1, sw2 = send_apdu(connection, select_aid)
    script.append({"apdu": toHexString(select_aid).replace(" ", "").lower(),
                   "response": toHexString(resp).replace(" ", "")})

    tlv = parse_tlv(resp)
    pdol_values = find_tag(tlv, "9F38")
    pdol = pdol_values[0] if pdol_values else None
    print("PDOL:", pdol)

    # Step 3: GPO
    gpo_apdu, resp, sw1, sw2 = get_processing_options(connection, pdol)
    script.append({"apdu": toHexString(gpo_apdu).replace(" ", "").lower(),
                   "response": toHexString(resp).replace(" ", "")})

    # Process AFL and ARQC if GPO succeeds
    if sw1 == 0x90 and sw2 == 0x00:
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

        # Generate ARQC
        resp, sw1, sw2 = generate_arqc(connection)
        script.append({
            "apdu": toHexString(gen_ac_apdu).replace(" ", "").lower(),
            "response": toHexString(resp).replace(" ", "")
        })

    # Extract data from all responses
    iad = find_tag(parse_tlv(resp), "9F10")
    iad = iad[0] if iad else ""
    
    track2 = None
    country_code = None
    cvm_list = None
    ctq_data = None
    for record in script:
        try:
            record_tlv = parse_tlv(bytes.fromhex(record['response']))
            track2_values = find_tag(record_tlv, '57')
            country_values = find_tag(record_tlv, '5F28')
            cvm_values = find_tag(record_tlv, '8E')
            ctq_values = find_tag(record_tlv, '9F6C')
            
            if track2_values and not track2:
                track2 = track2_values[0]
            if country_values and not country_code:
                country_code = country_values[0]
            if cvm_values and not cvm_list:
                cvm_list = cvm_values[0]
            if ctq_values and not ctq_data:
                ctq_data = ctq_values[0]
        except Exception as e:
            print(f"Error parsing record: {e}")

    # Create output
    track2_prefix = track2[:6] if track2 else "notrack2"
    output = {
        "name": f"{app_label}_{track2_prefix}",
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

    # Save to file
    if not os.path.exists('dumps'):
        os.makedirs('dumps')
    filename = f"{track2 or 'notrack2'}_{aid}.json"
    filepath = os.path.join('dumps', filename)
    with open(filepath, 'w') as f:
        json.dump(output, f, indent=4, ensure_ascii=False)
    print(f"Output saved to: {filepath}")
    print(json.dumps(output, indent=4, ensure_ascii=False))

def main():
    connection = wait_for_card()
    if not connection:
        return
    script = []

    # Step 1: SELECT PPSE
    select_ppse = [0x00, 0xA4, 0x04, 0x00, 0x0E] + list(b"2PAY.SYS.DDF01") + [0x00]
    resp, sw1, sw2 = send_apdu(connection, select_ppse)
    script.append({"apdu": toHexString(select_ppse).replace(" ", "").lower(),
                   "response": toHexString(resp).replace(" ", "")})

    tlv = parse_tlv(resp)
    aids = extract_aids(tlv)
    if not aids:
        print("AID não encontrado na resposta da PPSE.")
        return

    for aid in aids:
        extractApplication(aid['aid'], aid['label'])

if __name__ == "__main__":
    main()