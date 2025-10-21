#!/usr/bin/python3
import os

def patch_certificate(filename, certname) -> None:
    if not os.path.exists(filename):
        print(f"Didn't find {filename}, skipping patch certificate")
        return
    with open(filename, 'r+b') as f:
        data = f.read()
        start_index = data.find(bytes.fromhex('2D2D2D2D2D424547494E204345525449'))
        if start_index == -1:
            print(f"{filename} doesn't contain the root certificate.")
            return

        f.seek(start_index)
        if not os.path.exists(certname):
            print(f"Didn't find {certname}, skipping patch certificate")
            return
        
        with open(certname, 'rb') as cf:
            certificate = cf.read()
            f.write(certificate)

        patched_filename = f'{filename}'
        print(f'File {patched_filename} patched with the root certificate!')

patch_certificate('lumina_server', 'root_ca.cer')
