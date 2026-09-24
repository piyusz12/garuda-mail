import hashlib
from typing import List

# TLS Version mappings for JA4
TLS_VERSIONS = {
    0x0300: 's3', # SSL 3.0
    0x0301: '10', # TLS 1.0
    0x0302: '11', # TLS 1.1
    0x0303: '12', # TLS 1.2
    0x0304: '13', # TLS 1.3
}

def _hash_sha256_trunc12(data: str) -> str:
    """Returns the first 12 characters of the SHA256 hash"""
    return hashlib.sha256(data.encode('ascii')).hexdigest()[:12]

def generate_ja4_client(version: int, ciphers: List[int], extensions: List[int], sni: str = None, alpn: List[str] = None) -> str:
    """
    Generates the JA4 client fingerprint.
    Format: Protocol+TLSVersion+SNI+CiphersCount+ExtensionsCount_CiphersHash_ExtensionsHash
    (Simplified JA4 for prototype context)
    """
    # 1. Transport/Protocol
    t_proto = 't' # TCP
    
    # 2. TLS Version
    t_vers = TLS_VERSIONS.get(version, '00')
    
    # 3. SNI
    t_sni = 'd' if sni else 'i' # 'd' for domain, 'i' for ip/none
    
    # 4. Counts
    # We ignore GREASE values (0x?A?A) in actual JA4, but we'll do a simple count here
    clean_ciphers = [c for c in ciphers if (c & 0x0f0f) != 0x0a0a]
    clean_exts = [e for e in extensions if (e & 0x0f0f) != 0x0a0a]
    
    t_ciphers_len = f"{len(clean_ciphers):02d}"
    t_exts_len = f"{len(clean_exts):02d}"
    
    ja4_a = f"{t_proto}{t_vers}{t_sni}{t_ciphers_len}{t_exts_len}"
    
    # 5. Ciphers Hash (sorted hex, comma separated)
    ciphers_hex = [f"{c:04x}" for c in sorted(clean_ciphers)]
    ciphers_str = ",".join(ciphers_hex)
    ja4_b = _hash_sha256_trunc12(ciphers_str) if ciphers_hex else "000000000000"
    
    # 6. Extensions Hash (sorted hex, comma separated, ignoring SNI and ALPN for the hash in full JA4, but we keep it simple here)
    exts_hex = [f"{e:04x}" for e in sorted(clean_exts)]
    exts_str = ",".join(exts_hex)
    ja4_c = _hash_sha256_trunc12(exts_str) if exts_hex else "000000000000"
    
    return f"{ja4_a}_{ja4_b}_{ja4_c}"

def generate_ja4_server(version: int, cipher: int, extensions: List[int]) -> str:
    """
    Generates the JA4S server fingerprint.
    Format: Protocol+TLSVersion+ExtensionsCount_CipherHash_ExtensionsHash
    """
    t_proto = 't'
    t_vers = TLS_VERSIONS.get(version, '00')
    
    clean_exts = [e for e in extensions if (e & 0x0f0f) != 0x0a0a]
    t_exts_len = f"{len(clean_exts):02d}"
    
    ja4s_a = f"{t_proto}{t_vers}{t_exts_len}"
    
    # Cipher Hash
    cipher_str = f"{cipher:04x}"
    ja4s_b = _hash_sha256_trunc12(cipher_str)
    
    # Extensions Hash
    exts_hex = [f"{e:04x}" for e in sorted(clean_exts)]
    exts_str = ",".join(exts_hex)
    ja4s_c = _hash_sha256_trunc12(exts_str) if exts_hex else "000000000000"
    
    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"
