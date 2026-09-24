import struct
from typing import List, Optional

from app.models.tls_metadata import TLSMetadata
from app.tls.x509_parser import X509Parser
from app.tls.ja4 import generate_ja4_client, generate_ja4_server
from app.logger import logger

class TLSParser:
    def __init__(self, stream: bytes, offset: int = 0):
        self.stream = stream
        self.offset = offset
        self.meta = TLSMetadata()
        
    def _read_bytes(self, length: int) -> Optional[bytes]:
        if self.offset + length > len(self.stream):
            return None
        data = self.stream[self.offset : self.offset + length]
        self.offset += length
        return data

    def parse(self) -> TLSMetadata:
        while self.offset < len(self.stream):
            # TLS Record Header (5 bytes)
            record_header = self._read_bytes(5)
            if not record_header:
                break
                
            content_type, version, length = struct.unpack(">BHH", record_header)
            
            if content_type != 22: # Not Handshake
                self.offset += length
                continue
                
            # Parse Handshake Layer
            hs_data = self._read_bytes(length)
            if not hs_data:
                break
                
            self._parse_handshake(hs_data)
            
        return self.meta
        
    def _parse_handshake(self, hs_data: bytes):
        hs_offset = 0
        while hs_offset < len(hs_data):
            if hs_offset + 4 > len(hs_data):
                break
                
            hs_type = hs_data[hs_offset]
            hs_len = struct.unpack(">I", b'\x00' + hs_data[hs_offset+1:hs_offset+4])[0]
            hs_offset += 4
            
            msg_data = hs_data[hs_offset : hs_offset + hs_len]
            hs_offset += hs_len
            
            if hs_type == 1: # ClientHello
                self._parse_client_hello(msg_data)
            elif hs_type == 2: # ServerHello
                self._parse_server_hello(msg_data)
            elif hs_type == 11: # Certificate
                self._parse_certificate(msg_data)

    def _parse_client_hello(self, data: bytes):
        if len(data) < 34: return
        version = struct.unpack(">H", data[0:2])[0]
        self.meta.client_version = f"0x{version:04x}"
        
        # Skip Random (32)
        ptr = 34
        
        # Skip Session ID
        if ptr >= len(data): return
        sess_len = data[ptr]
        ptr += 1 + sess_len
        
        # Cipher Suites
        if ptr + 2 > len(data): return
        cs_len = struct.unpack(">H", data[ptr:ptr+2])[0]
        ptr += 2
        
        ciphers = []
        for i in range(0, cs_len, 2):
            if ptr + i + 2 > len(data): break
            c = struct.unpack(">H", data[ptr+i:ptr+i+2])[0]
            ciphers.append(c)
            self.meta.cipher_suites_offered.append(f"0x{c:04x}")
            
        ptr += cs_len
        
        # Skip Compression Methods
        if ptr >= len(data): return
        comp_len = data[ptr]
        ptr += 1 + comp_len
        
        # Extensions
        extensions = []
        if ptr + 2 <= len(data):
            ext_tot_len = struct.unpack(">H", data[ptr:ptr+2])[0]
            ptr += 2
            end = ptr + ext_tot_len
            
            while ptr < end and ptr + 4 <= len(data):
                ext_type, ext_len = struct.unpack(">HH", data[ptr:ptr+4])
                ptr += 4
                extensions.append(ext_type)
                self.meta.extensions_offered.append(ext_type)
                
                # Parse specific extensions
                if ext_type == 0: # SNI
                    self._parse_sni(data[ptr:ptr+ext_len])
                elif ext_type == 16: # ALPN
                    self._parse_alpn_client(data[ptr:ptr+ext_len])
                    
                ptr += ext_len
                
        self.meta.ja4.ja4 = generate_ja4_client(version, ciphers, extensions, self.meta.sni, self.meta.alpn_offered)

    def _parse_server_hello(self, data: bytes):
        if len(data) < 34: return
        version = struct.unpack(">H", data[0:2])[0]
        self.meta.server_version = f"0x{version:04x}"
        
        ptr = 34
        if ptr >= len(data): return
        sess_len = data[ptr]
        ptr += 1 + sess_len
        
        if ptr + 2 > len(data): return
        cipher = struct.unpack(">H", data[ptr:ptr+2])[0]
        self.meta.cipher_suite_selected = f"0x{cipher:04x}"
        ptr += 2
        
        # Skip Compression Method (1)
        ptr += 1
        
        extensions = []
        if ptr + 2 <= len(data):
            ext_tot_len = struct.unpack(">H", data[ptr:ptr+2])[0]
            ptr += 2
            end = ptr + ext_tot_len
            
            while ptr < end and ptr + 4 <= len(data):
                ext_type, ext_len = struct.unpack(">HH", data[ptr:ptr+4])
                ptr += 4
                extensions.append(ext_type)
                if ext_type == 16: # ALPN selected
                     self._parse_alpn_server(data[ptr:ptr+ext_len])
                ptr += ext_len
                
        self.meta.ja4.ja4s = generate_ja4_server(version, cipher, extensions)

    def _parse_certificate(self, data: bytes):
        # TLS 1.2 Certificate message structure:
        # Certificates Length (3 bytes)
        # Certificate List
        if len(data) < 3: return
        list_len = struct.unpack(">I", b'\x00' + data[0:3])[0]
        ptr = 3
        
        end = ptr + list_len
        while ptr < end and ptr + 3 <= len(data):
            cert_len = struct.unpack(">I", b'\x00' + data[ptr:ptr+3])[0]
            ptr += 3
            
            if ptr + cert_len > len(data):
                break
                
            cert_bytes = data[ptr:ptr+cert_len]
            parsed_cert = X509Parser.parse_der(cert_bytes)
            if parsed_cert:
                self.meta.certificates.append(parsed_cert)
                
            ptr += cert_len

    def _parse_sni(self, data: bytes):
        if len(data) < 5: return
        # List length (2), Name Type (1), Name Length (2)
        name_len = struct.unpack(">H", data[3:5])[0]
        if 5 + name_len <= len(data):
            self.meta.sni = data[5:5+name_len].decode('ascii', errors='ignore')
            
    def _parse_alpn_client(self, data: bytes):
        if len(data) < 2: return
        ptr = 2
        while ptr < len(data):
            str_len = data[ptr]
            ptr += 1
            if ptr + str_len <= len(data):
                self.meta.alpn_offered.append(data[ptr:ptr+str_len].decode('ascii', errors='ignore'))
            ptr += str_len
            
    def _parse_alpn_server(self, data: bytes):
        if len(data) < 2: return
        str_len = data[2]
        if 3 + str_len <= len(data):
            self.meta.alpn_selected = data[3:3+str_len].decode('ascii', errors='ignore')
