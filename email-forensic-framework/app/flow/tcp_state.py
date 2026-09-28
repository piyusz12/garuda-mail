from enum import Enum
from typing import List, Tuple

class TCPState(str, Enum):
    NEW = "NEW"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSING = "CLOSING"
    TIME_WAIT = "TIME_WAIT"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    CLOSED = "CLOSED"
    RST_SEEN = "RST_SEEN"

class TCPStateMachine:
    """Tracks state of a TCP connection based on observed flags"""
    def __init__(self):
        self.state = TCPState.NEW
        self.termination_reason = "NONE"
        self.client_closed = False
        self.server_closed = False
        self.last_update = 0

    def process_flags(self, is_client: bool, is_syn: bool, is_ack: bool, is_fin: bool, is_rst: bool):
        if is_rst:
            self.state = TCPState.RST_SEEN
            self.termination_reason = "RST"
            return
            
        if self.state == TCPState.NEW:
            if is_syn and not is_ack:
                self.state = TCPState.SYN_SENT
        elif self.state == TCPState.SYN_SENT:
            if is_syn and is_ack and not is_client:
                self.state = TCPState.SYN_RECV
            elif is_syn and not is_ack:
                # Simultaneous open or retransmission
                pass
        elif self.state == TCPState.SYN_RECV:
            if is_ack and not is_syn and is_client:
                self.state = TCPState.ESTABLISHED
        elif self.state == TCPState.ESTABLISHED:
            if is_fin:
                if is_client:
                    self.state = TCPState.FIN_WAIT_1
                    self.client_closed = True
                else:
                    self.state = TCPState.CLOSE_WAIT
                    self.server_closed = True
        elif self.state == TCPState.FIN_WAIT_1:
            if is_fin and not is_client:
                self.state = TCPState.CLOSING
                self.server_closed = True
            elif is_ack and not is_client:
                self.state = TCPState.FIN_WAIT_2
        elif self.state == TCPState.FIN_WAIT_2:
            if is_fin and not is_client:
                self.state = TCPState.TIME_WAIT
                self.server_closed = True
        elif self.state == TCPState.CLOSE_WAIT:
            if is_fin and not is_client:
                self.state = TCPState.LAST_ACK
                self.server_closed = True
        elif self.state == TCPState.LAST_ACK:
            if is_ack and is_client:
                self.state = TCPState.CLOSED
                self.termination_reason = "FIN"
        elif self.state == TCPState.CLOSING:
            if is_ack:
                self.state = TCPState.TIME_WAIT
        elif self.state == TCPState.TIME_WAIT:
            # Technically TIME_WAIT needs a timer, but for offline PCAP we might see nothing else
            pass
            
        if self.client_closed and self.server_closed and self.state not in (TCPState.CLOSED, TCPState.TIME_WAIT):
             if is_ack:
                  self.state = TCPState.CLOSED
                  self.termination_reason = "FIN"
