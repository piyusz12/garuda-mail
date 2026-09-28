from typing import List, Tuple, Dict
from app.config import OverlapPolicy
from app.reassembly.overlap_policy import resolve_overlap
from app.logger import logger
from app.models.session import GapRecord

class SequenceBuffer:
    def __init__(self, policy: OverlapPolicy):
        # Maps start sequence to (data_bytes, length)
        self.segments: Dict[int, bytes] = {}
        self.policy = policy
        self.retransmissions = 0
        self.overlaps = 0
        self.gaps: List[GapRecord] = []
        self.initial_seq = None

    def add_segment(self, seq: int, data: bytes):
        if not data:
            return

        length = len(data)
        if self.initial_seq is None:
            self.initial_seq = seq

        # Check for retransmission
        if seq in self.segments and self.segments[seq] == data:
            self.retransmissions += 1
            return
            
        # Check for overlap at the exact same sequence number but different data
        if seq in self.segments:
            self.overlaps += 1
            logger.debug("OVERLAP_DETECTED", seq=seq, length=length, policy=self.policy.value)
            self.segments[seq] = resolve_overlap(self.segments[seq], data, self.policy)
            return

        # It might overlap partially with an existing segment. We need to handle that during reassembly.
        # For now, just store it by sequence number.
        self.segments[seq] = data

    def reassemble(self) -> Tuple[bytes, bool]:
        """
        Merges segments, detects gaps and partial overlaps.
        Returns the merged stream and a boolean indicating if it's gap-free.
        """
        if not self.segments:
            return b"", True
            
        # Sort by sequence number
        sorted_seqs = sorted(self.segments.keys())
        
        merged_stream = bytearray()
        expected_seq = sorted_seqs[0]
        
        self.gaps = []
        
        for seq in sorted_seqs:
            data = self.segments[seq]
            length = len(data)
            
            if seq > expected_seq:
                # GAP detected
                gap_len = seq - expected_seq
                self.gaps.append(GapRecord(start_seq=expected_seq, end_seq=seq, length=gap_len))
                logger.debug("GAP_DETECTED", start_seq=expected_seq, end_seq=seq, length=gap_len)
                # Pad with null bytes or just append the next segment?
                # Usually we just append what we have, but logically there is a gap.
                merged_stream.extend(data)
                expected_seq = seq + length
                
            elif seq < expected_seq:
                # PARTIAL OVERLAP (seq is before expected_seq)
                overlap_len = expected_seq - seq
                if overlap_len < length:
                    # New data extends beyond the expected seq
                    self.overlaps += 1
                    logger.debug("PARTIAL_OVERLAP_DETECTED", seq=seq, expected_seq=expected_seq)
                    
                    if self.policy == OverlapPolicy.LAST_WINS:
                        # Overwrite the end of the existing stream
                        merged_stream = merged_stream[:-overlap_len]
                        merged_stream.extend(data)
                    else: # FIRST_WINS
                        # Only append the non-overlapping part
                        merged_stream.extend(data[overlap_len:])
                        
                    expected_seq = seq + length
                else:
                    # Completely contained within existing stream
                    self.overlaps += 1
                    logger.debug("CONTAINED_OVERLAP_DETECTED", seq=seq)
                    if self.policy == OverlapPolicy.LAST_WINS:
                        # Find the start index in the merged stream
                        start_idx = len(merged_stream) - (expected_seq - seq)
                        merged_stream[start_idx:start_idx+length] = data
            else:
                # PERFECT ALIGNMENT (seq == expected_seq)
                merged_stream.extend(data)
                expected_seq = seq + length
                
        is_complete = len(self.gaps) == 0
        return bytes(merged_stream), is_complete
