from app.config import OverlapPolicy

def resolve_overlap(existing_data: bytes, new_data: bytes, policy: OverlapPolicy) -> bytes:
    """
    Resolves overlap between two byte arrays based on the policy.
    This function is called when a new segment overlaps exactly with an existing segment.
    """
    if policy == OverlapPolicy.FIRST_WINS:
        return existing_data
    elif policy == OverlapPolicy.LAST_WINS:
        return new_data
    else:
        return existing_data # Default
