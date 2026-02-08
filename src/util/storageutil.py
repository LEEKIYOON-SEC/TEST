from __future__ import annotations

import logging
from typing import Optional

log = logging.getLogger("argus.storageutil")


def storage_delete_if_exists(sb, bucket: str, path: Optional[str]) -> bool:
    """
    Supabase Storage에서 단일 object 삭제(존재하지 않아도 실패로 치지 않음).
    반환: 삭제 요청 성공 여부(존재 유무까지 100% 보장하진 않지만, 운영상 충분)
    """
    if not path:
        return True
    try:
        storage = sb.storage.from_(bucket)
        # storage.remove 는 배열을 받는다
        storage.remove([path])
        log.info("Storage removed: %s/%s", bucket, path)
        return True
    except Exception as e:
        # Storage remove가 실패해도 전체 housekeeping을 중단하면 오히려 누수/정리 실패가 확대될 수 있어
        # 실패를 로그로 남기고 계속 진행하는 것이 운영적으로 안전.
        log.warning("Storage remove failed for %s/%s: %s", bucket, path, e)
        return False
