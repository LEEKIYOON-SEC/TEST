from __future__ import annotations

import logging
from typing import List

from .logging_utils import setup_logging, get_logger
from .config import load_config
from .supabase_db import SupabaseDB
from .util.storageutil import storage_delete_if_exists

log = get_logger("argus.housekeeping")


def run_housekeeping() -> None:
    setup_logging()
    cfg = load_config()
    db = SupabaseDB(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)

    ok = False
    deleted_files = 0
    failed_files = 0
    deleted_rows = 0
    expired_count = 0

    try:
        # 1) 만료된 report_objects 조회 (뷰)
        expired = db.list_expired_report_objects()
        expired_count = len(expired)

        # 2) Storage 실제 파일 삭제
        #    - report_path / rules_zip_path 각각 삭제 시도
        #    - 실패해도 계속 진행(로그 남김)
        for row in expired:
            report_path = row.get("report_path")
            rules_path = row.get("rules_zip_path")

            if storage_delete_if_exists(db.sb, cfg.STORAGE_BUCKET, report_path):
                deleted_files += 1
            else:
                failed_files += 1

            if rules_path:
                if storage_delete_if_exists(db.sb, cfg.STORAGE_BUCKET, rules_path):
                    deleted_files += 1
                else:
                    failed_files += 1

        # 3) report_objects row 삭제 (만료 메타 정리)
        report_ids: List[str] = [r["report_id"] for r in expired if r.get("report_id")]
        if report_ids:
            db.delete_report_object_rows(report_ids)
            deleted_rows = len(report_ids)

        # 4) DB housekeeping 함수 실행 (CVE_state 정리 포함)
        #    - 주의: 이 함수는 report_objects도 삭제하지만,
        #      우리는 "파일 먼저 삭제"를 위해 2)~3) 후에 호출한다.
        db.run_housekeeping_db()

        ok = True
        db.log_run(
            "HOUSEKEEPING",
            True,
            f"expired={expired_count} deleted_rows={deleted_rows} deleted_files={deleted_files} failed_files={failed_files}",
        )
        log.info(
            "HOUSEKEEPING OK expired=%d deleted_rows=%d deleted_files=%d failed_files=%d",
            expired_count,
            deleted_rows,
            deleted_files,
            failed_files,
        )

    except Exception as e:
        db.log_run(
            "HOUSEKEEPING",
            False,
            f"failed: {e} expired={expired_count} deleted_rows={deleted_rows} deleted_files={deleted_files} failed_files={failed_files}",
        )
        raise


if __name__ == "__main__":
    run_housekeeping()
