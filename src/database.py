import os
from supabase import create_client, Client

class ArgusDB:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        self.client: Client = create_client(url, key)

    def get_cve(self, cve_id):
        response = self.client.table("cves").select("*").eq("id", cve_id).execute()
        return response.data[0] if response.data else None

    def upsert_cve(self, data):
        self.client.table("cves").upsert(data).execute()

    def upload_report(self, cve_id, content):
        file_path = f"{cve_id}.html"
        bucket = "reports"
        
        # HTML 템플릿 (CSS 디자인 유지)
        html_template = f"""<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{cve_id} Analysis Report</title>
    <style>
        :root {{ --primary: #1e40af; --secondary: #3b82f6; --danger: #ef4444; --bg: #f8fafc; --text: #334155; }}
        body {{ font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, system-ui, Roboto, sans-serif; line-height: 1.6; background: var(--bg); color: var(--text); padding: 20px; max-width: 900px; margin: 0 auto; }}
        .header {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); border-left: 6px solid var(--primary); margin-bottom: 25px; }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 26px; color: #0f172a; }}
        .meta-tag {{ display: inline-block; background: #e2e8f0; padding: 4px 8px; border-radius: 4px; font-size: 13px; font-weight: 600; margin-right: 8px; color: #475569; }}
        .card {{ background: white; padding: 25px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); margin-bottom: 20px; }}
        .card-title {{ font-size: 18px; font-weight: 700; color: var(--primary); border-bottom: 2px solid #f1f5f9; padding-bottom: 12px; margin-bottom: 20px; }}
        .ai-table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        .ai-table th {{ width: 20%; background: #f8fafc; padding: 12px; text-align: left; color: #64748b; font-weight: 600; border-bottom: 1px solid #e2e8f0; vertical-align: top; }}
        .ai-table td {{ padding: 12px; border-bottom: 1px solid #e2e8f0; color: #334155; }}
        .mitigation-box {{ background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 20px; }}
        .badge {{ display: inline-flex; align-items: center; border-radius: 9999px; font-size: 12px; font-weight: 600; color: white; padding: 4px 10px; margin-right: 5px; }}
        .bg-red {{ background-color: var(--danger); }}
        .bg-orange {{ background-color: #f97316; }}
        .bg-green {{ background-color: #10b981; }}
        .bg-gray {{ background-color: #64748b; }}
        a {{ color: var(--secondary); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        li {{ margin-bottom: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        {content}
    </div>
</body>
</html>"""
        
        try:
            # UTF-8로 인코딩
            encoded_content = html_template.encode('utf-8')
            
            # [핵심] content-type을 text/html로 명시하여 업로드
            # upsert 옵션을 사용하여 기존 파일이 있으면 덮어씀
            self.client.storage.from_(bucket).upload(
                path=file_path, 
                file=encoded_content, 
                file_options={"content-type": "text/html", "upsert": "true"}
            )
        except Exception as e:
            # 혹시 모를 에러 로깅
            print(f"[WARN] Supabase Upload Error: {e}")
            pass
            
        return self.client.storage.from_(bucket).create_signed_url(file_path, 60 * 60 * 24 * 30)