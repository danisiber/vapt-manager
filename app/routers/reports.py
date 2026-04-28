from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from app.services.report import generate_project_report
import tempfile, os

router = APIRouter(prefix="/api/reports", tags=["reports"])

@router.get("/project/{project_id}/pdf")
def download_report(project_id: int):
    import uuid
    output_path = f"/tmp/vapt_report_{project_id}_{uuid.uuid4().hex}.pdf"
    try:
        path = generate_project_report(project_id, output_path)
        response = FileResponse(
            path,
            media_type="application/pdf",
            filename=f"vapt_report_project_{project_id}.pdf"
        )
        # Schedule file deletion after response is sent
        import threading
        def cleanup():
            import time
            time.sleep(5)
            try:
                import os
                if os.path.exists(path):
                    os.unlink(path)
            except Exception:
                pass
        threading.Thread(target=cleanup, daemon=True).start()
        return response
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gagal generate PDF: {str(e)}")
