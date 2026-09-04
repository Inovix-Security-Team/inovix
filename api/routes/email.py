from fastapi import APIRouter, UploadFile, File, HTTPException

router = APIRouter()


@router.post("/analyze")
async def analyze_email(file: UploadFile = File(...)):
    # Check file was provided
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No file provided"
        )

    # Only allow .eml files
    if not file.filename.lower().endswith(".eml"):
        raise HTTPException(
            status_code=400,
            detail="Only .eml files are supported"
        )

    # Read uploaded file
    contents = await file.read()

    # Check empty file
    if not contents:
        raise HTTPException(
            status_code=400,
            detail="The .eml file is empty"
        )

    return {
        "message": "Email analysis endpoint working",
        "filename": file.filename,
        "size": len(contents)
    }