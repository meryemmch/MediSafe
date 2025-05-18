import shutil
from fastapi import UploadFile

def save_file(upload_file: UploadFile, destination: str):
    with open(destination, "wb") as buffer:
        shutil.copyfileobj(upload_file.file, buffer)
