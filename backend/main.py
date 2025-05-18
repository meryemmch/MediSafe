import base64
from datetime import timedelta
import uuid
import os

from fastapi import FastAPI, Depends, Request, Response, UploadFile, File, Form, HTTPException,status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
#from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
#from backend.auth import ACCESS_TOKEN_EXPIRE_MINUTES, authenticate_user, create_access_token, get_current_active_user
from backend.models import Base, Report, User, UserRole, EncryptedImage
from backend.database import SessionLocal, engine
from pathlib import Path


# Initialize DB
Base.metadata.create_all(bind=engine)


app = FastAPI()


# Dependency to get DB

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

'''
@app.post("/token")
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }
'''

# Mount static folders
app.mount("/radiologist/static", StaticFiles(directory="frontend/radiologist"), name="radiologist_static")
app.mount("/doctor/static", StaticFiles(directory="frontend/doctor"), name="doctor_static")
app.mount("/patient/static", StaticFiles(directory="frontend/patient"), name="patient_static")
app.mount("/static", StaticFiles(directory="frontend/assets"), name="static")


# Serve login/register pages
@app.get("/", response_class=HTMLResponse)
async def login_page():
    return FileResponse("frontend/login.html")

@app.get("/register", response_class=HTMLResponse)
async def register_page():
    return FileResponse("frontend/register.html")

# Register endpoint
@app.post("/register/")
async def register_user(
    username: str = Form(...),
    email: str = Form(...),
    hashed_password: str = Form(...),
    hashed_aes_key: str = Form(...),
    salt: str = Form(...),
    role: str = Form(...),
    public_key: str = Form(...),
    db: Session = Depends(get_db)
):
    if db.query(User).filter((User.username == username) | (User.email == email)).first():
        raise HTTPException(status_code=400, detail="Username or email already exists.")

    user = User(
        user_id=str(uuid.uuid4()),
        username=username,
        email=email,
        hashed_password=hashed_password,
        hashed_aes_key=hashed_aes_key,
        salt=salt,
        role=UserRole(role),
        public_key=public_key,
    )
    db.add(user)
    db.commit()
    return RedirectResponse(url="/", status_code=302)

# Login endpoint
@app.post("/login")
async def login(username: str = Form(...), password_hash: str = Form(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user or user.hashed_password != password_hash:
        return JSONResponse(content={"message": "Invalid credentials"}, status_code=401)
    return JSONResponse(content={"message": "Login successful", "role": user.role.value})

# Role-based main pages
@app.get("/radiologist/", response_class=HTMLResponse)
async def serve_radiologist():
    return FileResponse("frontend/radiologist/index.html")

@app.get("/doctor/", response_class=HTMLResponse)
async def serve_doctor():
    return FileResponse("frontend/doctor/index.html")

@app.get("/patient/", response_class=HTMLResponse)
async def serve_patient():
    return FileResponse("frontend/patient/index.html")

@app.get("/favicon.ico", response_class=Response)
async def favicon():
    return Response(status_code=204)


@app.get("/users/public-key/{username}", response_class=PlainTextResponse)
async def get_public_key(username: str):
    db: Session = SessionLocal()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user.public_key  # should be PEM format string

# Upload image
SECURE_STORAGE_DIR = "backend/secure_storage/encrypted_images"

# Utility to save the encrypted image as a .enc file
def save_encrypted_image(encrypted_data: str, file_name: str) -> str:
    if not os.path.exists(SECURE_STORAGE_DIR):
        os.makedirs(SECURE_STORAGE_DIR)  # Create directory if not exists
    file_path = os.path.join(SECURE_STORAGE_DIR, file_name)
    
    # Decode the encrypted image from base64 and save it to the file
    with open(file_path, 'wb') as f:
        f.write(base64.b64decode(encrypted_data))  # Convert from base64 to binary data
    
    return file_path

from pydantic import BaseModel

class UploadImageRequest(BaseModel):
    encrypted_image: str
    salt: str
    original_filename: str
    encrypted_aes_key: str
    doctor_username: str
    patient_username: str

@app.post("/upload-image/")
async def upload_image(
    payload: UploadImageRequest,
    db: Session = Depends(get_db),
):
    # Extract data from payload
    encrypted_image = payload.encrypted_image
    salt = payload.salt
    original_filename = payload.original_filename
    encrypted_aes_key = payload.encrypted_aes_key
    doctor_username = payload.doctor_username
    patient_username = payload.patient_username

    # Fetch doctor
    doctor = db.query(User).filter(User.username == doctor_username).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found.")

    # Fetch patient
    patient = db.query(User).filter(User.username == patient_username).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found.")

    # Save the encrypted image
    unique_filename = f"{uuid.uuid4().hex}_{original_filename}.enc"
    try:
        file_path = save_encrypted_image(encrypted_image, unique_filename)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to save image: {str(e)}")

    # Save metadata to DB
    image_record = EncryptedImage(
        encrypted_filename=unique_filename,
        salt=salt,
        encrypted_aes_key=encrypted_aes_key,
        doctor_id=doctor.user_id,
        patient_id=patient.user_id
    )

    db.add(image_record)
    db.commit()
    db.refresh(image_record)

    return {"message": "Image uploaded successfully.", "image_id": image_record.image_id}

@app.get("/get-encrypted-images/{doctor_username}")
def get_encrypted_images(doctor_username: str, db: Session = Depends(get_db)):
    doctor = db.query(User).filter(
        User.username == doctor_username,
        User.role == UserRole.doctor
    ).first()
    if not doctor:
        raise HTTPException(status_code=404, detail="Doctor not found")

    images = db.query(EncryptedImage).filter(EncryptedImage.doctor_id == doctor.user_id).all()

    image_data_list = []
    for image in images:
        patient = db.query(User).filter(User.user_id == image.patient_id).first()
        if not patient:
            continue

        file_path = os.path.join(SECURE_STORAGE_DIR, image.encrypted_filename)
        if not os.path.exists(file_path):
            continue

        with open(file_path, "rb") as f:
            encoded_content = base64.b64encode(f.read()).decode("utf-8")

        image_data_list.append({
           "image_id": image.image_id,  # assuming this field exists
           "patient_username": patient.username,
           "encrypted_aes_key": image.encrypted_aes_key,
            "salt": image.salt,
           "base64_file": encoded_content
        })

    return image_data_list

@app.get("/get-patient-reports/{patient_username}")
def get_patient_reports(patient_username: str, db: Session = Depends(get_db)):
    patient = db.query(User).filter(
        User.username == patient_username,
        User.role == UserRole.patient
    ).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    reports = db.query(Report).filter(Report.patient_id == patient.user_id).all()

    report_data_list = []
    for report in reports:
        doctor = db.query(User).filter(User.user_id == report.doctor_id).first()
        if not doctor:
            continue

        file_path = os.path.join(SECURE_STORAGE_DIR1, report.encrypted_filename)
        if not os.path.exists(file_path):
            continue

        with open(file_path, "rb") as f:
            encoded_content = base64.b64encode(f.read()).decode("utf-8")

        report_data_list.append({
            "report_id": report.report_id,
            "doctor_username": doctor.username,
            "encrypted_aes_key": report.encrypted_aes_key,
            "salt": report.salt,
            "base64_file": encoded_content,
            "original_filename": report.encrypted_filename ,
            "iv":report.iv
        })

    return report_data_list


# ----------- POST upload encrypted report file -----------
SECURE_STORAGE_DIR1="backend/secure_storage/encrypted_reports"

class ReportUploadRequest(BaseModel):
    iv:str
    doctor_username: str
    patient_username: str
    filename: str
    encrypted_aes_key: str
    salt: str
    encrypted_report: str  # base64 or encrypted string

@app.post("/upload_report")
async def upload_report(data: ReportUploadRequest):
    db: Session = SessionLocal()
    try:
        doctor = db.query(User).filter(User.username == data.doctor_username, User.role == UserRole.doctor).first()
        patient = db.query(User).filter(User.username == data.patient_username, User.role == UserRole.patient).first()

        if not doctor or not patient:
            raise HTTPException(status_code=404, detail="Doctor or patient not found")

        # Save encrypted report file
        unique_filename = f"{uuid.uuid4()}_{data.filename}"
        file_path = os.path.join(SECURE_STORAGE_DIR1, unique_filename)
        with open(file_path, "w") as f:  # write encrypted string
            f.write(data.encrypted_report)

        # Store metadata in DB
        new_report = Report(
            report_id=str(uuid.uuid4()),
            iv=data.iv,
            doctor_id=doctor.user_id,
            patient_id=patient.user_id,
            encrypted_filename=unique_filename,
            encrypted_aes_key=data.encrypted_aes_key,
            salt=data.salt
        )
        db.add(new_report)
        db.commit()

        return JSONResponse({"detail": "Report uploaded successfully", "report_id": new_report.report_id})
    finally:
        db.close()
