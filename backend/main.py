from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from typing import Optional
import shutil
import os
import math
import pandas as pd
import psycopg2.extras
import jwt
import datetime
import bcrypt
from sqlalchemy.orm import Session
from pydantic import BaseModel

# Local imports
import models
from database import engine, get_db, get_db_connection
from log_parser import parse_zscaler_log
from ml_engine import analyze_for_anomalies

# Initialize the Database tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="SOC Dashboard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# AUTHENTICATION SETUP
# ==========================================
SECRET_KEY = "your-super-secret-soc-key"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def get_password_hash(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.InvalidTokenError:
        raise credentials_exception
        
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user

# ==========================================
#  PUBLIC API ENDPOINTS
# ==========================================
@app.post("/api/signup")
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = models.User(email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User created successfully"}

@app.post("/api/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    access_token = create_access_token(data={"sub": str(db_user.id)})
    return {"access_token": access_token, "token_type": "bearer", "email": db_user.email}

# ==========================================
#  SECURE SOC ENDPOINTS
# ==========================================
@app.post("/api/upload")
async def upload_logs(
    file: UploadFile = File(...), 
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_path = f"temp_{file.filename}"
    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        df = parse_zscaler_log(file_path)
        if df.empty:
            raise HTTPException(status_code=400, detail="No valid logs found in the file.")

        df = analyze_for_anomalies(df)

        # 1. Create the History Record in SQLAlchemy
        total_rows = len(df)
        total_anomalies = int(df['is_anomaly'].sum()) if 'is_anomaly' in df.columns else 0
        
        new_upload = models.UploadHistory(
            filename=file.filename,
            total_events=total_rows,
            anomalies_found=total_anomalies,
            user_id=current_user.id
        )
        db.add(new_upload)
        db.commit()
        db.refresh(new_upload)

        # 2. Insert the actual logs with the new upload_id attached
        conn = get_db_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection failed.")
            
        cursor = conn.cursor()
        inserted_count = 0
        
        for _, row in df.iterrows():
            if pd.isna(row['log_time']) or row['log_time'] is None:
                continue 
                
            cursor.execute("""
                INSERT INTO logs (
                    log_time, user_login, source_ip, url, action, 
                    bytes_sent, bytes_received, threat_name, 
                    is_anomaly, confidence_score, ai_explanation, 
                    user_id, upload_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                row['log_time'], row['user_login'], row['source_ip'], 
                row['url'], row['action'], row['bytes_sent'], row['bytes_received'], 
                row['threat_name'], bool(row.get('is_anomaly', False)), 
                row.get('confidence_score', None), row.get('ai_explanation', None),
                current_user.id, 
                new_upload.id
            ))
            inserted_count += 1
            
        conn.commit()
        cursor.close()
        conn.close()
        
        return {
            "message": f"Success! Parsed, analyzed, and saved {inserted_count} logs.",
            "upload_id": new_upload.id
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


# NEW ENDPOINT: Get Upload History

@app.get("/api/history")
def get_upload_history(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Fetches the history of all files uploaded by this user."""
    history = db.query(models.UploadHistory).filter(models.UploadHistory.user_id == current_user.id).order_by(models.UploadHistory.upload_date.desc()).all()
    return history

@app.get("/api/logs")
def get_logs(
    upload_id: Optional[int] = None,
    current_user: models.User = Depends(get_current_user)
):
    """Fetches logs for the logged-in user, optionally filtered by a specific upload."""
    try:
        conn = get_db_connection()
        if not conn:
            raise HTTPException(status_code=500, detail="Database connection failed.")
            
        cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        
        if upload_id:
            cursor.execute("""
                SELECT * FROM logs 
                WHERE user_id = %s AND upload_id = %s
                ORDER BY log_time DESC;
            """, (current_user.id, upload_id))
        else:
            cursor.execute("""
                SELECT * FROM logs 
                WHERE user_id = %s
                ORDER BY log_time DESC 
                LIMIT 200;
            """, (current_user.id,))
            
        logs = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        sanitized_logs = []
        for row in logs:
            row_dict = dict(row)
            
            for key, value in row_dict.items():
                if isinstance(value, float) and math.isnan(value):
                    row_dict[key] = None
            
            if row_dict.get('source_ip'):
                row_dict['source_ip'] = str(row_dict['source_ip'])
            if row_dict.get('dest_ip'):
                row_dict['dest_ip'] = str(row_dict['dest_ip'])
                
            if row_dict.get('log_time'):
                row_dict['log_time'] = str(row_dict['log_time'])
            if row_dict.get('created_at'):
                row_dict['created_at'] = str(row_dict['created_at'])
                
            sanitized_logs.append(row_dict)
            
        return sanitized_logs
        
    except Exception as e:
        print(f"Error in GET /api/logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # This loop keeps the Docker container running!
    uvicorn.run("main:app", host="0.0.0.0", port=8000)