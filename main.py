import os
import random
import asyncio
from http.client import responses
import base64
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body
from dotenv import load_dotenv
import asyncpg
import shutil
from datetime import datetime
from email.message import EmailMessage
import aiosmtplib
from fastapi.middleware.cors import CORSMiddleware
from auth import *
from pydantic import BaseModel, with_config

load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
#
@app.on_event("startup")
async def startup():
    print("Server started, endpoints loaded")
    app.state.pool = await asyncpg.create_pool(
        dsn=DATABASE_URL,
        statement_cache_size=0
    )

@app.on_event("shutdown")
async def shutdown():
    await app.state.pool.close()

@app.get("/")
async def root():
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT now() AS current_time;")
        return {"db_time": row["current_time"]}

@app.get("/hello/{name}")
async def say_hello(name: str):
    return {"message": f"Hellooo {name}"}


# @app.post("/signup", response_model=Token)
# def signup(data : dict):
#     username = data.get("username")
#     email = data.get("email")
#     password = data.get("password")
#     if not user:
#         raise HTTPException(status_code=401, detail="Invalid credentials")
#     access_token = create_access_token(data={"sub": user["username"]})
#     return {"access_token": access_token, "token_type": "bearer"}


class SignupRequest(BaseModel):
    username : str
    password : str
    email : str

@app.post("/signup")
async def signup(data : SignupRequest):
    print(data)
    username = data["username"]
    password = data["password"]
    email = data["email"]

    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id from users where username = $1 or email = $2", username, email)
        if row:
            return {"message": "User already exists", "status" : False}
        else :
            hashed_pw = get_password_hash(password)
            insert_row = await conn.fetchrow("INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id", username, email, hashed_pw)
            print(insert_row['id'])

            token = create_access_token({"id": insert_row['id']}, expires_delta=timedelta(minutes=30))
            print("Token: ", token)

            return {"message": "User created", "status" : True, "token": token}

@app.put("/update_user")
async def update_user(
    id: int = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    phone: str = Form(...),
    gender: str = Form(...),
    role: str = Form(...),
    picture: UploadFile = File(...),
    result: dict = Depends(verify_jwt_token)
):

    image_bytes = await picture.read()

    file_ext = os.path.splitext(picture.filename)[1]  # keep .jpg/.png
    filename = f"user_{id}_{datetime.now().strftime('%Y%m%d%H%M%S')}{file_ext}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(picture.file, buffer)
    query = """
        UPDATE users
        SET first_name = $1,
            last_name = $2,
            phone = $3,
            gender = $4,
            picture = $5,
            role = $6
        WHERE id = $7
        RETURNING id
    """
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow(
            query,
            first_name,
            last_name,
            phone,
            gender,
            image_bytes,
            role,
            id
        )
    if row:
        return {"message": "User updated", "id": row["id"]}
    else:
        return {"message": "User not found"}




class LoginRequest(BaseModel):
    email : str
    username: str
    password: str


@app.post("/login")
async def login(data :LoginRequest):
    """
    ใช้ username หรือ email + password เพื่อเข้าสู่ระบบ
    - ถ้า `username` มีค่า → ระบบจะเช็ค username
    - ถ้า `email` มีค่า → ระบบจะเช็ค email
    - {
    "username" : "username",
    "email" : "",
    "password" : "password"
    }
    - {
    "username" : "",
    "email" : "email",
    "password" : "password"
    }
    """

    print(data)
    username = data.username
    email = data.email
    password = data.password

    if username != "" :
        print(username)
        async with app.state.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id, username, password FROM users WHERE username = $1", username)
            if row:
                # print(row[0]['username'])
                is_correct_password  = verify_password(password, row["password"])
                if is_correct_password:
                    token = create_access_token({"id" : row["id"]}, expires_delta=timedelta(minutes=30))
                    return {"token" : token, "status": True}
                else:
                    return {"message" : "Incorrect Password", "status" : False}
            else:
                return {"message": "User not found", "status" : False}
    elif email != "" :
        print(email)
        async with app.state.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT id, email, password FROM users WHERE email = $1", email)
            if row:
                # print(row[0]['username'])
                is_correct_password  = verify_password(password, row["password"])
                if is_correct_password:
                    token = create_access_token({"id" : row["id"]}, expires_delta=timedelta(minutes=30))
                    return {"token" : token, "status": True}
                else:
                    return {"message" : "Incorrect Password", "status" : False}
            else:
                return {"message": "Email not found", "status" : False}




@app.get("/verify-token")
async def verify_token(result: dict = Depends(verify_jwt_token)):
    return result

otp_store = {}
async def send_email(recipient: str, otp: str):
    msg = EmailMessage()
    msg["From"] = os.getenv("EMAIL_USER")
    msg["To"] = recipient
    msg["Subject"] = "Your OTP Verification Code"
    msg.set_content(f"Your OTP code is: {otp}\n\nThis code will expire in 2 minutes.")

    await aiosmtplib.send(
        msg,
        hostname=os.getenv("SMTP_SERVER"),
        port=int(os.getenv("SMTP_PORT")),
        start_tls=True,
        username=os.getenv("EMAIL_USER"),
        password=os.getenv("EMAIL_PASS"),
    )

class EmailRequest(BaseModel):
    email: str

@app.post("/send-otp")
async def send_otp(data : EmailRequest, result: dict = Depends(verify_jwt_token)):
    print(f"✅ Token verified for user id: {result['id']}")

    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id FROM users WHERE email = $1", data.email)
        if not row:
            return {"message": "Email not found", "status" : False}
        else:

            otp = str(random.randint(100000, 999999))

            expire_time = datetime.utcnow() + timedelta(minutes=2)

            otp_store[data.email] = {"otp": otp, "expires": expire_time}

            try:
                await send_email(data.email, otp)
                return {"message": f"OTP sent to {data.email}", "status" : True}
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))



class OTPVerify(BaseModel):
    email: str
    otp: str
@app.post("/verify-otp")
async def verify_otp(data : OTPVerify, result: dict = Depends(verify_jwt_token)):
    record = otp_store.get(data.email)

    if not record:
        raise HTTPException(status_code=404, detail="No OTP found for this email")

    if datetime.utcnow() > record["expires"]:
        del otp_store[data.email]
        raise HTTPException(status_code=400, detail="OTP expired")

    if record["otp"] != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    del otp_store[data.email]

    return {"message": "OTP verified successfully!"}

# "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywiZXhwIjoxNzU5NDc5MDMwfQ.6eb9DBDTyuris4hViDlC8XZNmod3DM-RUWU5nmCRfGw",


class ResetPasswordRequestOTP(BaseModel):
    id: int
    new_password: str

@app.put("/reset-password/otp")
async def reset_password(data : ResetPasswordRequestOTP):
    async with app.state.pool.acquire() as conn:
        hash_password = get_password_hash(data.new_password)
        row = await conn.fetchrow("UPDATE users SET password = $1 WHERE id = $2", hash_password, data.id)
        if row:
            return {"message": "Password updated successfully!", "status" : True}
        else:
            return {"message": "Error during updating password", "status" : False}


class ResetPasswordRequestOldPassword(BaseModel):
    id: int
    old_password: str
    new_password: str

@app.put("/reset-password")
async def reset_password(data : ResetPasswordRequestOldPassword):
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT password FROM users WHERE id = $1", data.id)
        if row:
            print(row["password"])
            is_correct_old_password = verify_password(data.old_password, row["password"])
            if is_correct_old_password:
                hashed_new_password = get_password_hash(data.new_password)
                insert_new_password = await conn.fetchrow("UPDATE users set password = $1 WHERE id = $2", hashed_new_password, data.id)
                if insert_new_password:
                    return {"message": "Password updated successfully!", "status" : True}
                else:
                    return {"message" : "Error during password update", "status" : False}
            else:
                return {"message": "Incorrect Password", "status" : False}
            return {row}
        else:
            return {"message" : "User not found", "status" : False}
