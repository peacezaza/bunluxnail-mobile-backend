import os
from http.client import responses
import base64
from fastapi import FastAPI, UploadFile, File, Form
from dotenv import load_dotenv
import asyncpg
import shutil
from datetime import datetime

from fastapi.middleware.cors import CORSMiddleware
from auth import *


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


@app.post("/signup")
async def signup(data : dict):
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

@app.post("/update_user")
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





@app.get("/login")
async def login(data :dict):
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
    username = data["username"]
    email = data["email"]
    password = data["password"]

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


# "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NywiZXhwIjoxNzU5NDc5MDMwfQ.6eb9DBDTyuris4hViDlC8XZNmod3DM-RUWU5nmCRfGw",
