import os
from http.client import responses

from fastapi import FastAPI
from dotenv import load_dotenv
import asyncpg


from auth import *


load_dotenv()


DATABASE_URL = os.getenv("DATABASE_URL")
app = FastAPI()
#
@app.on_event("startup")
async def startup():
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
async def update_user(data : dict):
    id = data["id"]
    first_name = data["first_name"]
    last_name = data["last_name"]
    phone = data["phone"]
    gender = data["gender"]
    picture = data["picture"]
    role = data["role"]


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
                return {"message": "User not found", "status" : False}


# @app.get('/get_otp')
# async def get_otp():
