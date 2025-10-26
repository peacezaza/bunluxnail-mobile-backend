import os
import random
import asyncio
from http.client import responses
import base64
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Body
from dotenv import load_dotenv
import asyncpg
import shutil
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from email.message import EmailMessage
import aiosmtplib
from fastapi.middleware.cors import CORSMiddleware



from auth import *
from pydantic import BaseModel, EmailStr, Field
from typing import Optional

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
        statement_cache_size=0,
        max_inactive_connection_lifetime = 30,
    )

@app.on_event("shutdown")
async def shutdown():
    print("🧹 Closing connection pool...")
    try:
        # Cancel all running tasks
        tasks = [task for task in asyncio.all_tasks() if task is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
        # Close pool with shorter timeout
        await asyncio.wait_for(app.state.pool.close(), timeout=3.0)
        print("✅ Connection pool closed")
    except asyncio.TimeoutError:
        print("⚠️ Timeout: Force closing pool")
        app.state.pool.terminate()  # Force close
        await app.state.pool.wait_closed()
    except Exception as e:
        print(f"⚠️ Shutdown error: {e}")
    finally:
        # Clean up event loop
        loop = asyncio.get_event_loop()
        loop.stop()
        loop.run_until_complete(loop.shutdown_asyncgens())
        loop.close()

@app.get("/debug-pool")
async def debug_pool():
    return {
        "total_conns": app.state.pool._holder._conns,
        "free_conns": app.state.pool._holder._free,
        "active_tasks": len(asyncio.all_tasks())
    }

@app.get("/")
async def root():
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT now() AS current_time;")
        return {"message": "Hello World"}
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

class SignupResponse(BaseModel):
    message : str
    status : bool
    token : str

@app.post("/signup", response_model=SignupResponse, tags=["Authentication"])
async def signup(data : SignupRequest):
    print(data)
    username = data["username"]
    password = data["password"]
    email = data["email"]

    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("SELECT id from users where username = $1 or email = $2", username, email)
        if row:
            return {"message": "User already exists", "status" : False, "token" : ""}
        else :
            hashed_pw = get_password_hash(password)
            insert_row = await conn.fetchrow("INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id", username, email, hashed_pw)
            print(insert_row['id'])

            token = create_access_token({"id": insert_row['id']}, expires_delta=timedelta(minutes=30))
            print("Token: ", token)

            return {"message": "User created", "status" : True, "token": token}

@app.post("/update_user", tags=["Profile"])
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
    username: Optional[str] = Field(None, description="Username (leave empty if using email)")
    email: Optional[EmailStr] = Field(None, description="Email (leave empty if using username)")
    password: str


class LoginResponse(BaseModel):
    message : str
    status : bool
    token : Optional[str]



@app.post("/login", response_model=LoginResponse, tags=["Authentication"])
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
                    return {"message" : "Login Successfully", "status": True, "token" : token}
                else:
                    return {"message" : "Incorrect Password", "status" : False, "token": ""}
            else:
                return {"message": "User not found", "status" : False, "token": ""}
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

@app.post("/send-otp", tags=["Authentication"])
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

class OTPResponse(BaseModel):
    message : str

@app.post("/verify-otp", response_model=OTPResponse, tags=["Authentication"])
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

@app.put("/reset-password/otp", tags=["Authentication"])
async def reset_password(data : ResetPasswordRequestOTP, result: dict = Depends(verify_jwt_token)):
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

@app.put("/reset-password", tags=["Authentication"])
async def reset_password(data : ResetPasswordRequestOldPassword,result: dict = Depends(verify_jwt_token)):
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

class IdRequest(BaseModel):
    id: int

class ProfileResponse(BaseModel):
    id: int
    username: str
    email: str
    first_name: Optional[str]
    last_name: Optional[str]
    phone: Optional[str]
    gender: Optional[str]
    role: Optional[str]
    picture_base64: Optional[str]

@app.get("/profile", response_model=ProfileResponse, tags=["Profile"])
async def profile(data: IdRequest, result: dict = Depends(verify_jwt_token)):
    print(result)
    async with app.state.pool.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT id, username, email, first_name, last_name, phone, gender, picture, role 
            FROM users WHERE id = $1
        """, data.id)

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    image_bytes = row["picture"]
    image_base64 = None
    if image_bytes:
        # ✅ แปลง bytea เป็น Base64 string
        image_base64 = base64.b64encode(image_bytes).decode("utf-8")

    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "phone": row["phone"],
        "gender": row["gender"],
        "role": row["role"],
        "picture_base64": f"data:image/png;base64,{image_base64}" if image_base64 else None
    }


class ServicesResponse(BaseModel):
    id:int
    service_name: str
    service_detail : str
    price : int
    picture : Optional[str]
@app.get("/services", response_model=ServicesResponse,tags=["Reservation"])
async def services(result: dict = Depends(verify_jwt_token)):
    async with app.state.pool.acquire() as conn:
        row = await conn.fetch("SELECT * FROM services")
        if row:
            print("Row is:")
            print(row)
            return row

        print("TAP")
        return {"message": "successful"}


class ReservationRequest(BaseModel):
    id:int
    date : str
    period : str
    selected_services_id : list

class ReservationResponse(BaseModel):
    message : str



@app.post("/reservation",tags=["Reservation"])
async def reservation(data:ReservationRequest):
    """
    - Example use
    {
    "id": 7,
    "selected_services_id" : [1,2,3,4],
    "date" : "2025-10-08",
    "period" : "10:00"
    }
    """
    print(data.selected_services_id)
    # [1, 2, 3, 4]
    for i in data.selected_services_id:
        print("i is : ", i)

    # format_string_only = "%Y-%m-%d"
    format_string = "%Y-%m-%d %H:%M:%S"
    format_date_tz = "%Y-%m-%d %H:%M:%S%z"
    date_object = datetime.strptime(f"{data.date} {data.period}:00", format_string).replace(tzinfo=ZoneInfo("Asia/Bangkok"))
    day_of_week = date_object.strftime("%A")
    date_edit_object = date_object
    # print("Day of week: ", day_of_week)
    # print("Date Object: ", date_object.strftime("%A"))
    # print("Date with TimeZone", date_object)


    async with app.state.pool.acquire() as conn:
        get_day = await conn.fetchrow("SELECT * FROM shop_hours WHERE day = $1", day_of_week)
        if get_day:
            """
            {
            "id": 3,
            "day": "Wednesday",
            "open_time": "18:30:00+07:00",
            "close_time": "00:30:00+07:00"
            }
            """
            # print("Row is:", get_day["open_time"])
            open_date = datetime.strptime(f"{data.date} {get_day["open_time"]}", format_date_tz)
            close_date = datetime.strptime(f"{data.date} {get_day['close_time']}", format_date_tz)
            reseration_date_add_two_hours = date_object + timedelta(hours=2)

            # if date_object.time() < open_date.time():
            #     print("\n-------------------------")
            #     print(data.period)
            #     print(reseration_date_add_two_hours)
            #     print(open_date.time())
            #     print("-------------------------\n")
            #
            print("\n-------------------------")
            print(date_object)
            print(reseration_date_add_two_hours)
            print(open_date)
            print("-------------------------\n")

            if close_date.time() < open_date.time():
                close_date += timedelta(days=1)

            #
            # print("Open:", open_date,"\nClose:", close_date)
            #
            # print("Reservation Date :", date_object)

            if date_object >= open_date and reseration_date_add_two_hours <= close_date:
                fetch_reservation = await conn.fetch("SELECT user_id, status, date AT TIME ZONE 'Asia/Bangkok' AS date FROM booking WHERE date = $1 and status = $2", date_object, "confirmed")
            #     2025-10-08 18:30:00+07:00
                if fetch_reservation:
                    print("Reserved Data :",fetch_reservation)
                    return {"message" : "Duplicate reservation", "status" : False}
                else:
                    add_reservation = await conn.fetchrow("INSERT INTO booking (user_id, status, date) VALUES ($1, $2, $3) RETURNING id", data.id, "confirmed", date_object)
                    if add_reservation:
                        print("New Reserved Id: ",add_reservation["id"])
                        for i in data.selected_services_id:
                            add_service = await conn.fetchrow("INSERT INTO booking_services (booking_id, service_id) VALUES ($1, $2)", add_reservation["id"], i)
                            # print(add_service)


                        # print(data.selected_services_id)

                        return {"message" : "Added Reservation Successfully", "status" : True}
                    else:
                        return {"message" : "test"}
            else:
                return {"message" : "time is < open time or time + 2 > close time", "status" : False}


class availableTimeRequest(BaseModel):
    date:str

@app.get("/available/Time",tags=["Reservation"])
async def available_time(data: availableTimeRequest):
    print(data)
