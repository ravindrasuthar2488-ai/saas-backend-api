from fastapi import FastAPI, HTTPException
import uvicorn
import sqlite3
import os
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

conn = sqlite3.connect("mydatabase.db", check_same_thread=False)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT,
        password TEXT
    )
""")
conn.commit()


@app.post("/signup")
def signup(name: str, password: str):
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    existing_user = cursor.fetchone()

    if existing_user is not None:
        raise HTTPException(status_code=400, detail="User already exists")

    hashed_password = pwd_context.hash(password)
    cursor.execute("INSERT INTO users (name, password) VALUES (?, ?)", (name, hashed_password))
    conn.commit()
    return {"message": f"{name} signed up successfully"}


@app.get("/users")
def get_users():
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    return {"users": rows}


@app.post("/login")
def login(name: str, password: str):
    cursor.execute("SELECT password FROM users WHERE name = ?", (name,))
    result = cursor.fetchone()

    if result is None:
        raise HTTPException(status_code=404, detail="User not found")

    stored_password = result[0]

    if pwd_context.verify(password, stored_password):
        return {"message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Wrong password")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)