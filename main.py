from datetime import datetime, timedelta, timezone
from fastapi import Depends, FastAPI, HTTPException

from jose import JWTError, jwt

import uvicorn
from models import StatusCode, User, UserInDB, TokenData, Token
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi import status
from typing import Annotated
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import secrets

import socket
import platform


app = FastAPI()
security_basic_auth = HTTPBasic()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


status_codes: dict = {}


SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# http://127.0.0.1:8000/docs


def get_current_username(
    credentials: Annotated[HTTPBasicCredentials, Depends(security_basic_auth)]
):
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = b"jos"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = b"azerty123"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user_oauth(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = User(username=username)
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user_oauth)]
):
    return current_user

@app.post("/")
def post_root():
    return {"Hello": "post!"}

@app.get("/")
def get_root():
    return {"Hello": "get!"}

@app.post("/status-code")
def add_status_code(status_code: StatusCode):
    status_codes[status_code.status_code] = status_code.explanation
    return {"Message": "Status code added successfully"}

@app.get("/token")
def login_token(username: Annotated[HTTPBasicCredentials, Depends(get_current_username)]):
        if not username:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": username}, expires_delta=access_token_expires
        )
        return Token(access_token=access_token, token_type="bearer")


@app.get("/status-codes")
def get_status_codes():
    return {"Status Codes": status_codes}

@app.get("/network-settings")
def get_network_settings():
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return {"Hostname": hostname, "IP Address": ip_address}

@app.get("/system-info")
def get_system_info():
    system_info = {}
    system_info['System'] = platform.system()
    system_info['Node Name'] = platform.node()
    system_info['Release'] = platform.release()
    system_info['Version'] = platform.version()
    system_info['Machine'] = platform.machine()
    system_info['Processor'] = platform.processor()
    return system_info

@app.get("/secure-endpoint")
def secured_endpoint(username: Annotated[HTTPBasicCredentials, Depends(get_current_username)]):
        return {"message": "You are authenticated"}

@app.get("/bearer-auth")
def bearer_auth(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"username": current_user.username, "message": "Goed gedaan!"}]

@app.put("/")
def put_root():
    return {"Hello": "put!"}

@app.delete("/")
def delete_root():
    return {"Hello": "delete!"}

@app.delete("/status-codes")
def delete_status_codes():
    status_codes.clear()
    return {"Message": "Status codes deleted successfully"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)