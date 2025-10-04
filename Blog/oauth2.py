from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from . import database, models
from . import token as token_helper  # ✅ renamed to avoid conflict

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_current_user(
    token_str: str = Depends(oauth2_scheme), 
    db: Session = Depends(database.get_db)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # ✅ use the helper instead of shadowed token variable
    token_data = token_helper.verify_token(token_str, credentials_exception)
    
    user = db.query(models.User).filter(models.User.email == token_data.email).first()
    if not user:
        raise credentials_exception
    return user
