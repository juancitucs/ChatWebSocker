import json
from botocore.exceptions import ClientError
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends
from fastapi import (
    FastAPI, WebSocket, UploadFile, File,
    HTTPException, Depends
)
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from rethinkdb import RethinkDB
from rethinkdb.errors import ReqlOpFailedError
import bcrypt, jwt, datetime, os, boto3, uuid, json, asyncio
from typing import Any, Callable
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
TBL_ROOMS = "rooms"
auth_scheme = HTTPBearer() 
# ---------- RethinkDB ----------
r = RethinkDB()
RDB_HOST = "192.168.122.104"
RDB_PORT = 28015
DB_NAME   = "chat"
TBL_USERS = "users"
TBL_MSGS  = "messages"

def _get_conn():
    """Devuelve una conexión *nueva* a la BD."""
    return r.connect(host=RDB_HOST, port=RDB_PORT, db=DB_NAME)

def _run_sync(f: Callable[[], Any]):
    """Ejecuta bloqueante en thread pool y devuelve el resultado."""
    loop = asyncio.get_event_loop()
    return loop.run_in_executor(None, f)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],      
    allow_credentials=True,
    allow_methods=["*"],        # GET, POST, OPTIONS, etc.
    allow_headers=["*"],        # Authorization, Content-Type…
)

@app.on_event("startup")
def _init_db():
    """Crea BD y tablas si no existen."""
    conn = r.connect(host=RDB_HOST, port=RDB_PORT)
    # BD
    if DB_NAME not in r.db_list().run(conn):
        r.db_create(DB_NAME).run(conn)

    # Tabla usuarios (PK = username)
    try:
        r.db(DB_NAME).table_create(
            TBL_USERS, primary_key="username", replicas=2
        ).run(conn)
    except ReqlOpFailedError:
        pass

    # Tabla mensajes
    try:
        r.db(DB_NAME).table_create(
            TBL_MSGS, replicas=2
        ).run(conn)
    except ReqlOpFailedError:
        pass
    try:
        r.db(DB_NAME).table_create(
            TBL_ROOMS,
            primary_key="id",
            replicas=2
        ).run(conn)
    except ReqlOpFailedError:
        pass
    conn.close()

# ---------- MinIO ----------

MINIO = boto3.client(
    "s3",
    endpoint_url="http://192.168.122.106:9000",
    aws_access_key_id="minioadmin",
    aws_secret_access_key="minioadmin",
)

# Crear bucket 'chat' si no existe
try:
    MINIO.head_bucket(Bucket="chat")
except ClientError as e:
    code = e.response["Error"]["Code"]
    if code in ("404", "NoSuchBucket"):
        MINIO.create_bucket(Bucket="chat")
    else:
        raise

# Política pública de sólo lectura para todos los objetos en el bucket
public_read_policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"AWS": ["*"]},
        "Action": ["s3:GetObject"],
        "Resource": ["arn:aws:s3:::chat/*"]
    }]
}
MINIO.put_bucket_policy(
    Bucket="chat",
    Policy=json.dumps(public_read_policy)
)





# ---------- JWT ----------
SECRET = "super_secreto"

def create_jwt(username: str):
    payload = {
        "sub": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=3),
    }
    return jwt.encode(payload, SECRET, algorithm="HS256")


def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)
) -> str:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except Exception:
        raise HTTPException(status_code=401, detail="Token inválido")


# ---------- Archivos estáticos ----------
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_index():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "index.html"))

# ---------- Endpoints ----------
@app.post("/api/register", status_code=201)
async def register(u: dict):
    hashed = bcrypt.hashpw(u["password"].encode(), bcrypt.gensalt()).decode()

    def _tx():
        conn = _get_conn()
        # ¿Existe?
        if r.table(TBL_USERS).get(u["username"]).run(conn):
            conn.close()
            raise ValueError("Usuario ya existe")
        r.table(TBL_USERS).insert(
            {"username": u["username"], "password": hashed,
             "created_at": r.now()}
        ).run(conn)
        conn.close()

    try:
        await _run_sync(_tx)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}

@app.post("/api/login")
async def login(u: dict):
    def _tx():
        conn = _get_conn()
        row = r.table(TBL_USERS).get(u["username"]).run(conn)
        conn.close()
        return row
    row = await _run_sync(_tx)
    if not row or not bcrypt.checkpw(u["password"].encode(),
                                     row["password"].encode()):
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    return {"token": create_jwt(u["username"])}


@app.get("/api/rooms")
async def list_rooms(user: str = Depends(verify_token)):
    def _tx():
        conn = _get_conn()
        cursor = (
            r.table(TBL_ROOMS)
             .filter(lambda room: room["participants"].contains(user))
             .run(conn)
        )
        rooms = list(cursor)
        conn.close()
        return rooms

    rooms = await _run_sync(_tx)
    return rooms
@app.post("/api/room", status_code=201)
async def create_room(
    body: dict,
    user: str = Depends(verify_token)
):
    """
    Crea una sala con id y lista de participantes.
    body = {
      "id": "alice-bob",
      "participants": ["alice","bob"]
    }
    """
    def _tx():
        conn = _get_conn()
        # Verifica que no exista ya
        if r.table(TBL_ROOMS).get(body["id"]).run(conn):
            conn.close()
            raise ValueError("La sala ya existe")
        # Inserta la sala
        r.table(TBL_ROOMS).insert({
            "id":           body["id"],
            "participants": body["participants"],
            "created_by":   user,
            "created_at":   r.now()
        }).run(conn)
        conn.close()

    try:
        await _run_sync(_tx)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"ok": True}

@app.post("/api/send")
async def send(msg: dict, user: str = Depends(verify_token)):
    """
    msg = {
      "room": "sala-id",
      "content": "texto libre o URL de archivo"
    }
    """
    def _tx():
        conn = _get_conn()
        r.table(TBL_MSGS).insert({
            "from":    user,
            "room":    msg["room"],
            "content": msg["content"],
            "ts":      r.now(),
        }).run(conn)
        conn.close()
    await _run_sync(_tx)
    return {"ok": True}


@app.get("/api/history/{room}")
async def history(room: str, limit: int = 50,
                  user: str = Depends(verify_token)):
    def _tx():
        conn = _get_conn()
        cursor = (r.table(TBL_MSGS)
                    .filter({"room": room})
                    .order_by(r.desc("ts"))
                    .limit(limit)
                    .run(conn))
        msgs = list(cursor)
        conn.close()
        return msgs
    msgs = await _run_sync(_tx)
    # Convertimos a objetos JSON-serializables
    for m in msgs:
        m["ts"] = str(m["ts"])
    return msgs


@app.post("/api/upload")
async def upload_file(
    f: UploadFile = File(...),
    user: str = Depends(verify_token)
):
    """
    Sube cualquier tipo de archivo a MinIO y devuelve metadatos:
      - file: el ID generado
      - filename: nombre original
      - content_type: MIME
      - url: enlace de descarga
    """
    # Leer todo el contenido del archivo
    content = await f.read()
    # Generar un ID único conservando la extensión
    file_id = f"{uuid.uuid4()}{os.path.splitext(f.filename)[1]}"
    # Subir a MinIO en el bucket "chat"
    MINIO.put_object(
        Bucket="chat",
        Key=file_id,
        Body=content,
        ContentType=f.content_type
    )
    # Devolver metadatos completos
    return {
        "file": file_id,
        "filename": f.filename,
        "content_type": f.content_type,
        "url": f"http://192.168.122.106:9000/chat/{file_id}"
    }



# ---------- WebSocket ----------
@app.websocket("/ws/{room}")
async def websocket_chat(ws: WebSocket, room: str):
    await ws.accept()
    conn = _get_conn()
    feed = r.table(TBL_MSGS).filter({"room": room}).changes().run(conn)

    loop = asyncio.get_event_loop()

    async def next_change():
        # Ejecuta 'feed.next()' en un hilo para que no bloquee el loop
        return await loop.run_in_executor(
            FEED_EXECUTOR,
            feed.next                              
        )

    try:
        while True:
            change = await next_change()               
            new = change.get("new_val")
            if not new:
                continue
            new["ts"] = str(new["ts"])
            await ws.send_text(json.dumps(new))

    except Exception:
        pass
    finally:
        try:
            feed.close()
        except Exception:
            pass
        conn.close()
