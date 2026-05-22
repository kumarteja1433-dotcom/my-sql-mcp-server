None selected

Skip to content
Using Gmail with screen readers
Conversations
0% of 5,120 GB used
Terms · Privacy · Program Policies
Last account activity: 0 minutes ago
Currently being used in 2 other locations · Details

from mcp.server.fastmcp import FastMCP
import pyodbc
import os
import sys
import re
import json
import traceback
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime
import socket
import uvicorn

# --------------------------------------------------
# STDIO FLUSHING FOR MCP
# --------------------------------------------------
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# --------------------------------------------------
# ENV LOADING
# --------------------------------------------------
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)

mcp = FastMCP(
    "mssql-dba-server",
    host="0.0.0.0",
    port=8000
)

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
MSSQL_HOST     = os.getenv("MSSQL_HOST", "")
MSSQL_PORT     = os.getenv("MSSQL_PORT", "1433")
MSSQL_DB       = os.getenv("MSSQL_DB", "master")
MSSQL_USER     = os.getenv("MSSQL_USER", "")
MSSQL_PASSWORD = os.getenv("MSSQL_PASSWORD", "")

ALLOW_DESTRUCTIVE = os.getenv("ALLOW_DESTRUCTIVE", "false").strip().lower() == "true"
APPROVAL_TOKEN    = os.getenv("APPROVAL_TOKEN", "").strip()

BACKUP_ALLOWED_ROOTS = [
    p.strip().rstrip("\\/")
    for p in os.getenv("BACKUP_ALLOWED_ROOTS", "").split(";")
    if p.strip()
]

BACKUP_SHARE_USER     = os.getenv("BACKUP_SHARE_USER", "").strip()
BACKUP_SHARE_PASSWORD = os.getenv("BACKUP_SHARE_PASSWORD", "").strip()
BACKUP_SHARE_DOMAIN   = os.getenv("BACKUP_SHARE_DOMAIN", "").strip()

DEFAULT_DATA_DIR = os.getenv("DEFAULT_DATA_DIR", r"C:\SQLData").rstrip("\\/")
DEFAULT_LOG_DIR  = os.getenv("DEFAULT_LOG_DIR",  r"C:\SQLLogs").rstrip("\\/")

CONNECTION_TIMEOUT = int(os.getenv("CONNECTION_TIMEOUT", "30"))
QUERY_TIMEOUT      = int(os.getenv("QUERY_TIMEOUT", "600"))

# --------------------------------------------------
# HELPERS
# --------------------------------------------------
IDENTIFIER_RE    = re.compile(r"^[A-Za-z0-9_\-]+$")
SAFE_DB_NAME_RE  = re.compile(r"^[A-Za-z0-9_\-]+$")
SAFE_FILE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-\.]+$")

SELECT_RE = re.compile(r"^\s*SELECT\b", re.IGNORECASE)

def ok(data=None, message=None):
    return {"ok": True, "message": message, "data": data}

def fail(message, details=None):
    payload = {"ok": False, "error": message}
    if details is not None:
        payload["details"] = details
    return payload

def quote_ident(name: str) -> str:
    if not name or not SAFE_DB_NAME_RE.match(name):
        raise ValueError(f"Unsafe identifier: {name}")
    return f"[{name}]"

def validate_db_name(database_name: str):
    if not database_name or not SAFE_DB_NAME_RE.match(database_name):
        raise ValueError("Invalid database_name. Allowed: letters, numbers, underscore, hyphen.")

def validate_simple_name(value: str, field_name: str):
    if not value or not IDENTIFIER_RE.match(value):
        raise ValueError(f"Invalid {field_name}. Allowed: letters, numbers, underscore, hyphen.")

def normalize_path(path_value: str) -> str:
    p = path_value.strip().replace("/", "\\")
    return os.path.normpath(p)

def is_unc_path(path_value: str) -> bool:
    return normalize_path(path_value).startswith("\\\\")

def mount_share_if_needed(path_value: str):
    if not is_unc_path(path_value):
        return
    if not BACKUP_SHARE_USER or not BACKUP_SHARE_PASSWORD:
        return
    parts = normalize_path(path_value).split("\\")
    share_root = "\\\\" + parts[2] + "\\" + parts[3]
    user = f"{BACKUP_SHARE_DOMAIN}\\{BACKUP_SHARE_USER}" if BACKUP_SHARE_DOMAIN else BACKUP_SHARE_USER
    cmd = f'net use "{share_root}" "{BACKUP_SHARE_PASSWORD}" /user:"{user}" /persistent:no'
    sql = f"""
DECLARE @result INT;
EXEC @result = master..xp_cmdshell '{cmd.replace("'", "''")}', no_output;
SELECT @result AS return_code;
"""
    try:
        row = fetch_one_dict(sql, database="master")
        return_code = row.get("return_code") if row else None
        if return_code not in (0, None):
            raise RuntimeError(
                f"xp_cmdshell net use returned code {return_code} for share '{share_root}'. "
                "Ensure xp_cmdshell is enabled on the server and credentials are correct."
            )
    except Exception as e:
        raise RuntimeError(f"Failed to mount network share '{share_root}' on SQL Server: {e}")

def ensure_path_allowed(path_value: str):
    if not BACKUP_ALLOWED_ROOTS:
        raise ValueError("BACKUP_ALLOWED_ROOTS is not configured.")
    target  = normalize_path(path_value).lower()
    allowed = [normalize_path(p).lower() for p in BACKUP_ALLOWED_ROOTS]
    if not any(target.startswith(root.lower()) for root in allowed):
        raise ValueError(f"Path not allowed. Allowed roots: {BACKUP_ALLOWED_ROOTS}")

def require_destructive_enabled():
    if not ALLOW_DESTRUCTIVE:
        raise PermissionError(
            "Destructive operations are disabled. Set ALLOW_DESTRUCTIVE=true to enable."
        )

def require_approval_token(approval_token: str):
    if not APPROVAL_TOKEN:
        raise PermissionError("APPROVAL_TOKEN is not configured on server.")
    if approval_token != APPROVAL_TOKEN:
        raise PermissionError("Invalid approval token.")

# --------------------------------------------------
# CONNECTION FACTORY  (supports alternate host)
# --------------------------------------------------
def get_conn(
    database: str = None,
    autocommit: bool = False,
    host: str = None,
    port: str = None,
    user: str = None,
    password: str = None,
):
    db_name   = database or MSSQL_DB
    _host     = host     or MSSQL_HOST
    _port     = port     or MSSQL_PORT
    _user     = user     or MSSQL_USER
    _password = password or MSSQL_PASSWORD

    conn = pyodbc.connect(
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={_host},{_port};"
        f"DATABASE={db_name};"
        f"UID={_user};"
        f"PWD={_password};"
        "Encrypt=yes;"
        "TrustServerCertificate=yes;"
        f"Connection Timeout={CONNECTION_TIMEOUT};",
        autocommit=autocommit
    )
    conn.timeout = QUERY_TIMEOUT
    return conn

# --------------------------------------------------
# DATA HELPERS
# --------------------------------------------------
def fetch_all_dicts(query: str, params=None, database: str = None,
                    host=None, port=None, user=None, password=None):
    with get_conn(database, host=host, port=port, user=user, password=password) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()
        return [dict(zip(columns, map(_serialize_value, row))) for row in rows]

def fetch_one_dict(query: str, params=None, database: str = None,
                   host=None, port=None, user=None, password=None):
    with get_conn(database, host=host, port=port, user=user, password=password) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        row = cursor.fetchone()
        if row is None:
            return None
        columns = [col[0] for col in cursor.description]
        return dict(zip(columns, map(_serialize_value, row)))

def execute_non_query(query: str, params=None, database: str = None):
    with get_conn(database) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        conn.commit()

def execute_and_collect_messages(query: str, params=None, database: str = None,
                                  host=None, port=None, user=None, password=None):
    with get_conn(database, autocommit=True,
                  host=host, port=port, user=user, password=password) as conn:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        result_sets = []
        while True:
            if cursor.description:
                columns = [col[0] for col in cursor.description]
                rows = cursor.fetchall()
                result_sets.append(
                    [dict(zip(columns, map(_serialize_value, row))) for row in rows]
                )
            if not cursor.nextset():
                break
        messages = []
        if hasattr(conn, "messages") and conn.messages:
            for msg in conn.messages:
                messages.append(str(msg))
        return {"result_sets": result_sets, "messages": messages}

def _serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat(sep=" ", timespec="seconds")
    return value

# --------------------------------------------------
# AUDIT
# --------------------------------------------------
def ensure_audit_table():
    query = """
IF NOT EXISTS (
    SELECT 1
    FROM sys.tables t
    JOIN sys.schemas s ON t.schema_id = s.schema_id
    WHERE t.name = 'mcp_audit_log' AND s.name = 'dbo'
)
BEGIN
    CREATE TABLE dbo.mcp_audit_log (
        id               INT IDENTITY(1,1) PRIMARY KEY,
        event_time       DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
        tool_name        NVARCHAR(128)  NOT NULL,
        action_status    NVARCHAR(20)   NOT NULL,
        database_name    NVARCHAR(256)  NULL,
        request_payload  NVARCHAR(MAX)  NULL,
        result_payload   NVARCHAR(MAX)  NULL
    );
END
"""
    execute_non_query(query, database="master")

def audit(tool_name: str, action_status: str, database_name: str = None,
          request_payload=None, result_payload=None):
    try:
        ensure_audit_table()
        query = """
INSERT INTO dbo.mcp_audit_log
    (tool_name, action_status, database_name, request_payload, result_payload)
VALUES (?, ?, ?, ?, ?)
"""
        execute_non_query(
            query,
            params=[
                tool_name,
                action_status,
                database_name,
                json.dumps(request_payload, default=str) if request_payload is not None else None,
                json.dumps(result_payload,  default=str) if result_payload  is not None else None,
            ],
            database="master"
        )
    except Exception:
        pass

# --------------------------------------------------
# BACKUP / RESTORE BUILDERS
# --------------------------------------------------
def build_backup_sql(database_name, backup_type, destination,
                     copy_only=False, checksum=True, compress=True):
    validate_db_name(database_name)
    ensure_path_allowed(destination)
    db_quoted   = quote_ident(database_name)
    backup_type = backup_type.strip().upper()
    options = ["INIT", "STATS = 10"]
    if checksum:  options.append("CHECKSUM")
    if compress:  options.append("COMPRESSION")
    if copy_only: options.append("COPY_ONLY")
    if backup_type == "FULL":
        sql = f"BACKUP DATABASE {db_quoted}\nTO DISK = ?\nWITH {', '.join(options)}"
    elif backup_type == "DIFF":
        sql = f"BACKUP DATABASE {db_quoted}\nTO DISK = ?\nWITH DIFFERENTIAL, {', '.join(options)}"
    else:
        raise ValueError("backup_type must be FULL or DIFF.")
    return sql

def build_log_backup_sql(database_name, destination, checksum=True, compress=True):
    validate_db_name(database_name)
    ensure_path_allowed(destination)
    db_quoted = quote_ident(database_name)
    options = ["INIT", "STATS = 10"]
    if checksum: options.append("CHECKSUM")
    if compress: options.append("COMPRESSION")
    return f"BACKUP LOG {db_quoted}\nTO DISK = ?\nWITH {', '.join(options)}"

def get_database_file_list_from_backup(backup_file: str, host=None, port=None, user=None, password=None):
    ensure_path_allowed(backup_file)
    return fetch_all_dicts(
        "RESTORE FILELISTONLY FROM DISK = ?",
        params=[backup_file], database="master",
        host=host, port=port, user=user, password=password
    )

def get_backup_header(backup_file: str):
    ensure_path_allowed(backup_file)
    return fetch_all_dicts("RESTORE HEADERONLY FROM DISK = ?",
                           params=[backup_file], database="master")

def infer_move_clauses(filelist_rows, target_database: str):
    validate_db_name(target_database)
    move_clauses = []
    generated_files = []
    data_index = log_index = 0
    for row in filelist_rows:
        logical_name    = row.get("LogicalName")
        file_type       = row.get("Type")
        original_physical = row.get("PhysicalName", "")
        if not logical_name:
            raise ValueError("Backup file list does not contain LogicalName.")
        if file_type == "D":
            ext = ".mdf" if data_index == 0 else f"_{data_index}.ndf"
            file_path = f"{DEFAULT_DATA_DIR}\\{target_database}{ext}"
            data_index += 1
        elif file_type == "L":
            ext = ".ldf" if log_index == 0 else f"_{log_index}.ldf"
            file_path = f"{DEFAULT_LOG_DIR}\\{target_database}{ext}"
            log_index += 1
        else:
            guessed_ext = Path(str(original_physical)).suffix or ".dat"
            file_path = f"{DEFAULT_DATA_DIR}\\{target_database}_{logical_name}{guessed_ext}"
        move_clauses.append(f"MOVE N'{logical_name}' TO N'{file_path}'")
        generated_files.append({"logical_name": logical_name,
                                 "target_file": file_path, "type": file_type})
    return move_clauses, generated_files

def stored_procedure_exists(database_name: str, schema_name: str, procedure_name: str) -> bool:
    validate_db_name(database_name)
    validate_simple_name(schema_name, "schema_name")
    validate_simple_name(procedure_name, "procedure_name")
    query = f"""
SELECT 1
FROM {quote_ident(database_name)}.sys.procedures p
INNER JOIN {quote_ident(database_name)}.sys.schemas s ON p.schema_id = s.schema_id
WHERE s.name = ? AND p.name = ?
"""
    row = fetch_one_dict(query, params=[schema_name, procedure_name], database="master")
    return row is not None

def database_exists(database_name: str) -> bool:
    validate_db_name(database_name)
    row = fetch_one_dict("SELECT name FROM sys.databases WHERE name = ?",
                         params=[database_name], database="master")
    return row is not None

def get_database_state(database_name: str):
    validate_db_name(database_name)
    return fetch_one_dict("""
SELECT name AS database_name, state_desc, user_access_desc,
       recovery_model_desc, is_read_only
FROM sys.databases WHERE name = ?
""", params=[database_name], database="master")

def bring_database_online(database_name: str):
    validate_db_name(database_name)
    sql = f"ALTER DATABASE {quote_ident(database_name)} SET ONLINE"
    return execute_and_collect_messages(sql, database="master")

def execute_msdb_procedure(proc_schema: str, proc_name: str, target_database: str):
    validate_simple_name(proc_schema, "proc_schema")
    validate_simple_name(proc_name,   "proc_name")
    validate_db_name(target_database)
    sql = f"EXEC msdb.{quote_ident(proc_schema)}.{quote_ident(proc_name)} @DatabaseName = ?"
    return execute_and_collect_messages(sql, params=[target_database], database="master")

def validate_access_restoration(database_name: str):
    validate_db_name(database_name)
    users = fetch_all_dicts(f"""
SELECT dp.name AS user_name, dp.type_desc, dp.authentication_type_desc, sp.name AS login_name
FROM {quote_ident(database_name)}.sys.database_principals dp
LEFT JOIN master.sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.type IN ('S','U','G') AND dp.principal_id > 4
  AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys')
ORDER BY dp.name
""", database="master")
    orphaned = fetch_all_dicts(f"""
SELECT dp.name AS orphaned_user
FROM {quote_ident(database_name)}.sys.database_principals dp
LEFT JOIN master.sys.server_principals sp ON dp.sid = sp.sid
WHERE dp.type = 'S' AND dp.principal_id > 4
  AND dp.name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys')
  AND sp.sid IS NULL
ORDER BY dp.name
""", database="master")
    return {"database_users": users, "orphaned_users": orphaned,
            "orphaned_user_count": len(orphaned)}

# ==================================================
# TOOLS
# ==================================================

@mcp.tool()
def health():
    """Check MCP server status and configuration flags."""
    try:
        data = {
            "status": "running",
            "service": "mssql-dba-server",
            "host_configured": bool(MSSQL_HOST),
            "database_configured": bool(MSSQL_DB),
            "destructive_operations_enabled": ALLOW_DESTRUCTIVE,
            "allowed_backup_roots": BACKUP_ALLOWED_ROOTS,
            "default_data_dir": DEFAULT_DATA_DIR,
            "default_log_dir": DEFAULT_LOG_DIR
        }
        return ok(data=data)
    except Exception as e:
        return fail(str(e))


@mcp.tool()
def get_agent_capabilities():
    """Return the operations exposed by this DBA MCP server."""
    try:
        data = {
            "read_only_tools": [
                "health",
                "test_sql_connection",
                "list_databases",
                "describe_database",
                "get_backup_history",
                "check_blocking_sessions",
                "check_long_running_requests",
                "verify_backup",
                "prepare_restore_plan",
                "check_login_permissions",
                "list_server_role_members",
                "execute_query  (SELECT only — no approval needed)"
            ],
            "maintenance_tools": [
                "backup_database",
                "backup_log",
                "run_checkdb",
                "execute_sp  (stored procedure executor — any DB)"
            ],
            "destructive_tools": [
                "restore_database  (supports alternate target host)",
                "execute_query     (non-SELECT — requires approval_token)",
                "finalize_restore_permissions"
            ],
            "notes": [
                "execute_query: SELECT runs freely; INSERT/UPDATE/DELETE/DDL require ALLOW_DESTRUCTIVE=true + approval_token.",
                "execute_sp: pass sp_params as JSON string e.g. '{\"@Name\": \"test\", \"@ID\": 5}'.",
                "restore_database: optionally pass target_host/target_port/target_user/target_password to restore to a different server.",
                "backup and restore paths are restricted by BACKUP_ALLOWED_ROOTS."
            ]
        }
        return ok(data=data)
    except Exception as e:
        return fail(str(e))


@mcp.tool()
def test_sql_connection():
    """Test SQL connectivity and return server metadata."""
    try:
        row = fetch_one_dict("""
SELECT @@SERVERNAME AS server_name, DB_NAME() AS current_database,
       SUSER_SNAME() AS login_name, GETDATE() AS server_time, @@VERSION AS sql_version
""", database="master")
        return ok(data=row, message="SQL connection successful.")
    except Exception as e:
        return fail("SQL connection failed.", details=str(e))


@mcp.tool()
def list_databases():
    """List online databases with state, recovery model, and size."""
    try:
        rows = fetch_all_dicts("""
SELECT d.name AS database_name, d.state_desc, d.recovery_model_desc,
       d.compatibility_level, d.user_access_desc,
       CAST(SUM(mf.size) * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.databases d
LEFT JOIN sys.master_files mf ON d.database_id = mf.database_id
GROUP BY d.name, d.state_desc, d.recovery_model_desc,
         d.compatibility_level, d.user_access_desc
ORDER BY d.name
""", database="master")
        return ok(data=rows)
    except Exception as e:
        return fail(str(e))


@mcp.tool()
def describe_database(database_name: str):
    """Return database properties, files, and recent backup summary."""
    try:
        validate_db_name(database_name)
        db_info = fetch_one_dict("""
SELECT name AS database_name, state_desc, recovery_model_desc, containment_desc,
       compatibility_level, user_access_desc, is_read_only, create_date
FROM sys.databases WHERE name = ?
""", params=[database_name], database="master")
        if not db_info:
            return fail(f"Database '{database_name}' not found.")
        files = fetch_all_dicts("""
SELECT name AS logical_name, physical_name, type_desc, state_desc,
       CAST(size * 8.0 / 1024 AS DECIMAL(18,2)) AS size_mb
FROM sys.master_files WHERE database_id = DB_ID(?)
ORDER BY type_desc, name
""", params=[database_name], database="master")
        backup_summary = fetch_all_dicts("""
SELECT TOP 10 bs.database_name,
       CASE bs.type WHEN 'D' THEN 'FULL' WHEN 'I' THEN 'DIFF' WHEN 'L' THEN 'LOG'
       ELSE bs.type END AS backup_type,
       bs.backup_start_date, bs.backup_finish_date,
       CAST(bs.backup_size / 1024.0 / 1024.0 AS DECIMAL(18,2)) AS backup_size_mb,
       bmf.physical_device_name
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = ?
ORDER BY bs.backup_finish_date DESC
""", params=[database_name], database="master")
        return ok(data={"database": db_info, "files": files, "recent_backups": backup_summary})
    except Exception as e:
        return fail(str(e))


@mcp.tool()
def get_backup_history(database_name: str, top_n: int = 20):
    """Return recent backup history for a database."""
    try:
        validate_db_name(database_name)
        top_n = max(1, min(int(top_n), 100))
        rows = fetch_all_dicts(f"""
SELECT TOP ({top_n}) bs.database_name,
       CASE bs.type WHEN 'D' THEN 'FULL' WHEN 'I' THEN 'DIFF' WHEN 'L' THEN 'LOG'
       ELSE bs.type END AS backup_type,
       bs.backup_start_date, bs.backup_finish_date,
       CAST(bs.backup_size / 1024.0 / 1024.0 AS DECIMAL(18,2)) AS backup_size_mb,
       bs.server_name, bs.recovery_model, bs.is_copy_only, bmf.physical_device_name
FROM msdb.dbo.backupset bs
INNER JOIN msdb.dbo.backupmediafamily bmf ON bs.media_set_id = bmf.media_set_id
WHERE bs.database_name = ?
ORDER BY bs.backup_finish_date DESC
""", params=[database_name], database="master")
        return ok(data=rows)
    except Exception as e:
        return fail(str(e))


@mcp.tool()
def check_blocking_sessions():
    """Show active blocked and blocking sessions."""
    try:
        rows = fetch_all_dicts("""
SELECT r.session_id, r.blocking_session_id, r.status, r.command,
       DB_NAME(r.database_id) AS database_name, r.wait_type, r.wait_time,
       r.wait_resource, s.login_name, s.host_name, s.program_name, st.text AS sql_text
FROM sys.dm_exec_requests r
INNER JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) st
WHERE r.blocking_session_id <> 0
   OR r.session_id IN (
       SELECT DISTINCT blocking_session_id FROM sys.dm_exec_requests
       WHERE blocking_session_id <> 0
   )
ORDER BY r.blocking_session_id DESC, r.session_id
""", database="master")
        return ok(data=rows)
    except Exception as e:
        return fail(str(e))


@mcp.tool()
def check_long_running_requests(min_elapsed_seconds: int = 60):
    """Show running requests longer than the specified threshold."""
    try:
        min_elapsed_seconds = max(1, int(min_elapsed_seconds))
        rows = fetch_all_dicts("""
SELECT r.session_id, r.status, r.command, DB_NAME(r.database_id) AS database_name,
       r.cpu_time, r.total_elapsed_time / 1000 AS elapsed_seconds,
       r.reads, r.writes, s.login_name, s.host_name, s.program_name, st.text AS sql_text
FROM sys.dm_exec_requests r
INNER JOIN sys.dm_exec_sessions s ON r.session_id = s.session_id
OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) st
WHERE r.session_id <> @@SPID
  AND r.total_elapsed_time / 1000 >= ?
ORDER BY elapsed_seconds DESC
""", params=[min_elapsed_seconds], database="master")
        return ok(data=rows)
    except Exception as e:
        return fail(str(e))


# --------------------------------------------------
# NEW TOOL 1: execute_query
# --------------------------------------------------
@mcp.tool()
def execute_query(
    hostname: str,
    database_name: str,
    query: str,
    approval_token: str = ""
):
    """
    Execute a SQL query against any database on the configured SQL Server.

    - SELECT queries: run freely, no approval needed.
    - Non-SELECT queries (INSERT / UPDATE / DELETE / DDL / EXEC etc.):
      require ALLOW_DESTRUCTIVE=true and a valid approval_token.

    Parameters:
        hostname      : SQL Server hostname or IP (must match configured MSSQL_HOST).
        database_name : Target database to run the query against.
        query         : SQL query to execute.
        approval_token: Required only for non-SELECT statements.

    Returns rows for SELECT; affected-row count for DML.
    """
    request_payload = {
        "hostname": hostname,
        "database_name": database_name,
        "query": query
    }

    try:
        validate_db_name(database_name)

        if not query or not query.strip():
            return fail("Query cannot be empty.")

        is_select = bool(SELECT_RE.match(query.strip()))

        if not is_select:
            require_destructive_enabled()
            require_approval_token(approval_token)

        with get_conn(database_name, autocommit=not is_select) as conn:
            cursor = conn.cursor()
            cursor.execute(query)

            if is_select:
                if cursor.description:
                    columns = [col[0] for col in cursor.description]
                    rows = cursor.fetchall()
                    result = [dict(zip(columns, map(_serialize_value, row))) for row in rows]
                else:
                    result = []
                payload = {
                    "database_name": database_name,
                    "query_type": "SELECT",
                    "row_count": len(result),
                    "rows": result
                }
                audit("execute_query", "SUCCESS", database_name, request_payload, payload)
                return ok(data=payload, message=f"Query returned {len(result)} row(s).")
            else:
                affected = cursor.rowcount
                conn.commit()
                payload = {
                    "database_name": database_name,
                    "query_type": "NON-SELECT",
                    "rows_affected": affected
                }
                audit("execute_query", "SUCCESS", database_name, request_payload, payload)
                return ok(data=payload, message=f"Query executed. Rows affected: {affected}.")

    except Exception as e:
        error = fail("execute_query failed.", details=str(e))
        audit("execute_query", "FAILED", database_name, request_payload, error)
        return error


# --------------------------------------------------
# NEW TOOL 2: execute_sp
# --------------------------------------------------
@mcp.tool()
def execute_sp(
    hostname: str,
    database_name: str,
    schema_name: str,
    sp_name: str,
    sp_params: str = ""
):
    """
    Execute a stored procedure on the configured SQL Server.

    Parameters:
        hostname      : SQL Server hostname or IP (must match configured MSSQL_HOST).
        database_name : Database where the stored procedure lives.
        schema_name   : Schema of the SP (e.g. dbo).
        sp_name       : Name of the stored procedure (e.g. usp_GetOrders).
        sp_params     : JSON string of parameter name-value pairs.
                        Example: '{"@StartDate": "2025-01-01", "@StatusID": 2}'
                        Leave empty or '{}' if the SP takes no parameters.

    Returns all result sets produced by the stored procedure.
    """
    request_payload = {
        "hostname": hostname,
        "database_name": database_name,
        "schema_name": schema_name,
        "sp_name": sp_name,
        "sp_params": sp_params
    }

    try:
        validate_db_name(database_name)
        validate_simple_name(schema_name, "schema_name")
        validate_simple_name(sp_name, "sp_name")

        # Parse params
        params_dict = {}
        if sp_params and sp_params.strip() not in ("", "{}"):
            try:
                params_dict = json.loads(sp_params)
                if not isinstance(params_dict, dict):
                    raise ValueError("sp_params must be a JSON object (dict).")
            except json.JSONDecodeError as je:
                return fail(
                    "sp_params is not valid JSON.",
                    details=(
                        f"{je}. "
                        "Pass parameters as a JSON string like: "
                        '{\"@Param1\": \"value\", \"@Param2\": 42}'
                    )
                )

        # Validate param names (must start with @, alphanumeric + underscore only)
        param_name_re = re.compile(r"^@[A-Za-z0-9_]+$")
        for pname in params_dict:
            if not param_name_re.match(pname):
                return fail(f"Invalid parameter name: '{pname}'. Must match @AlphaNum_.")

        # Build: EXEC [db].[schema].[sp] @Param1 = ?, @Param2 = ?
        db_quoted     = quote_ident(database_name)
        schema_quoted = quote_ident(schema_name)
        sp_quoted     = quote_ident(sp_name)

        if params_dict:
            param_clause = ", ".join(f"{k} = ?" for k in params_dict.keys())
            sql = f"EXEC {db_quoted}.{schema_quoted}.{sp_quoted} {param_clause}"
            bound_values = list(params_dict.values())
        else:
            sql = f"EXEC {db_quoted}.{schema_quoted}.{sp_quoted}"
            bound_values = []

        result = execute_and_collect_messages(sql, params=bound_values, database=database_name)

        payload = {
            "hostname": hostname,
            "database_name": database_name,
            "sp_full_name": f"{database_name}.{schema_name}.{sp_name}",
            "params_used": params_dict,
            "result_sets": result["result_sets"],
            "messages": result["messages"],
            "result_set_count": len(result["result_sets"])
        }

        audit("execute_sp", "SUCCESS", database_name, request_payload, payload)
        return ok(data=payload, message=f"Stored procedure executed. {len(result['result_sets'])} result set(s) returned.")

    except Exception as e:
        error = fail("execute_sp failed.", details=str(e))
        audit("execute_sp", "FAILED", database_name, request_payload, error)
        return error


# --------------------------------------------------
# BACKUP TOOLS
# --------------------------------------------------
@mcp.tool()
def backup_database(
    database_name: str,
    backup_type: str,
    destination: str,
    copy_only: bool = False,
    checksum: bool = True,
    compress: bool = True
):
    """
    Run a FULL or DIFF database backup to an approved destination path.
    backup_type: FULL | DIFF
    """
    request_payload = {
        "database_name": database_name, "backup_type": backup_type,
        "destination": destination, "copy_only": copy_only,
        "checksum": checksum, "compress": compress
    }
    try:
        validate_db_name(database_name)
        backup_type = backup_type.strip().upper()
        if backup_type not in ("FULL", "DIFF"):
            raise ValueError("backup_type must be FULL or DIFF.")
        mount_share_if_needed(destination)
        sql = build_backup_sql(database_name, backup_type, destination,
                                copy_only, checksum, compress)
        result = execute_and_collect_messages(sql, params=[destination], database="master")
        payload = {"database_name": database_name, "backup_type": backup_type,
                   "destination": destination, "messages": result["messages"]}
        audit("backup_database", "SUCCESS", database_name, request_payload, payload)
        return ok(data=payload, message="Backup completed.")
    except Exception as e:
        error = fail("Backup failed.", details=str(e))
        audit("backup_database", "FAILED", database_name, request_payload, error)
        return error


@mcp.tool()
def backup_log(
    database_name: str,
    destination: str,
    checksum: bool = True,
    compress: bool = True
):
    """Run a transaction log backup to an approved destination path."""
    request_payload = {"database_name": database_name, "destination": destination,
                       "checksum": checksum, "compress": compress}
    try:
        validate_db_name(database_name)
        recovery_info = fetch_one_dict(
            "SELECT recovery_model_desc FROM sys.databases WHERE name = ?",
            params=[database_name], database="master"
        )
        if not recovery_info:
            raise ValueError(f"Database '{database_name}' not found.")
        if recovery_info["recovery_model_desc"] not in ("FULL", "BULK_LOGGED"):
            raise ValueError(
                f"Database recovery model is {recovery_info['recovery_model_desc']}. "
                "Log backup is usually not applicable."
            )
        mount_share_if_needed(destination)
        sql = build_log_backup_sql(database_name, destination, checksum, compress)
        result = execute_and_collect_messages(sql, params=[destination], database="master")
        payload = {"database_name": database_name, "destination": destination,
                   "messages": result["messages"]}
        audit("backup_log", "SUCCESS", database_name, request_payload, payload)
        return ok(data=payload, message="Log backup completed.")
    except Exception as e:
        error = fail("Log backup failed.", details=str(e))
        audit("backup_log", "FAILED", database_name, request_payload, error)
        return error


@mcp.tool()
def verify_backup(backup_file: str):
    """Verify a backup file using RESTORE VERIFYONLY. Does not restore."""
    request_payload = {"backup_file": backup_file}
    try:
        ensure_path_allowed(backup_file)
        header   = get_backup_header(backup_file)
        filelist = get_database_file_list_from_backup(backup_file)
        verify_result = execute_and_collect_messages(
            "RESTORE VERIFYONLY FROM DISK = ?", params=[backup_file], database="master"
        )
        payload = {"backup_file": backup_file, "header": header,
                   "filelist": filelist, "messages": verify_result["messages"]}
        audit("verify_backup", "SUCCESS", None, request_payload, payload)
        return ok(data=payload, message="Backup verification completed.")
    except Exception as e:
        error = fail("Backup verification failed.", details=str(e))
        audit("verify_backup", "FAILED", None, request_payload, error)
        return error


@mcp.tool()
def prepare_restore_plan(
    backup_file: str,
    target_database: str,
    replace_existing: bool = False,
    restore_as_new_database: bool = False,
    recovery_mode: str = "RECOVERY"
):
    """Prepare a restore plan without executing the restore."""
    request_payload = {
        "backup_file": backup_file, "target_database": target_database,
        "replace_existing": replace_existing,
        "restore_as_new_database": restore_as_new_database,
        "recovery_mode": recovery_mode
    }
    try:
        ensure_path_allowed(backup_file)
        validate_db_name(target_database)
        recovery_mode = recovery_mode.strip().upper()
        if recovery_mode not in ("RECOVERY", "NORECOVERY"):
            raise ValueError("recovery_mode must be RECOVERY or NORECOVERY.")
        header   = get_backup_header(backup_file)
        filelist = get_database_file_list_from_backup(backup_file)
        if not header:
            raise ValueError("Backup header could not be read.")
        target_db = fetch_one_dict(
            "SELECT name AS database_name, state_desc, recovery_model_desc FROM sys.databases WHERE name = ?",
            params=[target_database], database="master"
        )
        move_clauses, generated_files = infer_move_clauses(filelist, target_database)
        payload = {
            "backup_file": backup_file, "target_database": target_database,
            "target_database_exists": bool(target_db), "target_database_info": target_db,
            "replace_existing": replace_existing,
            "restore_as_new_database": restore_as_new_database,
            "recovery_mode": recovery_mode, "header": header, "filelist": filelist,
            "generated_move_clauses": move_clauses, "generated_target_files": generated_files,
            "risk_notes": [
                "This is a planning step only. No restore has been executed.",
                "If target database exists and replace_existing is false, restore execution will fail.",
                "Ensure active connections and tail-log considerations are handled before executing."
            ]
        }
        audit("prepare_restore_plan", "SUCCESS", target_database, request_payload, payload)
        return ok(data=payload, message="Restore plan prepared.")
    except Exception as e:
        error = fail("Prepare restore plan failed.", details=str(e))
        audit("prepare_restore_plan", "FAILED", target_database, request_payload, error)
        return error


# --------------------------------------------------
# UPDATED TOOL: restore_database (with alternate host)
# --------------------------------------------------
@mcp.tool()
def restore_database(
    backup_file: str,
    target_database: str,
    approval_token: str,
    replace_existing: bool = False,
    recovery_mode: str = "RECOVERY",
    target_host: str = "",
    target_port: str = "",
    target_user: str = "",
    target_password: str = ""
):
    """
    Execute a database restore from a trusted backup file.

    Supports restoring to an alternate SQL Server host (e.g. DR or staging server).

    Parameters:
        backup_file      : Full path to the .bak file (must be within BACKUP_ALLOWED_ROOTS).
        target_database  : Name of the database to restore into.
        approval_token   : Must match APPROVAL_TOKEN in .env.
        replace_existing : Set True to overwrite an existing database.
        recovery_mode    : RECOVERY (online after restore) or NORECOVERY (for log chain).
        target_host      : Optional. Alternate SQL Server IP/hostname. Defaults to MSSQL_HOST.
        target_port      : Optional. Alternate SQL Server port. Defaults to MSSQL_PORT.
        target_user      : Optional. SQL login for alternate host. Defaults to MSSQL_USER.
        target_password  : Optional. Password for alternate host. Defaults to MSSQL_PASSWORD.

    Requires:
        - ALLOW_DESTRUCTIVE=true in .env
        - valid approval_token
    """
    request_payload = {
        "backup_file": backup_file, "target_database": target_database,
        "replace_existing": replace_existing, "recovery_mode": recovery_mode,
        "target_host": target_host or "(default)", "target_port": target_port or "(default)"
    }

    try:
        require_destructive_enabled()
        require_approval_token(approval_token)
        ensure_path_allowed(backup_file)
        validate_db_name(target_database)

        recovery_mode = recovery_mode.strip().upper()
        if recovery_mode not in ("RECOVERY", "NORECOVERY"):
            raise ValueError("recovery_mode must be RECOVERY or NORECOVERY.")

        # Resolve connection params for alternate host
        _host     = target_host.strip()     or MSSQL_HOST
        _port     = target_port.strip()     or MSSQL_PORT
        _user     = target_user.strip()     or MSSQL_USER
        _password = target_password.strip() or MSSQL_PASSWORD

        conn_kwargs = dict(host=_host, port=_port, user=_user, password=_password)

        # Check if target DB already exists on the target host
        target_db = fetch_one_dict(
            "SELECT name, state_desc FROM sys.databases WHERE name = ?",
            params=[target_database], database="master", **conn_kwargs
        )

        if target_db and not replace_existing:
            raise ValueError(
                f"Target database '{target_database}' already exists on {_host}. "
                "Set replace_existing=true to overwrite."
            )

        filelist = get_database_file_list_from_backup(backup_file, **conn_kwargs)
        if not filelist:
            raise ValueError("Backup file list is empty; restore cannot proceed.")

        move_clauses, generated_files = infer_move_clauses(filelist, target_database)

        restore_parts = [
            f"RESTORE DATABASE {quote_ident(target_database)}",
            "FROM DISK = ?",
            "WITH",
            ", ".join(move_clauses)
        ]
        if replace_existing:
            restore_parts.append(", REPLACE")
        restore_parts.append(f", {recovery_mode}")
        restore_parts.append(", STATS = 10")

        restore_sql = "\n".join(restore_parts)

        result = execute_and_collect_messages(
            restore_sql, params=[backup_file], database="master", **conn_kwargs
        )

        payload = {
            "backup_file": backup_file, "target_database": target_database,
            "target_host": _host, "target_port": _port,
            "replace_existing": replace_existing, "recovery_mode": recovery_mode,
            "generated_target_files": generated_files, "messages": result["messages"]
        }

        audit("restore_database", "SUCCESS", target_database, request_payload, payload)
        return ok(data=payload, message=f"Restore completed on host '{_host}'.")

    except Exception as e:
        error = fail("Restore failed.", details=str(e))
        audit("restore_database", "FAILED", target_database, request_payload, error)
        return error


@mcp.tool()
def run_checkdb(
    database_name: str,
    physical_only: bool = True,
    no_infomsgs: bool = True
):
    """Run DBCC CHECKDB on the specified database."""
    request_payload = {"database_name": database_name,
                       "physical_only": physical_only, "no_infomsgs": no_infomsgs}
    try:
        validate_db_name(database_name)
        options = []
        if physical_only: options.append("PHYSICAL_ONLY")
        if no_infomsgs:   options.append("NO_INFOMSGS")
        option_clause = (" WITH " + ", ".join(options)) if options else ""
        sql = f"DBCC CHECKDB ({quote_ident(database_name)}){option_clause};"
        result = execute_and_collect_messages(sql, database="master")
        payload = {"database_name": database_name, "physical_only": physical_only,
                   "no_infomsgs": no_infomsgs,
                   "messages": result["messages"], "result_sets": result["result_sets"]}
        audit("run_checkdb", "SUCCESS", database_name, request_payload, payload)
        return ok(data=payload, message="DBCC CHECKDB completed.")
    except Exception as e:
        error = fail("DBCC CHECKDB failed.", details=str(e))
        audit("run_checkdb", "FAILED", database_name, request_payload, error)
        return error


@mcp.tool()
def check_login_permissions(login_name: str = "dbaagent"):
    """Get server permissions for a login."""
    conn = get_conn()
    cursor = conn.cursor()
    query = """
SELECT B.name AS login_name, A.permission_name, A.state_desc, B.type_desc
FROM sys.server_permissions A
JOIN sys.server_principals B ON A.grantee_principal_id = B.principal_id
WHERE B.name = ?
"""
    cursor.execute(query, login_name)
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


@mcp.tool()
def finalize_restore_permissions(
    target_database: str,
    approval_token: str,
    database_previously_existed: bool,
    copy_rights_schema: str = "dbo",
    copy_rights_sp: str = "copy_rights_sp",
    apply_rights_schema: str = "dbo",
    apply_rights_sp: str = "apply_rights_sp",
    revalidate_access: bool = True
):
    """
    Finalize post-restore permission handling.
    Steps: validate SPs exist → copy-rights (if DB existed) → bring online → apply-rights → revalidate.
    Requires ALLOW_DESTRUCTIVE=true and valid approval_token.
    """
    request_payload = {
        "target_database": target_database,
        "database_previously_existed": database_previously_existed,
        "copy_rights_schema": copy_rights_schema, "copy_rights_sp": copy_rights_sp,
        "apply_rights_schema": apply_rights_schema, "apply_rights_sp": apply_rights_sp,
        "revalidate_access": revalidate_access
    }
    try:
        require_destructive_enabled()
        require_approval_token(approval_token)
        validate_db_name(target_database)
        if not database_exists(target_database):
            raise ValueError(f"Target database '{target_database}' does not exist after restore.")
        copy_exists  = stored_procedure_exists("msdb", copy_rights_schema, copy_rights_sp)
        apply_exists = stored_procedure_exists("msdb", apply_rights_schema, apply_rights_sp)
        if not copy_exists:
            raise ValueError(f"Required SP msdb.{copy_rights_schema}.{copy_rights_sp} not found.")
        if not apply_exists:
            raise ValueError(f"Required SP msdb.{apply_rights_schema}.{apply_rights_sp} not found.")
        actions = []
        if database_previously_existed:
            copy_result = execute_msdb_procedure(copy_rights_schema, copy_rights_sp, target_database)
            actions.append({"step": "copy_rights", "status": "executed",
                            "messages": copy_result.get("messages", [])})
        else:
            actions.append({"step": "copy_rights", "status": "skipped",
                            "reason": "Target database is new."})
        online_result = bring_database_online(target_database)
        actions.append({"step": "bring_database_online", "status": "executed",
                        "messages": online_result.get("messages", [])})
        apply_result = execute_msdb_procedure(apply_rights_schema, apply_rights_sp, target_database)
        actions.append({"step": "apply_rights", "status": "executed",
                        "messages": apply_result.get("messages", [])})
        validation_result = None
        if revalidate_access:
            validation_result = validate_access_restoration(target_database)
            actions.append({"step": "revalidate_access", "status": "executed",
                            "orphaned_user_count": validation_result["orphaned_user_count"]})
        else:
            actions.append({"step": "revalidate_access", "status": "skipped"})
        db_state = get_database_state(target_database)
        payload = {
            "target_database": target_database,
            "database_previously_existed": database_previously_existed,
            "stored_procedures_found": {
                "copy_rights":  f"msdb.{copy_rights_schema}.{copy_rights_sp}",
                "apply_rights": f"msdb.{apply_rights_schema}.{apply_rights_sp}"
            },
            "database_state": db_state, "actions": actions,
            "validation_result": validation_result
        }
        audit("finalize_restore_permissions", "SUCCESS", target_database, request_payload, payload)
        return ok(data=payload, message="Restore permission finalization completed.")
    except Exception as e:
        error = fail("Restore permission finalization failed.", details=str(e))
        audit("finalize_restore_permissions", "FAILED", target_database, request_payload, error)
        return error


@mcp.tool()
def list_server_role_members():
    """Get all SQL Server role memberships and member login details."""
    conn = get_conn()
    cursor = conn.cursor()
    query = """
SELECT r.name AS server_role, m.name AS member_name, m.type_desc AS member_type,
       CASE WHEN m.type = 'S' THEN 'SQL Login'
            WHEN m.type = 'U' THEN 'Windows Login'
            WHEN m.type = 'G' THEN 'Windows Group'
            ELSE m.type_desc END AS member_login_type,
       m.is_disabled AS login_disabled
FROM sys.server_role_members rm
INNER JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
INNER JOIN sys.server_principals m ON rm.member_principal_id = m.principal_id
WHERE r.type = 'R'
ORDER BY r.name, m.name
"""
    cursor.execute(query)
    columns = [column[0] for column in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


# --------------------------------------------------
# ENTRYPOINT
# --------------------------------------------------
TRANSPORT = os.getenv("MCP_TRANSPORT", "stdio").strip().lower()

if TRANSPORT == "http":
    app = mcp.streamable_http_app()
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
elif TRANSPORT == "sse":
    app = mcp.sse_app()

if __name__ == "__main__":
    if TRANSPORT in ("http", "sse"):
        port = int(os.environ.get("PORT", 8000))
        uvicorn.run(
            "app.server:app",
            host="0.0.0.0",
            port=port,
            log_level="info",
            proxy_headers=True,
            forwarded_allow_ips="*"
        )
    else:
        try:
            mcp.run()
        except Exception as e:
            sys.stderr.write("Fatal server error:\n")
            sys.stderr.write(str(e) + "\n")
            sys.stderr.write(traceback.format_exc() + "\n")
            raise
server.py.txt
Displaying server.py.txt.