import asyncio
import json
import os
from mcp.server import Server
from mcp.types import Tool, TextContent
import pyodbc

app = Server("sql-mcp-server")

@app.list_tools()
async def list_tools():
    return [
        Tool(
            name="execute_sql",
            description="Execute SQL query on your Azure VM SQL Server",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string", 
                        "description": "SQL query to execute (SELECT, INSERT, UPDATE, DELETE, etc.)"
                    }
                },
                "required": ["query"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "execute_sql":
        # Get connection string from environment variable
        conn_str = os.getenv("SQL_CONNECTION_STRING")
        
        if not conn_str:
            return [TextContent(
                type="text", 
                text="Error: SQL_CONNECTION_STRING environment variable not set"
            )]
        
        try:
            # Connect to SQL Server on your Azure VM
            conn = pyodbc.connect(conn_str)
            cursor = conn.cursor()
            
            # Execute the query
            query = arguments.get("query", "")
            cursor.execute(query)
            
            # Check if it's a SELECT query
            if query.strip().upper().startswith("SELECT"):
                rows = cursor.fetchall()
                columns = [column[0] for column in cursor.description]
                result = [dict(zip(columns, row)) for row in rows]
                return [TextContent(
                    type="text", 
                    text=json.dumps(result, indent=2, default=str)
                )]
            else:
                # For INSERT, UPDATE, DELETE queries
                conn.commit()
                return [TextContent(
                    type="text", 
                    text=f"Query executed successfully. {cursor.rowcount} rows affected."
                )]
                
        except Exception as e:
            return [TextContent(type="text", text=f"Database error: {str(e)}")]
        finally:
            conn.close()

if __name__ == "__main__":
    asyncio.run(app.run())
