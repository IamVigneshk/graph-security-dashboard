import os
import logging
import threading
import queue
import kuzu

logger = logging.getLogger("security_graph.db")

DB_DIR = os.getenv("KUZU_DB_DIR", "./graph_db")

# ──────────────────────────────────────────────────────────────────────────────
# Dedicated DB Worker Queue Architecture
# Kuzu's C++ engine requires ALL database & connection operations to occur on
# a single OS thread. To prevent any thread conflicts between FastAPI/Uvicorn
# async loops and background scanner threads, we route ALL queries through a
# dedicated singleton worker thread.
# ──────────────────────────────────────────────────────────────────────────────
_db_queue = queue.Queue()


def _db_worker_loop():
    logger.info(f"Initializing Kuzu Database on dedicated worker thread at: {DB_DIR}")
    db = kuzu.Database(DB_DIR)
    conn = kuzu.Connection(db)
    
    # Auto-initialize schemas on worker startup
    _init_schema_on_conn(conn)

    while True:
        task = _db_queue.get()
        if task is None:
            break
        fn, args, kwargs, result_holder, event = task
        try:
            res = fn(conn, *args, **kwargs)
            result_holder["result"] = res
        except Exception as e:
            result_holder["error"] = e
        finally:
            event.set()
            _db_queue.task_done()


def _run_on_db_thread(fn, *args, **kwargs):
    result_holder = {}
    event = threading.Event()
    _db_queue.put((fn, args, kwargs, result_holder, event))
    event.wait()
    if "error" in result_holder:
        raise result_holder["error"]
    return result_holder.get("result")


# Start the dedicated DB worker thread automatically
_worker_thread = threading.Thread(target=_db_worker_loop, daemon=True, name="KuzuDBWorker")
_worker_thread.start()


def _init_schema_on_conn(conn: kuzu.Connection):
    node_tables = {
        "Machine":      "CREATE NODE TABLE Machine(id STRING, name STRING, private_ip STRING, public_ip STRING, owner STRING, os STRING, internal_tags STRING[], cloud_tags STRING, has_defender BOOLEAN, has_crowdstrike BOOLEAN, riskScore INT64, PRIMARY KEY(id))",
        "CloudResource":"CREATE NODE TABLE CloudResource(id STRING, name STRING, type STRING, region STRING, resource_group STRING, internal_tags STRING[], PRIMARY KEY(id))",
        "Incident":     "CREATE NODE TABLE Incident(id STRING, title STRING, severity STRING, status STRING, description STRING, created_at STRING, PRIMARY KEY(id))",
        "Alert":        "CREATE NODE TABLE Alert(id STRING, name STRING, category STRING, evidence STRING, PRIMARY KEY(id))",
        "User":         "CREATE NODE TABLE User(id STRING, email STRING, role STRING, privilege STRING, riskScore INT64, PRIMARY KEY(id))",
    }
    rel_tables = {
        "AFFECTS":      "CREATE REL TABLE AFFECTS(FROM Incident TO Machine)",
        "HOSTED_IN":    "CREATE REL TABLE HOSTED_IN(FROM Machine TO CloudResource)",
        "CONTAINED_IN": "CREATE REL TABLE CONTAINED_IN(FROM CloudResource TO CloudResource)",
        "INCLUDES":     "CREATE REL TABLE INCLUDES(FROM Incident TO Alert)",
        "LOGGED_IN_TO": "CREATE REL TABLE LOGGED_IN_TO(FROM User TO Machine)",
        "AFFECTS_USER": "CREATE REL TABLE AFFECTS_USER(FROM Incident TO User)",
    }

    for name, cypher in node_tables.items():
        try:
            conn.execute(cypher)
            logger.info(f"Node table '{name}' created.")
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                logger.debug(f"Node table '{name}' already exists.")
            else:
                logger.error(f"Error creating node table '{name}': {e}")

    for name, cypher in rel_tables.items():
        try:
            conn.execute(cypher)
            logger.info(f"Rel table '{name}' created.")
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                logger.debug(f"Rel table '{name}' already exists.")
            else:
                logger.error(f"Error creating rel table '{name}': {e}")


def init_schema():
    """Trigger schema init (runs safely on dedicated worker thread)."""
    def _do_init(conn):
        _init_schema_on_conn(conn)
    _run_on_db_thread(_do_init)


def execute_query(query: str, params: dict = None) -> list[dict]:
    """
    Executes a Cypher query safely on the dedicated Kuzu DB worker thread.
    """
    def _do_exec(conn):
        if params:
            result = conn.execute(query, params)
        else:
            result = conn.execute(query)

        columns = result.get_column_names()
        rows = []
        while result.has_next():
            row_values = result.get_next()
            rows.append(dict(zip(columns, row_values)))
        return rows

    return _run_on_db_thread(_do_exec)


def clear_database():
    """
    Deletes all graph data (edges first, then nodes) on the dedicated DB thread.
    """
    logger.warning("Clearing all graph data for full resync...")
    stmts = [
        "MATCH (a)-[r:AFFECTS]->(b) DELETE r",
        "MATCH (a)-[r:HOSTED_IN]->(b) DELETE r",
        "MATCH (a)-[r:CONTAINED_IN]->(b) DELETE r",
        "MATCH (a)-[r:INCLUDES]->(b) DELETE r",
        "MATCH (a)-[r:LOGGED_IN_TO]->(b) DELETE r",
        "MATCH (a)-[r:AFFECTS_USER]->(b) DELETE r",
        "MATCH (m:Machine) DELETE m",
        "MATCH (c:CloudResource) DELETE c",
        "MATCH (i:Incident) DELETE i",
        "MATCH (a:Alert) DELETE a",
        "MATCH (u:User) DELETE u",
    ]
    for q in stmts:
        try:
            execute_query(q)
        except Exception as e:
            logger.error(f"Cleanup query failed '{q}': {e}")


def update_node_tags(node_id: str, tags: list[str]) -> bool:
    """Updates internal_tags on a Machine or CloudResource node."""
    for q in [
        "MATCH (m:Machine) WHERE m.id = $id SET m.internal_tags = $tags RETURN m.id",
        "MATCH (c:CloudResource) WHERE c.id = $id SET c.internal_tags = $tags RETURN c.id",
    ]:
        try:
            res = execute_query(q, {"id": node_id, "tags": tags})
            if res:
                return True
        except Exception as e:
            logger.error(f"Tag update failed: {e}")
    return False
