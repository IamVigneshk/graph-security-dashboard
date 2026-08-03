import os
import asyncio
import queue
import logging
import threading
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src.backend.db import init_schema, execute_query, update_node_tags
from src.backend.scanner import run_azure_defender_scan

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("security_graph.app")

app = FastAPI(
    title="Security Graph Agent Backend",
    description="Embedded Graph API server for Azure Resource Topology & Defender Alerts"
)

@app.on_event("startup")
def startup_event():
    try:
        init_schema()
        from src.backend.scanner import run_azure_defender_scan
        run_azure_defender_scan()
    except Exception as e:
        logger.error(f"Error during startup initialization: {e}")


# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class TagUpdateRequest(BaseModel):
    id: str
    tags: list[str]

class QueryRequest(BaseModel):
    query: str

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "engine": "Kuzu Graph Engine"}

@app.post("/api/scan")
async def trigger_scan():
    """
    Triggers Azure & Defender scan via async SSE streaming response.
    """
    q = asyncio.Queue()
    loop = asyncio.get_running_loop()

    def callback(msg):
        loop.call_soon_threadsafe(q.put_nowait, msg)

    def runner():
        try:
            run_azure_defender_scan(callback)
        except Exception as e:
            logger.error(f"Scan error: {e}")
            loop.call_soon_threadsafe(q.put_nowait, f"[Error] {e}")
        finally:
            loop.call_soon_threadsafe(q.put_nowait, None)

    threading.Thread(target=runner, daemon=True).start()

    async def event_generator():
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=30.0)
                if msg is None:
                    break
                yield f"data: {msg}\n\n"
            except asyncio.TimeoutError:
                yield "data: [Heartbeat] Scan in progress...\n\n"
            except (Exception, BaseException):
                break
        try:
            yield "data: [DONE]\n\n"
        except (Exception, BaseException):
            pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/graph")
def get_graph():
    """
    Fetches nodes and relationships from Kuzu database and formats them for Cytoscape.js.
    Each node/edge type is fetched independently so one failure doesn't kill the whole response.
    """
    nodes = []
    edges = []

    # 1. Fetch Machines
    try:
        machines = execute_query("MATCH (m:Machine) RETURN m.id, m.name, m.private_ip, m.public_ip, m.owner, m.os, m.internal_tags, m.cloud_tags")
        for m in machines:
            nodes.append({
                "data": {
                    "id": m["m.id"],
                    "label": m["m.name"],
                    "type": "Machine",
                    "private_ip": m["m.private_ip"],
                    "public_ip": m["m.public_ip"],
                    "owner": m["m.owner"],
                    "os": m["m.os"],
                    "internal_tags": m["m.internal_tags"],
                    "cloud_tags": m["m.cloud_tags"],
                    "riskScore": 15
                }
            })
    except Exception as e:
        logger.error(f"Error fetching Machines: {e}")

    # 2. Fetch Cloud Resources
    try:
        resources = execute_query("MATCH (c:CloudResource) RETURN c.id, c.name, c.type, c.region, c.resource_group, c.internal_tags")
        for r in resources:
            nodes.append({
                "data": {
                    "id": r["c.id"],
                    "label": r["c.name"],
                    "type": r["c.type"].capitalize() if r["c.type"] else "CloudResource",
                    "resource_type": r["c.type"],
                    "region": r["c.region"],
                    "resource_group": r["c.resource_group"],
                    "internal_tags": r["c.internal_tags"]
                }
            })
    except Exception as e:
        logger.error(f"Error fetching CloudResources: {e}")

    # 3. Fetch Incidents
    try:
        incidents = execute_query("MATCH (i:Incident) RETURN i.id, i.title, i.severity, i.status, i.description, i.created_at")
        for i in incidents:
            nodes.append({
                "data": {
                    "id": i["i.id"],
                    "label": i["i.title"].split(":")[-1].strip(),
                    "type": "Incident",
                    "severity": i["i.severity"],
                    "status": i["i.status"],
                    "description": i["i.description"],
                    "created_at": i["i.created_at"]
                }
            })
    except Exception as e:
        logger.error(f"Error fetching Incidents: {e}")

    # 4. Fetch Alerts
    try:
        alerts = execute_query("MATCH (a:Alert) RETURN a.id, a.name, a.category, a.evidence")
        for a in alerts:
            nodes.append({
                "data": {
                    "id": a["a.id"],
                    "label": a["a.name"].split(":")[-1].strip(),
                    "type": "Alert",
                    "category": a["a.category"],
                    "evidence": a["a.evidence"]
                }
            })
    except Exception as e:
        logger.error(f"Error fetching Alerts: {e}")

    # 4.5 Fetch Users (served from live Entra ID memory store + DB fallback)
    user_nodes_added = set()
    user_node_ids = []
    try:
        from src.backend.scanner import get_live_users
        for u in get_live_users():
            u_id = u["id"]
            if u_id not in user_nodes_added:
                user_nodes_added.add(u_id)
                user_node_ids.append(u_id)
                nodes.append({
                    "data": {
                        "id": u_id,
                        "label": u_id.split("@")[0] if "@" in (u_id or "") else (u_id or "User"),
                        "type": "User",
                        "email": u.get("email") or u_id,
                        "role": u.get("role") or "User",
                        "privilege": u.get("privilege") or "Standard User",
                        "riskScore": u.get("riskScore") or 10
                    }
                })
    except Exception as e:
        logger.error(f"Error fetching Users from memory store: {e}")

    try:
        users = execute_query("MATCH (u:User) RETURN u.id, u.email, u.role, u.privilege")
        for u in users:
            u_id = u["u.id"]
            if u_id not in user_nodes_added:
                user_nodes_added.add(u_id)
                user_node_ids.append(u_id)
                nodes.append({
                    "data": {
                        "id": u_id,
                        "label": u_id.split("@")[0] if "@" in (u_id or "") else (u_id or "User"),
                        "type": "User",
                        "email": u.get("u.email") or u_id,
                        "role": u.get("u.role") or "User",
                        "privilege": u.get("u.privilege") or "Standard User",
                        "riskScore": 10
                    }
                })
    except Exception as e:
        logger.error(f"Error fetching Users from Kuzu DB: {e}")

    # Generate LOGGED_IN_TO topological edges (User -> Machine)
    machine_ids = [n["data"]["id"] for n in nodes if n["data"].get("type") == "Machine"]
    if machine_ids and user_node_ids:
        for idx, u_id in enumerate(user_node_ids):
            target_m = machine_ids[idx % len(machine_ids)]
            edges.append({
                "data": {
                    "id": f"{u_id}-{target_m}-logged_in",
                    "source": u_id,
                    "target": target_m,
                    "type": "LOGGED_IN_TO"
                }
            })





    # 5. Fetch AFFECTS edges (Incident -> Machine)
    try:
        affects_edges = execute_query("MATCH (i:Incident)-[r:AFFECTS]->(m:Machine) RETURN i.id, m.id")
        for e in affects_edges:
            edges.append({
                "data": {
                    "id": f"{e['i.id']}-{e['m.id']}-affects",
                    "source": e["i.id"],
                    "target": e["m.id"],
                    "type": "AFFECTS"
                }
            })
    except Exception as e:
        logger.error(f"Error fetching AFFECTS edges: {e}")

    # 6. Fetch HOSTED_IN edges (Machine -> CloudResource)
    try:
        hosted_edges = execute_query("MATCH (m:Machine)-[r:HOSTED_IN]->(c:CloudResource) RETURN m.id, c.id")
        for e in hosted_edges:
            edges.append({
                "data": {
                    "id": f"{e['m.id']}-{e['c.id']}-hosted_in",
                    "source": e["m.id"],
                    "target": e["c.id"],
                    "type": "HOSTED_IN"
                }
            })
    except Exception as e:
        logger.error(f"Error fetching HOSTED_IN edges: {e}")

    # 7. Fetch CONTAINED_IN edges (CloudResource -> CloudResource)
    try:
        contained_edges = execute_query("MATCH (c1:CloudResource)-[r:CONTAINED_IN]->(c2:CloudResource) RETURN c1.id, c2.id")
        for e in contained_edges:
            edges.append({
                "data": {
                    "id": f"{e['c1.id']}-{e['c2.id']}-contained_in",
                    "source": e["c1.id"],
                    "target": e["c2.id"],
                    "type": "CONTAINED_IN"
                }
            })
    except Exception as e:
        logger.error(f"Error fetching CONTAINED_IN edges: {e}")

    # 8. Fetch INCLUDES edges (Incident -> Alert)
    try:
        includes_edges = execute_query("MATCH (i:Incident)-[r:INCLUDES]->(a:Alert) RETURN i.id, a.id")
        for e in includes_edges:
            edges.append({
                "data": {
                    "id": f"{e['i.id']}-{e['a.id']}-includes",
                    "source": e["i.id"],
                    "target": e["a.id"],
                    "type": "INCLUDES"
                }
            })
    except Exception as e:
        logger.error(f"Error fetching INCLUDES edges: {e}")

    # 9. Fetch LOGGED_IN_TO edges (User -> Machine)
    try:
        logged_edges = execute_query("MATCH (u:User)-[r:LOGGED_IN_TO]->(m:Machine) RETURN u.id, m.id")
        for e in logged_edges:
            edges.append({
                "data": {
                    "id": f"{e['u.id']}-{e['m.id']}-logged_in_to",
                    "source": e["u.id"],
                    "target": e["m.id"],
                    "type": "LOGGED_IN_TO"
                }
            })
    except Exception as e:
        logger.error(f"Error fetching LOGGED_IN_TO edges: {e}")

    # 10. Fetch AFFECTS_USER edges (Incident -> User)
    try:
        affects_user_edges = execute_query("MATCH (i:Incident)-[r:AFFECTS_USER]->(u:User) RETURN i.id, u.id")
        for e in affects_user_edges:
            edges.append({
                "data": {
                    "id": f"{e['i.id']}-{e['u.id']}-affects_user",
                    "source": e["i.id"],
                    "target": e["u.id"],
                    "type": "AFFECTS_USER"
                }
            })
    except Exception as e:
        logger.error(f"Error fetching AFFECTS_USER edges: {e}")

    return {"nodes": nodes, "edges": edges}

@app.post("/api/tags")
def update_tags(payload: TagUpdateRequest):
    """
    Updates the local tag layer for a given Node.
    """
    success = update_node_tags(payload.id, payload.tags)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node with ID '{payload.id}' not found or tag update failed."
        )
    return {"message": "Node tags updated successfully", "id": payload.id, "tags": payload.tags}

@app.post("/api/query")
def run_custom_query(payload: QueryRequest):
    """
    Executes a custom Cypher query against the Kuzu database.
    """
    try:
        results = execute_query(payload.query)
        return {"results": results}
    except Exception as e:
        logger.error(f"Error executing custom query '{payload.query}': {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cypher error: {str(e)}"
        )

# Serve React static build files if available
frontend_dist_path = "src/frontend/dist"
if os.path.exists(frontend_dist_path):
    app.mount("/", StaticFiles(directory=frontend_dist_path, html=True), name="static")
    logger.info(f"Mounted React static build directory from: {frontend_dist_path}")
else:
    logger.warning(
        f"React build files not found at '{frontend_dist_path}'. "
        "Run the server in development mode. API is serving endpoints on /api/*"
    )

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("src.backend.app:app", host="0.0.0.0", port=port, reload=False)

