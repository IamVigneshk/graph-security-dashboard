from mcp.server.fastmcp import FastMCP
from src.backend.db import execute_query

mcp = FastMCP("SecurityGraphAgent")

@mcp.tool()
def get_graph_schema() -> str:
    """
    Returns the graph schema detailing nodes and relationship connections.
    Use this tool to understand node types, properties, and relationship mappings.
    """
    return """
    Nodes:
      - Machine {
          id: STRING (Primary Key),
          name: STRING,
          private_ip: STRING,
          public_ip: STRING,
          owner: STRING,
          os: STRING,
          internal_tags: STRING[],
          cloud_tags: STRING
        }
      - CloudResource {
          id: STRING (Primary Key),
          name: STRING,
          type: STRING (e.g., 'virtualnetwork', 'subnet', 'storageaccount', 'keyvault'),
          region: STRING,
          resource_group: STRING,
          internal_tags: STRING[]
        }
      - Incident {
          id: STRING (Primary Key),
          title: STRING,
          severity: STRING (e.g., 'High', 'Medium', 'Low'),
          status: STRING (e.g., 'Active', 'Investigating', 'Resolved'),
          description: STRING,
          created_at: STRING
        }
      - Alert {
          id: STRING (Primary Key),
          name: STRING,
          category: STRING,
          evidence: STRING
        }

    Relationships:
      - (:Incident)-[:AFFECTS]->(:Machine) (Represents endpoints affected by an incident)
      - (:Machine)-[:HOSTED_IN]->(:CloudResource) (VM mapping inside subnet topology)
      - (:CloudResource)-[:HOSTED_IN]->(:CloudResource) (e.g., Subnet hosted in Virtual Network)
      - (:Incident)-[:INCLUDES]->(:Alert) (Correlates security alerts within an incident)
    """

@mcp.tool()
def read_cypher_query(query: str) -> list[dict]:
    """
    Executes a Cypher read query against the local Kuzu Security Graph.
    Use this tool to trace blast radiuses, identify Crown Jewel correlations, 
    and perform similar incident searches across machines and subnets.
    
    Example: MATCH (i:Incident)-[:AFFECTS]->(m:Machine) RETURN i.title, m.name
    
    Warning: Writing queries (using CREATE, SET, DELETE, MERGE) is blocked.
    """
    query_upper = query.upper()
    forbidden = ["CREATE ", "SET ", "DELETE ", "REMOVE ", "MERGE ", "DETACH "]
    if any(word in query_upper for word in forbidden):
        raise ValueError(
            "Write operations (CREATE, SET, DELETE, REMOVE, MERGE, DETACH) "
            "are strictly prohibited on this read-only interface."
        )

    try:
        results = execute_query(query)
        return results
    except Exception as e:
        return [{"error": f"Failed to execute Cypher query: {str(e)}"}]

if __name__ == "__main__":
    mcp.run()
