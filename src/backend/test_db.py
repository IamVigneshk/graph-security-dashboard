import os
import sys

# Ensure project root is in python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from src.backend.db import init_schema, execute_query, update_node_tags
from src.backend.scanner import run_azure_defender_scan

def test_pipeline():
    print("=== Start Automated Security Graph Verification ===")
    
    # 1. Initialize schema
    print("\n1. Initializing Kuzu DB schema...")
    init_schema()
    
    # 2. Trigger Scan
    print("\n2. Launching asset scan simulation...")
    def log_print(msg):
        print(f"   [Scan Log] {msg}")
    run_azure_defender_scan(log_callback=log_print)
    
    # 3. Verify Nodes Ingested
    print("\n3. Verifying database node ingestion...")
    machines = execute_query("MATCH (m:Machine) RETURN m.name, m.private_ip, m.internal_tags")
    print(f"   Monitored machines in DB: {len(machines)}")
    for m in machines:
        print(f"   - VM: {m['m.name']} | IP: {m['m.private_ip']} | Tags: {m['m.internal_tags']}")
        
    resources = execute_query("MATCH (c:CloudResource) RETURN c.name, c.type")
    print(f"   Cloud resources in DB: {len(resources)}")
    
    incidents = execute_query("MATCH (i:Incident) RETURN i.title, i.severity")
    print(f"   Incidents in DB: {len(incidents)}")
    for i in incidents:
        print(f"   - Incident: {i['i.title']} | Severity: {i['i.severity']}")
        
    # 4. Verify Local Tagging Updates
    print("\n4. Testing local custom tagging system...")
    # Find a node to tag
    test_node_name = "vm-prod-app-01"
    vms = execute_query("MATCH (m:Machine {name: $name}) RETURN m.id", {"name": test_node_name})
    if not vms:
        print("   [FAIL] Could not find test node vm-prod-app-01")
        return False
        
    node_id = vms[0]["m.id"]
    print(f"   Selected node ID: {node_id} ({test_node_name})")
    
    # Set tags
    print("   Setting internal tags to ['CrownJewel', 'PCI_Scope']...")
    success = update_node_tags(node_id, ["CrownJewel", "PCI_Scope"])
    if not success:
        print("   [FAIL] Tag update returned failure status")
        return False
        
    # Check database
    updated = execute_query("MATCH (m:Machine {id: $id}) RETURN m.name, m.internal_tags", {"id": node_id})
    print(f"   Verification query result tags: {updated[0]['m.internal_tags']}")
    if "CrownJewel" in updated[0]["m.internal_tags"] and "PCI_Scope" in updated[0]["m.internal_tags"]:
        print("   [PASS] Tagging verification successful!")
    else:
        print("   [FAIL] Tags did not match updated state")
        return False
        
    print("\n=== All Database & Ingestion Tests PASSED successfully ===")
    return True

if __name__ == "__main__":
    success = test_pipeline()
    sys.exit(0 if success else 1)
