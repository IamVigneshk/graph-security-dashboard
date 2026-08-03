import React, { useEffect, useRef, useState, useMemo } from 'react';
import { 
  Shield, 
  Cpu, 
  Network, 
  Database, 
  Terminal as TerminalIcon, 
  RefreshCw, 
  X, 
  Play, 
  Tag, 
  Search, 
  ChevronDown,
  ChevronRight,
  Layers as LayersIcon,
  Key,
  Monitor,
  User,
  AlertTriangle,
  CheckCircle,
  Eye,
  Activity
} from 'lucide-react';
import './App.css';

const API_BASE = import.meta.env.DEV ? 'http://localhost:8000' : '';

// Reference icons by EntityType
const entityIcons = {
  Machine: Monitor,
  User: User,
  Virtualnetwork: Network,
  Subnet: LayersIcon,
  Storageaccount: Database,
  Keyvault: Key,
  Incident: Shield,
  Alert: Activity,
};

// Reference color tokens matching tokens.css exactly
const entityColors = {
  Machine: "var(--secondary)",      // Sky Blue (#3cabff)
  User: "var(--success)",         // Teal/Green (#12a594)
  Virtualnetwork: "var(--violet)",// Violet (#6347ea)
  Subnet: "var(--info)",          // Grey (#606060)
  Storageaccount: "var(--medium)",// Gold/Yellow (#ffc53d)
  Keyvault: "var(--violet)",      // Violet (#6347ea)
  Incident: "var(--critical)",    // Red (#f04438)
  Alert: "var(--high)",           // Orange (#f97316)
};

export default function App() {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [selectedId, setSelectedId] = useState(null);
  const [detailTab, setDetailTab] = useState("overview"); // overview, logs, incidents, relationships
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs] = useState(["Ready for Asset Discovery Scan..."]);
  const [cypherQuery, setCypherQuery] = useState("MATCH (m:Machine) RETURN m.name, m.internal_tags");
  const [queryResults, setQueryResults] = useState(null);
  const [queryError, setQueryError] = useState("");
  const [searchQuery, setSearchQuery] = useState("");
  
  // Filter settings
  const [daysFilter, setDaysFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState([]);
  const [statusFilter, setStatusFilter] = useState([]);
  const [envFilter, setEnvFilter] = useState([]);
  const [tagFilter, setTagFilter] = useState([]);
  
  const [hasIncidentsFilter, setHasIncidentsFilter] = useState(false);
  const [isBottomCollapsed, setIsBottomCollapsed] = useState(true);
  const [showFiltersPanel, setShowFiltersPanel] = useState(true);

  // Accordion toggles
  const [openSections, setOpenSections] = useState({
    entityTypes: true,
    status: true,
    environments: true,
    tags: true
  });

  const terminalEndRef = useRef(null);

  // Auto-scroll logs
  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs]);

  // Load graph data
  const fetchGraph = async () => {
    try {
      const response = await fetch(`${API_BASE}/api/graph`);
      if (!response.ok) throw new Error("Failed to load graph data");
      const data = await response.json();
      setGraphData(data);
      if (data.nodes && data.nodes.length > 40) {
        setHasIncidentsFilter(true);
      }
    } catch (error) {
      console.error("Error loading graph:", error);
      setLogs((prev) => [...prev, `[Error] Failed to fetch updated graph: ${error.message}`]);
    }
  };

  useEffect(() => {
    fetchGraph();
  }, []);

  // Filter and process nodes
  const getProcessedGraph = () => {
    const nodes = JSON.parse(JSON.stringify(graphData.nodes));
    const edges = JSON.parse(JSON.stringify(graphData.edges));

    const now = new Date("2026-08-02T00:06:25Z");
    const activeIncidentIds = new Set();
    const activeAlertIds = new Set();

    nodes.forEach(n => {
      if (n.data.type === 'Incident') {
        const createdDate = new Date(n.data.created_at || '');
        const diffMs = now - createdDate;
        const diffHours = diffMs / (1000 * 60 * 60);
        const diffDays = diffHours / 24;

        let inTimeframe = true;
        if (daysFilter === "1h") inTimeframe = diffHours <= 1;
        else if (daysFilter === "24h") inTimeframe = diffHours <= 24;
        else if (daysFilter === "7d") inTimeframe = diffDays <= 7;
        else if (daysFilter === "30d") inTimeframe = diffDays <= 30;

        if (inTimeframe) {
          activeIncidentIds.add(n.data.id);
        }
      }
    });

    edges.forEach(e => {
      if (e.data.type === 'INCLUDES' && activeIncidentIds.has(e.data.source)) {
        activeAlertIds.add(e.data.target);
      }
    });

    const filteredNodes = nodes.filter(n => {
      if (n.data.type === 'Incident') return activeIncidentIds.has(n.data.id);
      if (n.data.type === 'Alert') return activeAlertIds.has(n.data.id);
      return true;
    });

    const compromisedMachineIds = new Set();
    const suspectedMachineIds = new Set();
    const compromisedUserIds = new Set();
    const suspectedUserIds = new Set();

    edges.forEach(e => {
      if (activeIncidentIds.has(e.data.source)) {
        const incNode = nodes.find(n => n.data.id === e.data.source);
        const severity = incNode?.data.severity || 'Medium';
        
        if (e.data.type === 'AFFECTS') {
          if (severity === 'High') compromisedMachineIds.add(e.data.target);
          else suspectedMachineIds.add(e.data.target);
        } else if (e.data.type === 'AFFECTS_USER') {
          if (severity === 'High') compromisedUserIds.add(e.data.target);
          else suspectedUserIds.add(e.data.target);
        }
      }
    });

    const compromisedSubnets = new Set();
    edges.forEach(e => {
      if (e.data.type === 'HOSTED_IN' && compromisedMachineIds.has(e.data.source)) {
        compromisedSubnets.add(e.data.target);
      }
    });

    edges.forEach(e => {
      if (e.data.type === 'HOSTED_IN' && compromisedSubnets.has(e.data.target)) {
        const vmId = e.data.source;
        if (!compromisedMachineIds.has(vmId)) {
          suspectedMachineIds.add(vmId);
        }
      }
    });

    filteredNodes.forEach(n => {
      if (n.data.type === 'Machine') {
        if (compromisedMachineIds.has(n.data.id)) {
          n.data.status = 'compromised';
          n.data.riskScore = 88;
        } else if (suspectedMachineIds.has(n.data.id)) {
          n.data.status = 'suspected';
          n.data.riskScore = 65;
        } else {
          n.data.status = 'healthy';
          n.data.riskScore = 15;
        }
      } else if (n.data.type === 'User') {
        if (compromisedUserIds.has(n.data.id)) {
          n.data.status = 'compromised';
          n.data.riskScore = 92;
        } else if (suspectedUserIds.has(n.data.id)) {
          n.data.status = 'suspected';
          n.data.riskScore = 70;
        } else {
          n.data.status = 'healthy';
          n.data.riskScore = 10;
        }
      } else {
        n.data.status = 'healthy';
        n.data.riskScore = 5;
      }
    });

    let finalNodes = filteredNodes;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      finalNodes = finalNodes.filter(n => {
        const label = n.data.label?.toLowerCase() || '';
        const id = n.data.id?.toLowerCase() || '';
        const ip = n.data.private_ip?.toLowerCase() || '';
        const owner = n.data.owner?.toLowerCase() || '';
        const email = n.data.email?.toLowerCase() || '';
        const role = n.data.role?.toLowerCase() || '';
        return label.includes(q) || id.includes(q) || ip.includes(q) || owner.includes(q) || email.includes(q) || role.includes(q);
      });
    }

    if (typeFilter.length > 0) {
      finalNodes = finalNodes.filter(n => typeFilter.includes(n.data.type));
    }
    if (statusFilter.length > 0) {
      finalNodes = finalNodes.filter(n => {
        if (n.data.type === 'Machine' || n.data.type === 'User') {
          return statusFilter.includes(n.data.status);
        }
        return true;
      });
    }
    if (envFilter.length > 0) {
      finalNodes = finalNodes.filter(n => {
        if (n.data.type === 'Machine') {
          const env = (n.data.cloud_tags?.includes('env:prod') || n.data.name?.includes('prod')) ? 'production' : 'dev';
          return envFilter.includes(env);
        }
        return true;
      });
    }
    if (tagFilter.length > 0) {
      finalNodes = finalNodes.filter(n => {
        if (n.data.internal_tags) {
          return tagFilter.some(t => n.data.internal_tags.includes(t));
        }
        return true;
      });
    }

    if (hasIncidentsFilter) {
      const affectedMachineIds = new Set();
      finalNodes.forEach(n => {
        if (n.data.type === 'Machine' && (n.data.status === 'compromised' || n.data.status === 'suspected')) {
          affectedMachineIds.add(n.data.id);
        }
      });

      const affectedUserIds = new Set();
      finalNodes.forEach(n => {
        if (n.data.type === 'User' && (n.data.status === 'compromised' || n.data.status === 'suspected')) {
          affectedUserIds.add(n.data.id);
        }
      });

      const activeSubnetIds = new Set();
      edges.forEach(e => {
        if (e.data.type === 'HOSTED_IN' && affectedMachineIds.has(e.data.source)) {
          activeSubnetIds.add(e.data.target);
        }
      });

      const activeVnetIds = new Set();
      edges.forEach(e => {
        if (e.data.type === 'CONTAINED_IN' && activeSubnetIds.has(e.data.source)) {
          activeVnetIds.add(e.data.target);
        }
      });

      finalNodes = finalNodes.filter(n => {
        if (n.data.type === 'Incident' || n.data.type === 'Alert') return true;
        if (n.data.type === 'Machine') return affectedMachineIds.has(n.data.id);
        if (n.data.type === 'User') return affectedUserIds.has(n.data.id);
        if (n.data.type === 'Subnet') return activeSubnetIds.has(n.data.id);
        if (n.data.type === 'Virtualnetwork') return activeVnetIds.has(n.data.id);
        
        let affectedDirectly = false;
        edges.forEach(e => {
          if (activeIncidentIds.has(e.data.source)) {
            if ((e.data.type === 'AFFECTS' || e.data.type === 'AFFECTS_USER') && e.data.target === n.data.id) {
              affectedDirectly = true;
            }
          }
        });
        return affectedDirectly;
      });
    }

    const nodeIds = new Set(finalNodes.map(n => n.data.id));
    const finalEdges = edges.filter(e => 
      nodeIds.has(e.data.source) && nodeIds.has(e.data.target)
    );

    return { nodes: finalNodes, edges: finalEdges };
  };

  const processedGraph = getProcessedGraph();

  // Trigger discovery scan
  const startScan = () => {
    setScanning(true);
    setLogs(["[Scanner] Connecting to local Azure session..."]);
    setSelectedId(null);

    const eventSource = new EventSource(`${API_BASE}/api/scan`);

    eventSource.onmessage = (event) => {
      if (event.data === '[DONE]') {
        eventSource.close();
        setScanning(false);
        setLogs((prev) => [...prev, "[Scanner] Synchronization complete."]);
        fetchGraph();
      } else {
        setLogs((prev) => [...prev, event.data]);
      }
    };

    eventSource.onerror = (err) => {
      console.error("SSE Error:", err);
      eventSource.close();
      setScanning(false);
      setLogs((prev) => [...prev, "[Error] Scan pipeline aborted."]);
    };
  };

  // Run Cypher query
  const executeQuery = async () => {
    setQueryError("");
    setQueryResults(null);
    try {
      const response = await fetch(`${API_BASE}/api/query`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: cypherQuery })
      });
      const data = await response.json();
      if (!response.ok) {
        setQueryError(data.detail || "Query failed");
      } else {
        setQueryResults(data.results);
      }
    } catch (err) {
      setQueryError(err.message || "Failed to execute query");
    }
  };

  // Update tag
  const handleTagToggle = async (tag) => {
    if (!selectedId) return;
    const selected = processedGraph.nodes.find(n => n.data.id === selectedId);
    if (!selected) return;

    let currentTags = selected.data.internal_tags || [];
    let updatedTags;

    if (currentTags.includes(tag)) {
      updatedTags = currentTags.filter(t => t !== tag);
    } else {
      updatedTags = [...currentTags, tag];
    }

    try {
      const response = await fetch(`${API_BASE}/api/tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: selectedId, tags: updatedTags })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.detail || "Failed to update tags");
      }

      fetchGraph();
    } catch (err) {
      console.error("Error setting tag:", err);
      alert(`Tag update failed: ${err.message}`);
    }
  };

  const toggleFilter = (arr, val, setter) => {
    setter(arr.includes(val) ? arr.filter(v => v !== val) : [...arr, val]);
  };

  const toggleSection = (section) => {
    setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
  };

  // Sidebar counters
  const allNodes = processedGraph.nodes;
  const hostCount = allNodes.filter(n => n.data.type === 'Machine').length;
  const userCount = allNodes.filter(n => n.data.type === 'User').length;
  const vnetCount = allNodes.filter(n => n.data.type === 'Virtualnetwork').length;
  const subnetCount = allNodes.filter(n => n.data.type === 'Subnet').length;
  const storageCount = allNodes.filter(n => n.data.type === 'Storageaccount').length;
  const kvCount = allNodes.filter(n => n.data.type === 'Keyvault').length;
  const incidentCount = allNodes.filter(n => n.data.type === 'Incident').length;
  const alertCount = allNodes.filter(n => n.data.type === 'Alert').length;

  const compromisedCount = allNodes.filter(n => (n.data.type === 'Machine' || n.data.type === 'User') && n.data.status === 'compromised').length;
  const suspectedCount = allNodes.filter(n => (n.data.type === 'Machine' || n.data.type === 'User') && n.data.status === 'suspected').length;
  const healthyCount = allNodes.filter(n => (n.data.type === 'Machine' || n.data.type === 'User') && n.data.status === 'healthy').length;

  const prodCount = allNodes.filter(n => n.data.type === 'Machine' && (n.data.cloud_tags?.includes('env:prod') || n.data.name?.includes('prod'))).length;
  const devCount = allNodes.filter(n => n.data.type === 'Machine' && (n.data.cloud_tags?.includes('env:dev') || n.data.name?.includes('dev') || n.data.name?.includes('ingress') || n.data.name?.includes('workstation'))).length;

  const activeFilterCount = typeFilter.length + statusFilter.length + envFilter.length + tagFilter.length;

  const selectedNode = useMemo(() => {
    if (!selectedId) return null;
    const node = processedGraph.nodes.find(n => n.data.id === selectedId);
    if (!node) return null;
    
    const machineIncidents = [];
    if (node.data.type === 'Machine') {
      const incidentsAffected = processedGraph.edges
        .filter(e => e.data.type === 'AFFECTS' && e.data.target === node.data.id)
        .map(e => e.data.source);
      processedGraph.nodes.forEach(n => {
        if (n.data.type === 'Incident' && incidentsAffected.includes(n.data.id)) {
          machineIncidents.push(n.data);
        }
      });
    } else if (node.data.type === 'User') {
      const incidentsAffected = processedGraph.edges
        .filter(e => e.data.type === 'AFFECTS_USER' && e.data.target === node.data.id)
        .map(e => e.data.source);
      processedGraph.nodes.forEach(n => {
        if (n.data.type === 'Incident' && incidentsAffected.includes(n.data.id)) {
          machineIncidents.push(n.data);
        }
      });
    }
    return { ...node.data, incidents: machineIncidents };
  }, [selectedId, processedGraph]);

  const selectedNodeRelationships = useMemo(() => {
    if (!selectedId) return [];
    return processedGraph.edges.filter(e => e.data.source === selectedId || e.data.target === selectedId);
  }, [selectedId, processedGraph.edges]);

  return (
    <div className="app-container">
      {/* Header */}
      <header className="dashboard-header">
        <div className="brand-section">
          <Shield size={22} style={{ color: 'var(--accent)' }} />
          <span className="brand-name">Knowledge Graph</span>
          <span className="brand-meta">
            {allNodes.length} entities • {processedGraph.edges.length} relationships
          </span>
        </div>

        {/* Search */}
        <div className="header-search-container">
          <Search size={16} style={{ color: 'var(--text-muted)' }} />
          <input 
            type="text" 
            placeholder="Search entities, IPs, owners..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="header-search-input"
          />
        </div>

        {/* Ingest Action Controls */}
        <div className="header-controls">
          <button 
            className={`btn-filters-pendant ${showFiltersPanel ? 'active' : ''}`}
            onClick={() => setShowFiltersPanel(!showFiltersPanel)}
          >
            Filters
            {activeFilterCount > 0 && <span style={{ marginLeft: '6px', background: 'rgba(255,255,255,0.15)', padding: '1px 6px', borderRadius: '10px', fontSize: '0.65rem' }}>{activeFilterCount}</span>}
          </button>
          
          <button 
            className={`btn-scan-header ${scanning ? 'scanning' : ''}`}
            onClick={startScan}
            disabled={scanning}
          >
            <RefreshCw size={14} className={scanning ? 'spinner' : ''} />
            {scanning ? 'Syncing...' : 'Scan Azure & Defender'}
          </button>
        </div>
      </header>

      {/* Main Content Layout */}
      <div className="dashboard-body">
        
        {/* Left Side Filter Sidebar */}
        {showFiltersPanel && (
          <aside className="workspace-left-sidebar">
            
            {/* Entity Types */}
            <div className="sidebar-section">
              <button onClick={() => toggleSection('entityTypes')} className="sidebar-section-toggle">
                {openSections.entityTypes ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span className="sidebar-section-title">Entity Type</span>
              </button>
              
              {openSections.entityTypes && (
                <div className="sidebar-section-content">
                  <FilterChip label="Host / Machine" active={typeFilter.includes("Machine")} onClick={() => toggleFilter(typeFilter, "Machine", setTypeFilter)} count={hostCount} icon={<Monitor size={12} style={{ color: 'var(--secondary)' }} />} />
                  <FilterChip label="User / Identity" active={typeFilter.includes("User")} onClick={() => toggleFilter(typeFilter, "User", setTypeFilter)} count={userCount} icon={<User size={12} style={{ color: 'var(--success)' }} />} />
                  <FilterChip label="Virtual Networks" active={typeFilter.includes("Virtualnetwork")} onClick={() => toggleFilter(typeFilter, "Virtualnetwork", setTypeFilter)} count={vnetCount} icon={<Network size={12} style={{ color: 'var(--violet)' }} />} />
                  <FilterChip label="Subnets" active={typeFilter.includes("Subnet")} onClick={() => toggleFilter(typeFilter, "Subnet", setTypeFilter)} count={subnetCount} icon={<LayersIcon size={12} style={{ color: 'var(--info)' }} />} />
                  <FilterChip label="Storage Accounts" active={typeFilter.includes("Storageaccount")} onClick={() => toggleFilter(typeFilter, "Storageaccount", setTypeFilter)} count={storageCount} icon={<Database size={12} style={{ color: 'var(--medium)' }} />} />
                  <FilterChip label="Key Vaults" active={typeFilter.includes("Keyvault")} onClick={() => toggleFilter(typeFilter, "Keyvault", setTypeFilter)} count={kvCount} icon={<Key size={12} style={{ color: 'var(--violet)' }} />} />
                  <FilterChip label="Security Incidents" active={typeFilter.includes("Incident")} onClick={() => toggleFilter(typeFilter, "Incident", setTypeFilter)} count={incidentCount} icon={<Shield size={12} style={{ color: 'var(--critical)' }} />} />
                  <FilterChip label="Alert Events" active={typeFilter.includes("Alert")} onClick={() => toggleFilter(typeFilter, "Alert", setTypeFilter)} count={alertCount} icon={<Activity size={12} style={{ color: 'var(--high)' }} />} />
                </div>
              )}
            </div>

            {/* Security Status */}
            <div className="sidebar-section">
              <button onClick={() => toggleSection('status')} className="sidebar-section-toggle">
                {openSections.status ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span className="sidebar-section-title">Status</span>
              </button>

              {openSections.status && (
                <div className="sidebar-section-content">
                  <FilterChip label="Healthy" active={statusFilter.includes("healthy")} onClick={() => toggleFilter(statusFilter, "healthy", setStatusFilter)} count={healthyCount} icon={<span className="legend-color-dot healthy" />} />
                  <FilterChip label="Compromised" active={statusFilter.includes("compromised")} onClick={() => toggleFilter(statusFilter, "compromised", setStatusFilter)} count={compromisedCount} icon={<span className="legend-color-dot compromised" />} />
                  <FilterChip label="Suspected" active={statusFilter.includes("suspected")} onClick={() => toggleFilter(statusFilter, "suspected", setStatusFilter)} count={suspectedCount} icon={<span className="legend-color-dot suspected" />} />
                </div>
              )}
            </div>

            {/* Environments */}
            <div className="sidebar-section">
              <button onClick={() => toggleSection('environments')} className="sidebar-section-toggle">
                {openSections.environments ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span className="sidebar-section-title">Environment</span>
              </button>

              {openSections.environments && (
                <div className="sidebar-section-content">
                  <FilterChip label="production" active={envFilter.includes("production")} onClick={() => toggleFilter(envFilter, "production", setEnvFilter)} count={prodCount} color="var(--critical)" />
                  <FilterChip label="dev / workstation" active={envFilter.includes("dev")} onClick={() => toggleFilter(envFilter, "dev", setEnvFilter)} count={devCount} color="var(--secondary)" />
                </div>
              )}
            </div>

            {/* Tag scopes */}
            <div className="sidebar-section">
              <button onClick={() => toggleSection('tags')} className="sidebar-section-toggle">
                {openSections.tags ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                <span className="sidebar-section-title">Tags</span>
              </button>

              {openSections.tags && (
                <div className="sidebar-section-content">
                  <FilterChip label="CrownJewel" active={tagFilter.includes("CrownJewel")} onClick={() => toggleFilter(tagFilter, "CrownJewel", setTagFilter)} icon={<Tag size={12} style={{ color: 'var(--medium)' }} />} />
                  <FilterChip label="PCI_Scope" active={tagFilter.includes("PCI_Scope")} onClick={() => toggleFilter(tagFilter, "PCI_Scope", setTagFilter)} icon={<Tag size={12} style={{ color: 'var(--secondary)' }} />} />
                </div>
              )}
            </div>

            {activeFilterCount > 0 && (
              <button 
                onClick={() => { setTypeFilter([]); setStatusFilter([]); setEnvFilter([]); setTagFilter([]); }}
                className="btn-clear-filters"
              >
                Clear all filters
              </button>
            )}

          </aside>
        )}

        {/* Center: Canvas Workspace */}
        <main className="workspace-content">
          
          {/* Canvas Container */}
          <div className="canvas-container">
            
            {/* Graph Summary Overlay */}
            <div className="graph-summary-overlay">
              <span className="summary-title">Graph Summary</span>
              <div className="summary-row">
                <span>Total Nodes</span>
                <span style={{ fontWeight: 'bold' }}>{allNodes.length}</span>
              </div>
              <div className="summary-row">
                <span>Total Edges</span>
                <span style={{ fontWeight: 'bold' }}>{processedGraph.edges.length}</span>
              </div>
              <div className="summary-row" style={{ color: 'var(--critical)' }}>
                <span>Compromised</span>
                <span>{compromisedCount}</span>
              </div>
              <div className="summary-row" style={{ color: 'var(--medium)' }}>
                <span>Suspected</span>
                <span>{suspectedCount}</span>
              </div>
            </div>

            {/* Legend Overlay */}
            <div className="legend-overlay">
              <div className="legend-item">
                <span className="legend-color-dot compromised"></span>
                <span>Compromised</span>
              </div>
              <div className="legend-item">
                <span className="legend-color-dot suspected"></span>
                <span>Suspected / Vulnerable</span>
              </div>
              <div className="legend-item">
                <span className="legend-color-dot healthy"></span>
                <span>Healthy</span>
              </div>
            </div>

            {/* Canvas Toolbar Overlay */}
            <div className="canvas-toolbar">
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <select 
                  value={daysFilter}
                  onChange={(e) => setDaysFilter(e.target.value)}
                  className="toolbar-select"
                >
                  <option value="all">All Time</option>
                  <option value="1h">Last 1 Hour</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
                </select>

                <button 
                  className={`toggle-btn ${hasIncidentsFilter ? 'active' : ''}`}
                  onClick={() => setHasIncidentsFilter(!hasIncidentsFilter)}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.8rem', padding: '6px 12px' }}
                >
                  <Shield size={12} style={{ color: hasIncidentsFilter ? 'var(--critical)' : 'var(--text-secondary)' }} />
                  Has Incidents Only
                </button>
              </div>
            </div>

            {/* SVG Canvas */}
            <ResourceGraph 
              entities={processedGraph.nodes} 
              edges={processedGraph.edges} 
              selectedId={selectedId} 
              onSelect={setSelectedId} 
            />

          </div>

          {/* Bottom Terminals */}
          <div 
            className="bottom-collapse-handle"
            onClick={() => setIsBottomCollapsed(!isBottomCollapsed)}
          >
            {isBottomCollapsed ? <ChevronDown size={16} /> : <ChevronDown size={16} style={{ transform: 'rotate(180deg)' }} />}
            <span style={{ fontSize: '0.75rem', fontWeight: 600, marginLeft: '6px' }}>
              {isBottomCollapsed ? "Open Developer Terminals" : "Close Developer Terminals"}
            </span>
          </div>

          <div className={`bottom-section ${isBottomCollapsed ? 'collapsed' : ''}`}>
            
            {/* Cypher Console */}
            <div className="console-panel">
              <div className="panel-header">
                <span className="panel-title"><Database size={14} /> Cypher Console</span>
              </div>
              <div className="cypher-input-container">
                <textarea 
                  className="cypher-textarea" 
                  value={cypherQuery}
                  onChange={(e) => setCypherQuery(e.target.value)}
                  placeholder="MATCH (m:Machine) RETURN m.name"
                />
                <button className="btn-execute" onClick={executeQuery}>
                  <Play size={12} /> Run
                </button>
              </div>

              <div className="query-results-wrapper">
                {queryError && (
                  <div style={{ color: 'var(--critical)', padding: '10px', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                    {queryError}
                  </div>
                )}
                {queryResults ? (
                  queryResults.length === 0 ? (
                    <div className="no-results" style={{ fontSize: '0.75rem' }}>No records found.</div>
                  ) : (
                    <table className="query-table">
                      <thead>
                        <tr>
                          {Object.keys(queryResults[0]).map((key) => (
                            <th key={key}>{key}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {queryResults.map((row, idx) => (
                          <tr key={idx}>
                            {Object.values(row).map((val, vIdx) => (
                              <td key={vIdx}>{Array.isArray(val) ? val.join(', ') : String(val)}</td>
                            ))}
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )
                ) : (
                  !queryError && <div className="no-results" style={{ fontSize: '0.75rem' }}>Execute a Cypher query.</div>
                )}
              </div>
            </div>

            {/* Scan Logs */}
            <div className="console-panel">
              <div className="panel-header">
                <span className="panel-title"><TerminalIcon size={14} /> Scan Logs</span>
              </div>
              <div className="terminal-view">
                {logs.map((logLine, idx) => (
                  <div key={idx} className="terminal-line">
                    <span style={{ color: 'var(--text-muted)', marginRight: '6px' }}>[SYS]</span>
                    <span>{logLine}</span>
                  </div>
                ))}
                <div ref={terminalEndRef} />
              </div>
            </div>

          </div>

        </main>

        {/* Right Side Drawer */}
        <aside className="workspace-right-drawer" style={{ width: selectedId ? '380px' : '0px', minWidth: selectedId ? '380px' : '0px' }}>
          {selectedNode ? (
            <>
              {/* Header */}
              <div className="drawer-header">
                <div className="drawer-title-row">
                  <div className="node-icon-wrapper" style={{ borderColor: selectedNode.status === 'compromised' ? 'var(--critical)' : selectedNode.status === 'suspected' ? 'var(--medium)' : 'var(--success)', borderStyle: 'solid', borderWidth: '1px' }}>
                    {React.createElement(entityIcons[selectedNode.type] || Monitor, {
                      size: 20,
                      style: { color: entityColors[selectedNode.type] }
                    })}
                  </div>
                  <div>
                    <div className="node-name truncate max-w-[200px]">{selectedNode.label}</div>
                    <div className="node-type-label">{selectedNode.type}</div>
                  </div>
                </div>
                <button className="close-btn" onClick={() => setSelectedId(null)}>
                  <X size={16} />
                </button>
              </div>

              {/* Drawer Tabs */}
              <div className="drawer-tabs-row">
                {[
                  { id: "overview", label: "Overview" },
                  { id: "logs", label: "Logs" },
                  { id: "incidents", label: "Incidents" },
                  { id: "relationships", label: "Relationships" }
                ].map(tab => (
                  <button 
                    key={tab.id}
                    className={`drawer-tab-btn ${detailTab === tab.id ? 'active' : ''}`}
                    onClick={() => setDetailTab(tab.id)}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Drawer Body */}
              <div className="drawer-body">
                
                {/* Overview */}
                {detailTab === "overview" && (
                  <div className="space-y-4" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    
                    {/* Risk & Criticality */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                      <div className="bg-surface-2" style={{ border: '1px solid var(--border)', padding: '10px 14px', borderRadius: '8px', textAlign: 'center' }}>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>Risk Score</div>
                        <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: selectedNode.riskScore > 75 ? 'var(--critical)' : selectedNode.riskScore > 40 ? 'var(--medium)' : 'var(--success)' }}>
                          {selectedNode.riskScore || 15}
                        </div>
                      </div>
                      <div className="bg-surface-2" style={{ border: '1px solid var(--border)', padding: '10px 14px', borderRadius: '8px', textAlign: 'center' }}>
                        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px', textTransform: 'uppercase' }}>Criticality</div>
                        <div style={{ fontSize: '1.2rem', fontWeight: 'bold', color: selectedNode.internal_tags?.includes('CrownJewel') ? 'var(--medium)' : 'var(--text)', textTransform: 'capitalize', marginTop: '6px' }}>
                          {selectedNode.internal_tags?.includes('CrownJewel') ? 'Critical' : selectedNode.internal_tags?.includes('PCI_Scope') ? 'High' : 'Medium'}
                        </div>
                      </div>
                    </div>

                    {/* Properties */}
                    <div className="property-group">
                      <div className="property-row">
                        <span className="property-key">ID</span>
                        <span className="property-val" style={{ fontSize: '0.7rem' }}>{selectedNode.id}</span>
                      </div>

                      {selectedNode.type === 'Machine' && (
                        <>
                          <div className="property-row">
                            <span className="property-key">Private IP</span>
                            <span className="property-val">{selectedNode.private_ip || 'N/A'}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">EDR Agent Coverage</span>
                            <span className="property-val" style={{ color: selectedNode.has_defender && selectedNode.has_crowdstrike ? 'var(--success)' : 'var(--text)' }}>
                              {(selectedNode.has_defender ? "Defender" : "") + 
                               (selectedNode.has_defender && selectedNode.has_crowdstrike ? " + " : "") + 
                               (selectedNode.has_crowdstrike ? "CrowdStrike" : "") || "None"}
                            </span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">Owner</span>
                            <span className="property-val">{selectedNode.owner || 'N/A'}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">Operating System</span>
                            <span className="property-val">{selectedNode.os || 'N/A'}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">Cloud Tags</span>
                            <span className="property-val" style={{ color: 'var(--text-secondary)', fontSize: '0.7rem' }}>{selectedNode.cloud_tags || 'None'}</span>
                          </div>
                        </>
                      )}

                      {selectedNode.type === 'User' && (
                        <>
                          <div className="property-row">
                            <span className="property-key">Email</span>
                            <span className="property-val">{selectedNode.email || 'N/A'}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">AD Role</span>
                            <span className="property-val" style={{ color: selectedNode.role === 'CEO' ? 'var(--critical)' : 'var(--text)', fontWeight: 'bold' }}>{selectedNode.role || 'N/A'}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">Privilege</span>
                            <span className="property-val" style={{ color: selectedNode.privilege === 'Global Admin' ? 'var(--critical)' : 'var(--text)', fontWeight: 'bold' }}>{selectedNode.privilege || 'N/A'}</span>
                          </div>
                        </>
                      )}

                      {selectedNode.type !== 'Machine' && selectedNode.type !== 'User' && selectedNode.type !== 'Incident' && selectedNode.type !== 'Alert' && (
                        <>
                          <div className="property-row">
                            <span className="property-key">Resource Type</span>
                            <span className="property-val">{selectedNode.resource_type || selectedNode.type}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">Region</span>
                            <span className="property-val">{selectedNode.region || 'N/A'}</span>
                          </div>
                          <div className="property-row">
                            <span className="property-key">Resource Group</span>
                            <span className="property-val">{selectedNode.resource_group || 'N/A'}</span>
                          </div>
                        </>
                      )}

                      <div className="property-row">
                        <span className="property-key">Status</span>
                        <span className="property-val" style={{ 
                          color: selectedNode.status === 'compromised' ? 'var(--critical)' : selectedNode.status === 'suspected' ? 'var(--medium)' : 'var(--success)',
                          fontWeight: 'bold',
                          textTransform: 'uppercase'
                        }}>
                          {selectedNode.status || 'healthy'}
                        </span>
                      </div>
                    </div>

                    {/* Local Custom Tag Editor */}
                    {(selectedNode.type === 'Machine' || (selectedNode.type !== 'User' && selectedNode.type !== 'Incident' && selectedNode.type !== 'Alert')) && (
                      <div className="tag-manager-section">
                        <span className="section-label"><Tag size={12} style={{ marginRight: '4px' }} /> Local Custom Tags</span>
                        <div className="tag-list-flex">
                          <button 
                            className={`tag-pill-edit ${selectedNode.internal_tags?.includes('CrownJewel') ? 'active-gold' : 'inactive-gold'}`}
                            onClick={() => handleTagToggle('CrownJewel')}
                          >
                            CrownJewel
                          </button>
                          <button 
                            className={`tag-pill-edit ${selectedNode.internal_tags?.includes('PCI_Scope') ? 'active-blue' : 'inactive-blue'}`}
                            onClick={() => handleTagToggle('PCI_Scope')}
                          >
                            PCI_Scope
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* Logs */}
                {detailTab === "logs" && (
                  <div className="space-y-3" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <p className="text-caption text-text-muted font-medium mb-1">Recent Activity Logs</p>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', padding: '10px', borderRadius: '6px', borderLeft: '3px solid var(--success)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: '4px' }}>
                          <span>INFO</span>
                          <span>Discovery Sync</span>
                        </div>
                        <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Ingested successfully into local graph store via Azure scan pipeline.</p>
                      </div>
                      
                      {selectedNode.status === 'compromised' && (
                        <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', padding: '10px', borderRadius: '6px', borderLeft: '3px solid var(--critical)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--critical)', marginBottom: '4px', fontWeight: 'bold' }}>
                            <span>CRITICAL</span>
                            <span>Defender Alert</span>
                          </div>
                          <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Active malicious event correlation triggers compromising hosts alert.</p>
                        </div>
                      )}

                      {selectedNode.status === 'suspected' && (
                        <div style={{ background: 'var(--surface-2)', border: '1px solid var(--border)', padding: '10px', borderRadius: '6px', borderLeft: '3px solid var(--medium)' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--medium)', marginBottom: '4px', fontWeight: 'bold' }}>
                            <span>WARNING</span>
                            <span>Blast Radius Risk</span>
                          </div>
                          <p style={{ margin: 0, fontSize: '0.75rem', color: 'var(--text-secondary)' }}>VM shares a subnet segment with compromised resources. Potential lateral vulnerability path.</p>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Incidents */}
                {detailTab === "incidents" && (
                  <div className="event-log-container">
                    <span className="section-label"><Shield size={12} style={{ marginRight: '4px' }} /> Connected Incidents ({selectedNode.incidents?.length || 0})</span>
                    {(selectedNode.type === 'Machine' || selectedNode.type === 'User') && selectedNode.incidents && selectedNode.incidents.length > 0 ? (
                      selectedNode.incidents.map((inc, iIdx) => (
                        <div key={iIdx} className={`event-card ${inc.severity?.toLowerCase()}`} style={{ borderLeftWidth: '3px', background: 'var(--surface-2)', padding: '10px', borderRadius: '6px', border: '1px solid var(--border)', borderLeftColor: inc.severity === 'High' ? 'var(--critical)' : 'var(--medium)' }}>
                          <div className="event-card-header" style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 'bold', fontSize: '0.8rem', color: 'var(--text)', marginBottom: '4px' }}>
                            <span>{inc.title.split(':')[-1] || inc.title}</span>
                            <span style={{ fontSize: '0.7rem', color: inc.severity === 'High' ? 'var(--critical)' : 'var(--medium)' }}>{inc.severity}</span>
                          </div>
                          <div className="event-card-desc" style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', lineHeight: 1.3 }}>{inc.description}</div>
                        </div>
                      ))
                    ) : (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic', padding: '10px', textAlign: 'center', backgroundColor: 'var(--surface-2)', borderRadius: '6px' }}>
                        No active security incidents affecting this node.
                      </div>
                    )}
                  </div>
                )}

                {/* Relationships */}
                {detailTab === "relationships" && (
                  <div className="space-y-3" style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    <span className="section-label"><Network size={12} style={{ marginRight: '4px' }} /> Direct Relationships ({selectedNodeRelationships.length})</span>
                    {selectedNodeRelationships.length > 0 ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedNodeRelationships.map((edge) => {
                          const isSource = edge.data.source === selectedId;
                          const targetId = isSource ? edge.data.target : edge.data.source;
                          const otherNode = processedGraph.nodes.find(n => n.data.id === targetId);
                          if (!otherNode) return null;
                          return (
                            <button
                              key={edge.data.id}
                              onClick={() => setSelectedId(targetId)}
                              className="relationship-link-card"
                              style={{
                                background: 'var(--surface-2)',
                                border: '1px solid var(--border)',
                                padding: '10px',
                                borderRadius: '6px',
                                cursor: 'pointer',
                                textAlign: 'left',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '8px',
                                width: '100%',
                                transition: 'all 0.2s'
                              }}
                            >
                              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>{isSource ? '→' : '←'}</span>
                              <div style={{ flex: 1, minWidth: 0 }}>
                                <div style={{ fontSize: '0.75rem', color: 'var(--accent)', fontWeight: 'bold' }}>{edge.data.type}</div>
                                <div className="truncate" style={{ fontSize: '0.8rem', color: 'var(--text)', fontFamily: 'monospace' }}>{otherNode.data.label}</div>
                              </div>
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', background: 'var(--surface-3)', padding: '2px 6px', borderRadius: '10px' }}>
                                {otherNode.data.type}
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    ) : (
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic', padding: '10px', textAlign: 'center', backgroundColor: 'var(--surface-2)', borderRadius: '6px' }}>
                        No direct topological relationships found.
                      </div>
                    )}
                  </div>
                )}

              </div>
            </>
          ) : (
            <div className="drawer-placeholder">
              <Shield size={36} style={{ color: 'var(--border)' }} />
              <div>
                <div style={{ fontWeight: 'bold', fontSize: '0.9rem', color: 'var(--text-muted)' }}>No Node Selected</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>Click any node in the graph topology to query its configuration details and incident history.</div>
              </div>
            </div>
          )}
        </aside>

      </div>
    </div>
  );
}

// -------------------------------------------------------------
// Centered-Zoom Interactive SVG Graph Canvas Component
// -------------------------------------------------------------
function ResourceGraph({ entities, edges, selectedId, onSelect }) {
  const svgRef = useRef(null);
  const [zoom, setZoom] = useState(0.85);
  const [pan, setPan] = useState({ x: 60, y: 50 });
  const [dragging, setDragging] = useState(false);
  const [nodePositions, setNodePositions] = useState({});
  const dragStart = useRef({ x: 0, y: 0 });
  const [draggingNode, setDraggingNode] = useState(null);

  // Distribute all nodes evenly across concentric circles (Obsidian circular radar grid layout)
  useEffect(() => {
    const positions = {};
    const centerX = 450;
    const centerY = 325;
    
    // Sort nodes to ensure consistent placement (VMs in middle, network at core, alerts outside)
    const sorted = [...entities].sort((a, b) => {
      const typeWeights = { Virtualnetwork: 0, Subnet: 1, Machine: 2, User: 3, Storageaccount: 4, Keyvault: 4, Incident: 5, Alert: 5 };
      return (typeWeights[a.data.type] || 3) - (typeWeights[b.data.type] || 3);
    });

    sorted.forEach((e, i) => {
      const angle = (i / sorted.length) * Math.PI * 2;
      // 3 Concentric circular rings
      const radius = 150 + (i % 3) * 75;
      positions[e.data.id] = { 
        x: centerX + Math.cos(angle) * radius, 
        y: centerY + Math.sin(angle) * radius 
      };
    });

    setNodePositions(positions);
  }, [entities]);

  // Adjust zoom while keeping viewport center (450, 325) pinned
  const adjustZoom = (factor) => {
    const minZoom = 0.25;
    const maxZoom = 3.0;

    setZoom((prevZoom) => {
      const newZoom = Math.max(minZoom, Math.min(prevZoom * factor, maxZoom));
      const cx = 450;
      const cy = 325;

      setPan((prevPan) => ({
        x: cx - (cx - prevPan.x) * (newZoom / prevZoom),
        y: cy - (cy - prevPan.y) * (newZoom / prevZoom)
      }));

      return newZoom;
    });
  };

  const handleMouseDown = (e) => {
    if (draggingNode) return;
    setDragging(true);
    dragStart.current = { x: e.clientX - pan.x, y: e.clientY - pan.y };
  };

  const handleMouseMove = (e) => {
    if (dragging) {
      setPan({ x: e.clientX - dragStart.current.x, y: e.clientY - dragStart.current.y });
    }
  };

  // Node Dragging Start
  const handleNodeMouseDown = (e, id) => {
    e.stopPropagation();
    setDraggingNode(id);
  };

  // Dragging movement math fix: divide movement delta by zoom scale factor
  const handleNodeMouseMove = (e) => {
    if (!draggingNode || !svgRef.current) return;
    const pt = svgRef.current.createSVGPoint();
    pt.x = e.clientX;
    pt.y = e.clientY;
    const ctm = svgRef.current.getScreenCTM();
    if (!ctm) return;
    const svgPt = pt.matrixTransform(ctm.inverse());
    
    // Correctly divide coordinate translation by current zoom factor
    const localX = (svgPt.x - pan.x) / zoom;
    const localY = (svgPt.y - pan.y) / zoom;

    setNodePositions(prev => ({
      ...prev,
      [draggingNode]: { x: localX, y: localY }
    }));
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.05 : 1 / 1.05;
    adjustZoom(factor);
  };

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', overflow: 'hidden' }}>
      <svg
        ref={svgRef}
        width="100%"
        height="100%"
        viewBox="0 0 900 650"
        onMouseDown={handleMouseDown}
        onMouseMove={(e) => { handleMouseMove(e); handleNodeMouseMove(e); }}
        onMouseUp={() => { setDragging(false); setDraggingNode(null); }}
        onMouseLeave={() => { setDragging(false); setDraggingNode(null); }}
        onWheel={handleWheel}
        style={{ cursor: dragging ? "grabbing" : draggingNode ? "grabbing" : "grab", background: 'var(--bg)' }}
      >
        <g transform={`translate(${pan.x} ${pan.y}) scale(${zoom})`}>
          
          {/* 1. Edges */}
          {edges.map((edge) => {
            const s = nodePositions[edge.data.source];
            const t = nodePositions[edge.data.target];
            if (!s || !t) return null;
            
            const isHighlighted = selectedId === edge.data.source || selectedId === edge.data.target;
            const isLoggedRel = edge.data.type === 'LOGGED_IN_TO';
            const isAffectsRel = edge.data.type === 'AFFECTS' || edge.data.type === 'AFFECTS_USER';

            let strokeColor = "var(--border)";
            let strokeWidth = 1.2;
            let strokeDash = "0";

            if (isHighlighted) {
              strokeColor = isAffectsRel ? "var(--critical)" : isLoggedRel ? "var(--violet)" : "var(--accent)";
              strokeWidth = 2.2;
            } else {
              if (isAffectsRel) {
                strokeColor = "rgba(240, 68, 56, 0.4)";
                strokeDash = "3 3";
              } else if (isLoggedRel) {
                strokeColor = "rgba(99, 71, 234, 0.4)";
              }
            }

            return (
              <g key={edge.data.id}>
                <line
                  x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                  stroke={strokeColor}
                  strokeWidth={strokeWidth}
                  strokeDasharray={strokeDash}
                  style={{ transition: 'stroke 0.15s, stroke-width 0.15s' }}
                />
                {isHighlighted && (
                  <text
                    x={(s.x + t.x) / 2} y={(s.y + t.y) / 2 - 5}
                    textAnchor="middle" fill={strokeColor}
                    style={{ fontSize: '9px', fontWeight: 'bold', fontFamily: 'monospace', fill: 'var(--text)' }}
                  >
                    {edge.data.type}
                  </text>
                )}
              </g>
            );
          })}

          {/* 2. Nodes */}
          {entities.map((node) => {
            const pos = nodePositions[node.data.id];
            if (!pos) return null;

            const Icon = entityIcons[node.data.type] || Monitor;
            const isSelected = selectedId === node.data.id;
            const isCompromised = node.data.status === 'compromised';
            const isSuspected = node.data.status === 'suspected';

            let nodeColor = entityColors[node.data.type] || "var(--secondary)";
            let circleColor = "var(--surface-1)";
            let ringColor = isSelected ? "var(--accent)" : (isCompromised ? "var(--critical)" : isSuspected ? "var(--medium)" : "var(--success)");
            let ringWidth = isSelected ? 3.0 : 1.8;

            return (
              <g
                key={node.data.id}
                transform={`translate(${pos.x} ${pos.y})`}
                onClick={(e) => { e.stopPropagation(); onSelect(node.data.id); }}
                onMouseDown={(e) => handleNodeMouseDown(e, node.data.id)}
                style={{ cursor: 'pointer' }}
              >
                {/* Compromised Pulse Glow Ring */}
                {isCompromised && (
                  <circle
                    r={25}
                    fill="none"
                    stroke="var(--critical)"
                    strokeWidth={1.5}
                    className="animate-pulse-critical"
                  />
                )}

                {/* Node base circle */}
                <circle
                  r={isSelected ? 21 : 18}
                  fill={circleColor}
                  stroke={ringColor}
                  strokeWidth={ringWidth}
                  style={{ transition: 'stroke-width 0.2s, r 0.2s' }}
                />

                {/* Embedded Lucide Vector Icon */}
                <foreignObject x={-10} y={-10} width={20} height={20}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', width: 20, height: 20 }}>
                    <Icon size={14} style={{ color: nodeColor }} />
                  </div>
                </foreignObject>

                {/* Incident / Threat warning badge */}
                {(isCompromised || isSuspected) && (
                  <circle
                    cx={13}
                    cy={-13}
                    r={4}
                    fill={isCompromised ? "var(--critical)" : "var(--medium)"}
                    stroke="var(--surface-1)"
                    strokeWidth={1.5}
                  />
                )}

                {/* Label text */}
                <text
                  y={30}
                  textAnchor="middle"
                  fill="var(--text)"
                  style={{ fontSize: '9.5px', fontWeight: isSelected ? 'bold' : 'normal', fontFamily: '-apple-system, sans-serif' }}
                >
                  {node.data.label?.length > 18 ? node.data.label.slice(0, 16) + '...' : node.data.label}
                </text>

                <text
                  y={40}
                  textAnchor="middle"
                  fill="var(--text-muted)"
                  style={{ fontSize: '7.5px', textTransform: 'uppercase', letterSpacing: '0.5px' }}
                >
                  {node.data.type}
                </text>
              </g>
            );
          })}

        </g>
      </svg>

      {/* Manual zoom controls in bottom-right corner */}
      <div className="zoom-controls">
        <button onClick={() => adjustZoom(1.15)} className="zoom-btn">+</button>
        <button onClick={() => adjustZoom(1 / 1.15)} className="zoom-btn">−</button>
        <button onClick={() => { setZoom(0.85); setPan({ x: 60, y: 50 }); }} className="zoom-btn zoom-btn-fit">fit</button>
      </div>
    </div>
  );
}

function FilterChip({ label, icon, active, onClick, count, color }) {
  return (
    <button
      onClick={onClick}
      className={`filter-chip ${active ? 'active' : ''}`}
      style={{
        width: '100%',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        padding: '6px 10px',
        borderRadius: '6px',
        fontSize: '0.75rem',
        background: active ? 'rgba(233, 61, 130, 0.12)' : 'none',
        border: 'none',
        color: active ? 'var(--accent)' : 'var(--text-secondary)',
        cursor: 'pointer',
        textAlign: 'left',
        transition: 'all 0.15s ease'
      }}
    >
      {icon || (color ? <span style={{ backgroundColor: color, display: 'inline-block', width: '8px', height: '8px', borderRadius: '99px' }} /> : null)}
      <span style={{ flex: 1, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>{label}</span>
      {count !== undefined && <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', fontWeight: 'bold' }}>{count}</span>}
      {active && <X size={10} style={{ marginLeft: 'auto', flexShrink: 0 }} />}
    </button>
  );
}
