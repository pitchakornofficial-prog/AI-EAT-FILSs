import { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, HardDrive, Trash2, RotateCcw, AlertTriangle, CheckCircle, Clock } from 'lucide-react';
import './index.css';

// Configure axios
axios.defaults.baseURL = 'http://localhost:8000';

function App() {
  const [activeTab, setActiveTab] = useState('scan');
  const [systemStatus, setSystemStatus] = useState(null);
  
  // Scan state
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanId, setScanId] = useState(null);
  const [scanResults, setScanResults] = useState([]);
  const [scanSummary, setScanSummary] = useState(null);
  const [drives, setDrives] = useState([]);
  const [defaultTarget, setDefaultTarget] = useState('');
  const [selectedPath, setSelectedPath] = useState('');
  
  // Quarantine state
  const [quarantinedItems, setQuarantinedItems] = useState([]);

  useEffect(() => {
    fetchSystemStatus();
    fetchDrives();
    fetchQuarantinedItems();
    
    // Auto-refresh status if scanning
    let interval;
    if (scanning && scanId) {
      interval = setInterval(checkScanStatus, 1000);
    }
    return () => clearInterval(interval);
  }, [scanning, scanId]);

  const fetchSystemStatus = async () => {
    try {
      const res = await axios.get('/api/system/status');
      setSystemStatus(res.data);
    } catch (err) {
      console.error("Failed to fetch status", err);
    }
  };

  const fetchDrives = async () => {
    try {
      const res = await axios.get('/api/system/drives');
      setDrives(res.data.drives);
      setDefaultTarget(res.data.default);
      if (!selectedPath) setSelectedPath(res.data.default);
    } catch (err) {
      console.error("Failed to fetch drives", err);
    }
  };

  const startScan = async () => {
    try {
      setScanning(true);
      setScanResults([]);
      setScanSummary(null);
      const res = await axios.post('/api/scans', { min_size_mb: 50, use_ai: true, target_path: selectedPath });
      setScanId(res.data.scan_id);
    } catch (err) {
      console.error("Scan failed to start", err);
      setScanning(false);
    }
  };

  const checkScanStatus = async () => {
    try {
      const res = await axios.get(`/api/scans/${scanId}/status`);
      setScanStatus(res.data);
      if (res.data.status === 'completed' || res.data.status === 'error') {
        setScanning(false);
        if (res.data.status === 'completed') {
          fetchScanResults(scanId);
        }
      }
    } catch (err) {
      console.error("Failed to check status", err);
      setScanning(false);
    }
  };

  const fetchScanResults = async (id) => {
    try {
      const summaryRes = await axios.get(`/api/scans/${id}/summary`);
      setScanSummary(summaryRes.data.summary);
      
      const itemsRes = await axios.get(`/api/scans/${id}/items`);
      setScanResults(itemsRes.data);
    } catch (err) {
      console.error("Failed to fetch results", err);
    }
  };

  const quarantineSafeItems = async () => {
    if (!scanId) return;
    if (!window.confirm("Quarantine all SAFE items?")) return;
    
    try {
      await axios.post('/api/quarantine/move', { scan_id: scanId });
      fetchScanResults(scanId);
      fetchQuarantinedItems();
      alert("SAFE items moved to quarantine successfully.");
    } catch (err) {
      console.error("Quarantine failed", err);
      alert("Failed to move items to quarantine.");
    }
  };

  const directDeleteItem = async (itemPath) => {
    if (!window.confirm("Are you sure you want to delete this item? (It will be sent to the Recycle Bin)")) return;
    
    try {
      await axios.post('/api/items/delete', { item_paths: [itemPath] });
      // Refresh scan results
      if (scanId) {
         fetchScanResults(scanId);
      }
    } catch (err) {
      console.error("Delete failed", err);
      alert("Failed to delete item directly.");
    }
  };

  const fetchQuarantinedItems = async () => {
    try {
      const res = await axios.get('/api/quarantine/items');
      setQuarantinedItems(res.data);
    } catch (err) {
      console.error("Failed to fetch quarantine", err);
    }
  };

  const restoreItem = async (qId) => {
    try {
      await axios.post('/api/quarantine/restore', { quarantine_ids: [qId] });
      fetchQuarantinedItems();
    } catch (err) {
      console.error("Restore failed", err);
      alert("Failed to restore item.");
    }
  };

  const deleteItem = async (qId) => {
    try {
      await axios.post('/api/quarantine/delete', { quarantine_ids: [qId], permanent: false });
      fetchQuarantinedItems();
    } catch (err) {
      console.error("Delete failed", err);
      alert("Failed to delete item.");
    }
  };

  const formatSize = (bytes) => {
    if (!bytes) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="container">
      {/* Header */}
      <header className="flex justify-between items-center" style={{ marginBottom: '2rem' }}>
        <div className="flex items-center gap-4">
          <div style={{ background: 'rgba(255, 255, 255, 0.1)', padding: '0.75rem', borderRadius: '1rem' }}>
            <Shield size={32} color="var(--text-primary)" />
          </div>
          <div>
            <h1 className="text-gradient" style={{ fontSize: '1.875rem' }}>AI Storage Cleaner</h1>
            <p style={{ color: 'var(--text-secondary)' }}>Intelligent disk space analyzer</p>
          </div>
        </div>
        
        {systemStatus && (
          <div className="flex gap-4">
            <div className="glass" style={{ padding: '0.5rem 1rem', borderRadius: '99px', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <span style={{ width: '8px', height: '8px', borderRadius: '50%', backgroundColor: systemStatus.ollama.available ? 'var(--status-safe)' : 'var(--status-protected)' }}></span>
              <span style={{ fontSize: '0.875rem', color: 'var(--text-secondary)' }}>
                Ollama: {systemStatus.ollama.available ? systemStatus.ollama.model : 'Offline'}
              </span>
            </div>
          </div>
        )}
      </header>

      {/* Tabs */}
      <div className="flex gap-4" style={{ marginBottom: '2rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem' }}>
        <button 
          className={`btn ${activeTab === 'scan' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => setActiveTab('scan')}
        >
          <HardDrive size={18} /> Scanner
        </button>
        <button 
          className={`btn ${activeTab === 'quarantine' ? 'btn-primary' : 'btn-outline'}`}
          onClick={() => { setActiveTab('quarantine'); fetchQuarantinedItems(); }}
        >
          <Trash2 size={18} /> Quarantine ({quarantinedItems.length})
        </button>
      </div>

      {/* Scan Tab */}
      {activeTab === 'scan' && (
        <div className="flex-col gap-6">
          <div className="glass-card" style={{ padding: '2rem' }}>
            <div className="flex justify-between items-center">
              <div>
                <h2>System Scan</h2>
                <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>Scan your Local AppData for safe-to-remove cache and temporary files.</p>
              </div>
              <div className="flex gap-4 items-center">
                <input 
                  type="text"
                  className="input" 
                  value={selectedPath} 
                  onChange={(e) => setSelectedPath(e.target.value)}
                  disabled={scanning}
                  list="drives-list"
                  placeholder="Enter path (e.g. C:\Users)"
                  style={{ minWidth: '250px', padding: '0.5rem 1rem', borderRadius: '0.5rem', border: '1px solid var(--border)', background: 'transparent', color: 'var(--text-primary)' }}
                />
                <datalist id="drives-list">
                  {defaultTarget && <option value={defaultTarget}>Default Target (AppData)</option>}
                  {drives.map(drive => (
                    <option key={drive} value={drive}>Drive {drive}</option>
                  ))}
                </datalist>
                <button 
                  className="btn btn-primary" 
                  onClick={startScan} 
                  disabled={scanning}
                  style={{ padding: '0.75rem 1.5rem', fontSize: '1rem' }}
                >
                  {scanning ? <><Clock className="animate-spin" size={18} /> Scanning...</> : 'Start Scan'}
                </button>
              </div>
            </div>

            {scanning && scanStatus && (
              <div style={{ marginTop: '2rem' }}>
                <div className="flex justify-between" style={{ marginBottom: '0.5rem', fontSize: '0.875rem' }}>
                  <span>{scanStatus.message}</span>
                  <span>{scanStatus.progress}%</span>
                </div>
                <div className="progress-bg">
                  <div className="progress-fill" style={{ width: `${scanStatus.progress}%` }}></div>
                </div>
              </div>
            )}
          </div>

          {/* Scan Results */}
          {scanResults.length > 0 && (
            <>
              <div className="flex gap-4">
                {['SAFE', 'REVIEW', 'PROTECTED'].map(status => {
                  const data = scanSummary?.[status];
                  if (!data) return null;
                  
                  const colors = {
                    SAFE: 'var(--status-safe)',
                    REVIEW: 'var(--status-review)',
                    PROTECTED: 'var(--status-protected)'
                  };
                  const icons = {
                    SAFE: <CheckCircle size={24} color={colors.SAFE} />,
                    REVIEW: <AlertTriangle size={24} color={colors.REVIEW} />,
                    PROTECTED: <Shield size={24} color={colors.PROTECTED} />
                  };
                  
                  return (
                    <div key={status} className="glass-card" style={{ flex: 1, padding: '1.5rem', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                      {icons[status]}
                      <div>
                        <div style={{ fontSize: '1.5rem', fontWeight: 600 }}>{formatSize(data.total_size)}</div>
                        <div style={{ color: 'var(--text-secondary)', fontSize: '0.875rem' }}>{data.count} {status} items</div>
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="flex justify-between items-center" style={{ marginTop: '1rem' }}>
                <h3>Scan Results</h3>
                <button 
                  className="btn btn-outline" 
                  style={{ borderColor: 'var(--status-safe)', color: 'var(--status-safe)' }}
                  onClick={quarantineSafeItems}
                >
                  <Trash2 size={16} /> Quarantine All SAFE Items
                </button>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Type</th>
                      <th>Size</th>
                      <th>Status</th>
                      <th>Reason</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanResults.map(item => (
                      <tr key={item.item_id}>
                        <td>
                          <div style={{ fontWeight: 500 }}>{item.filename}</div>
                          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{item.app_name || item.parent_folder.split('\\').pop()}</div>
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>{item.file_type}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>{formatSize(item.size_bytes)}</td>
                        <td>
                          <span className={`badge badge-${item.classification.toLowerCase()}`}>
                            {item.classification}
                          </span>
                        </td>
                        <td style={{ color: 'var(--text-secondary)' }}>{item.reason}</td>
                        <td style={{ textAlign: 'right' }}>
                          <button 
                            className="btn btn-outline btn-danger"
                            style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem', borderColor: 'var(--status-review)', color: 'var(--status-review)' }}
                            onClick={() => directDeleteItem(item.full_path)}
                            title="Delete Item directly (Send to Recycle Bin)"
                          >
                            <Trash2 size={14} /> Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {/* Quarantine Tab */}
      {activeTab === 'quarantine' && (
        <div className="flex-col gap-6">
          <div className="glass-card" style={{ padding: '2rem' }}>
            <div className="flex justify-between items-center">
              <div>
                <h2>Quarantine</h2>
                <p style={{ color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                  Files isolated here can be restored or sent to the Recycle Bin.
                </p>
              </div>
              <div className="flex gap-4 items-center">
                 <div style={{ fontSize: '1.25rem', fontWeight: 600 }}>
                   {formatSize(quarantinedItems.reduce((acc, curr) => acc + curr.size_bytes, 0))}
                 </div>
                 <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>Total Size</div>
              </div>
            </div>
          </div>

          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Original Path</th>
                  <th>Size</th>
                  <th>Quarantined On</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {quarantinedItems.length === 0 ? (
                  <tr>
                    <td colSpan="4" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
                      No items in quarantine
                    </td>
                  </tr>
                ) : (
                  quarantinedItems.map(item => (
                    <tr key={item.quarantine_id}>
                      <td>
                        <div style={{ fontWeight: 500 }}>{item.filename}</div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{item.original_path}</div>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>{formatSize(item.size_bytes)}</td>
                      <td style={{ color: 'var(--text-secondary)' }}>
                        {new Date(item.quarantined_at).toLocaleString()}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div className="flex gap-2 justify-center" style={{ justifyContent: 'flex-end' }}>
                          <button 
                            className="btn btn-outline" 
                            style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }}
                            onClick={() => restoreItem(item.quarantine_id)}
                            title="Restore"
                          >
                            <RotateCcw size={14} /> Restore
                          </button>
                          <button 
                            className="btn btn-danger" 
                            style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem' }}
                            onClick={() => deleteItem(item.quarantine_id)}
                            title="Delete to Recycle Bin"
                          >
                            <Trash2 size={14} /> Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
