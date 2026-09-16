import { useState } from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import './App.css';

function App() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [packets, setPackets] = useState([]);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [stats, setStats] = useState(null);
  const [currentPage, setCurrentPage] = useState(0);

  const handleFileChange = (event) => {
    setSelectedFile(event.target.files[0]);
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert("Please choose a file first!");
      return;
    }

    setUploading(true);

    const formData = new FormData();
    formData.append("file", selectedFile);

    try {
      const response = await fetch("http://127.0.0.1:5000/api/upload", {
        method: "POST",
        body: formData,
      });

      const data = await response.json();
      setPackets(data);
      setSelectedPacket(null);
      setCurrentPage(0);

      // Also fetch stats for the dashboard
      const statsFormData = new FormData();
      statsFormData.append("file", selectedFile);
      const statsResponse = await fetch("http://127.0.0.1:5000/api/stats", {
        method: "POST",
        body: statsFormData,
      });
      const statsData = await statsResponse.json();
      setStats(statsData);
    } catch (error) {
      console.error("Upload failed:", error);
      alert("Upload failed. Is your Flask server running?");
    }

    setUploading(false);
  };

  return (
    <div className="App">
      <h1>PacketScope</h1>
      <p>Network Packet Analyzer</p>

      <div style={{ marginTop: "20px", display: "flex", justifyContent: "center", gap: "10px", alignItems: "center" }}>
        <input type="file" onChange={handleFileChange} accept=".pcap,.pcapng" />
        <button onClick={handleUpload} disabled={uploading}>
          {uploading ? "Uploading..." : "Upload"}
        </button>
      </div>

      {packets.length > 0 && (
        <div style={{ marginTop: "30px", textAlign: "left", maxWidth: "900px", marginLeft: "auto", marginRight: "auto" }}>
          <p>Total packets: {packets.length} — click a row to inspect it</p>
          <table border="1" cellPadding="6" style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                <th>No.</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Length</th>
              </tr>
            </thead>
            <tbody>
              {packets.slice(currentPage * 50, currentPage * 50 + 50).map((packet, index) => (
                <tr
                  key={index}
                  onClick={() => setSelectedPacket(packet)}
                  style={{
                    cursor: "pointer",
                    backgroundColor: selectedPacket === packet ? "#d0e8ff" : "white",
                  }}
                >
                  <td>{packet.id}</td>
                  <td>{packet.src_ip || "-"}</td>
                  <td>{packet.dst_ip || "-"}</td>
                  <td>{packet.transport || packet.protocol || "-"}</td>
                  <td>{packet.length}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <div style={{ marginTop: "10px", display: "flex", justifyContent: "center", alignItems: "center", gap: "15px" }}>
            <button
              onClick={() => setCurrentPage((p) => Math.max(p - 1, 0))}
              disabled={currentPage === 0}
            >
              Previous
            </button>
            <span style={{ fontSize: "13px" }}>
              Showing {currentPage * 50 + 1}–{Math.min(currentPage * 50 + 50, packets.length)} of {packets.length}
            </span>
            <button
              onClick={() => setCurrentPage((p) => (p + 1) * 50 < packets.length ? p + 1 : p)}
              disabled={(currentPage + 1) * 50 >= packets.length}
            >
              Next
            </button>
          </div>
        </div>
      )}

      {stats && (
        <div style={{ marginTop: "30px", maxWidth: "500px", marginLeft: "auto", marginRight: "auto" }}>
          <strong>Protocol Distribution</strong>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={Object.entries(stats).map(([name, value]) => ({ name, value }))}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label
              >
                {Object.keys(stats).map((_, index) => (
                  <Cell key={index} fill={["#2563eb", "#f97316", "#10b981", "#a855f7", "#ef4444"][index % 5]} />
                ))}
              </Pie>
              <Tooltip />
              <Legend />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}

      {selectedPacket && (
        <div style={{ marginTop: "20px", textAlign: "left", maxWidth: "900px", marginLeft: "auto", marginRight: "auto" }}>
          <strong>Selected packet #{selectedPacket.id} — Layer Breakdown</strong>

          <div style={{ marginTop: "10px", display: "flex", flexDirection: "column", gap: "6px" }}>

            {/* Application layer */}
            {selectedPacket.payload_preview && (
              <div style={{ backgroundColor: "#ffb3b3", padding: "10px 14px", borderRadius: "6px" }}>
                <strong>Application</strong>
                <div style={{ fontSize: "13px", wordBreak: "break-all" }}>
                  {selectedPacket.payload_type === "binary" ? (
                    <>Binary data (hex): {selectedPacket.payload_preview}</>
                  ) : (
                    <>Payload preview: {selectedPacket.payload_preview}</>
                  )}
                </div>
              </div>
            )}

            {/* Transport layer */}
            {selectedPacket.transport && (
              <div style={{ backgroundColor: "#c9b3ff", padding: "10px 14px", borderRadius: "6px" }}>
                <strong>Transport ({selectedPacket.transport})</strong>
                <div style={{ fontSize: "13px" }}>
                  {selectedPacket.transport === "TCP" && (
                    <>
                      Src Port: {selectedPacket.src_port} &nbsp;→&nbsp; Dst Port: {selectedPacket.dst_port}
                      <br />Flags: {selectedPacket.tcp_flags} &nbsp; Seq: {selectedPacket.seq} &nbsp; Ack: {selectedPacket.ack}
                    </>
                  )}
                  {selectedPacket.transport === "UDP" && (
                    <>
                      Src Port: {selectedPacket.src_port} &nbsp;→&nbsp; Dst Port: {selectedPacket.dst_port}
                    </>
                  )}
                  {selectedPacket.transport === "ICMP" && (
                    <>
                      ICMP Type: {selectedPacket.icmp_type} &nbsp; Code: {selectedPacket.icmp_code}
                    </>
                  )}
                  {selectedPacket.transport === "ICMPv6" && (
                    <>ICMPv6 Echo message (ping)</>
                  )}
                </div>
              </div>
            )}

            {/* Network layer */}
            {selectedPacket.src_ip && (
              <div style={{ backgroundColor: "#b3e0ff", padding: "10px 14px", borderRadius: "6px" }}>
                <strong>Network ({selectedPacket.protocol})</strong>
                <div style={{ fontSize: "13px" }}>
                  Src IP: {selectedPacket.src_ip} &nbsp;→&nbsp; Dst IP: {selectedPacket.dst_ip}
                  {selectedPacket.ttl && <> &nbsp; TTL: {selectedPacket.ttl}</>}
                </div>
              </div>
            )}

            {/* Data Link layer */}
            {selectedPacket.src_mac && (
              <div style={{ backgroundColor: "#d9d9d9", padding: "10px 14px", borderRadius: "6px" }}>
                <strong>Data Link (Ethernet)</strong>
                <div style={{ fontSize: "13px" }}>
                  Src MAC: {selectedPacket.src_mac} &nbsp;→&nbsp; Dst MAC: {selectedPacket.dst_mac}
                  {selectedPacket.ethertype && <> &nbsp; EtherType: {selectedPacket.ethertype}</>}
                </div>
              </div>
            )}

            {/* Physical layer */}
            <div style={{ backgroundColor: "#a3a3a3", padding: "10px 14px", borderRadius: "6px" }}>
              <strong>Physical</strong>
              <div style={{ fontSize: "13px" }}>
                {selectedPacket.length} bytes on wire
              </div>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}

export default App;