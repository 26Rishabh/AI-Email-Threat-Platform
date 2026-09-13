// src/components/IPMap.jsx
// Leaflet map showing approximate IP infrastructure locations.
import { MapContainer, TileLayer, CircleMarker, Popup } from 'react-leaflet'

// Country → approximate lat/lng
const COUNTRY_COORDS = {
  'India': [20.5937, 78.9629], 'United States': [37.0902, -95.7129],
  'Russia': [61.524, 105.3188], 'China': [35.8617, 104.1954],
  'Germany': [51.1657, 10.4515], 'United Kingdom': [55.3781, -3.4360],
  'Brazil': [-14.235, -51.9253], 'France': [46.2276, 2.2137],
  'Netherlands': [52.1326, 5.2913], 'Singapore': [1.3521, 103.8198],
  'Japan': [36.2048, 138.2529], 'Canada': [56.1304, -106.3468],
  'Australia': [-25.2744, 133.7751], 'South Korea': [35.9078, 127.7669],
  'Ukraine': [48.3794, 31.1656], 'Nigeria': [9.082, 8.6753],
  'Pakistan': [30.3753, 69.3451], 'Bangladesh': [23.685, 90.3563],
}

export default function IPMap({ ipResults }) {
  const validIPs = (ipResults || []).filter(
    r => r.lookup_status === 'success' && r.country !== 'Unknown'
  )

  if (validIPs.length === 0) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
        <h3 className="text-white font-semibold mb-2 text-sm">IP Infrastructure Map</h3>
        <p className="text-slate-500 text-sm">No geolocatable IPs found.</p>
      </div>
    )
  }

  const firstCoords = COUNTRY_COORDS[validIPs[0].country] || [20, 0]

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-2xl overflow-hidden">
      <div className="px-5 pt-5 pb-3">
        <h3 className="text-white font-semibold text-sm">IP Infrastructure Map</h3>
        <p className="text-slate-500 text-xs mt-1">
          Approximate infrastructure geolocation — NOT attacker location
        </p>
      </div>

      <div className="h-56">
        <MapContainer
          center={firstCoords}
          zoom={2}
          style={{ height: '100%', width: '100%' }}
          scrollWheelZoom={false}
        >
          <TileLayer
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            attribution='&copy; OpenStreetMap contributors'
          />
          {validIPs.map((ip) => {
            const coords = COUNTRY_COORDS[ip.country]
            if (!coords) return null
            return (
              <CircleMarker
                key={ip.ip}
                center={coords}
                radius={8}
                pathOptions={{ color: '#ef4444', fillColor: '#ef4444', fillOpacity: 0.7 }}
              >
                <Popup>
                  <div style={{ fontSize: '12px', lineHeight: '1.6' }}>
                    <b>IP:</b> {ip.ip}<br />
                    <b>Country:</b> {ip.country}<br />
                    <b>Region:</b> {ip.region}<br />
                    <b>ISP:</b> {ip.isp}<br />
                    {ip.asn && <><b>ASN:</b> {ip.asn}<br /></>}
                    <i style={{ color: '#888', fontSize: '11px' }}>{ip.disclaimer}</i>
                  </div>
                </Popup>
              </CircleMarker>
            )
          })}
        </MapContainer>
      </div>

      <div className="px-5 pb-5 pt-3 space-y-2">
        {validIPs.map((ip) => (
          <div key={ip.ip} className="flex items-center justify-between bg-slate-700/50 rounded-lg px-3 py-2">
            <div>
              <span className="text-white font-mono text-xs">{ip.ip}</span>
              {ip.is_hosting && (
                <span className="ml-2 text-xs bg-orange-500/20 text-orange-400 border border-orange-500/30 px-2 py-0.5 rounded-full">
                  Hosting
                </span>
              )}
            </div>
            <div className="text-right">
              <p className="text-slate-300 text-xs">{ip.country} · {ip.region}</p>
              <p className="text-slate-500 text-xs">{ip.isp}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
