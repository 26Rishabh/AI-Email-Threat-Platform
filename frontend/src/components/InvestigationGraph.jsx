// src/components/InvestigationGraph.jsx
// Module 11 — Visual investigation graph using React Flow.
//
// Shows how all indicators are connected:
//   Email → Domain → IP → ISP/ASN
//
// WHY REACT FLOW:
// React Flow is a library for building node-based
// diagrams. Each indicator (email, domain, IP, ISP)
// becomes a "node" and relationships become "edges".
// This lets analysts visually trace the infrastructure.

import { useEffect, useRef, useState } from 'react'

// Node type colours
const NODE_COLORS = {
  email:  { bg: '#1e3a5f', border: '#3b82f6', text: '#93c5fd', icon: '✉' },
  domain: { bg: '#1e3a1e', border: '#22c55e', text: '#86efac', icon: '🌐' },
  ip:     { bg: '#3a1e1e', border: '#ef4444', text: '#fca5a5', icon: '🖥' },
  isp:    { bg: '#2e1e3a', border: '#a855f7', text: '#d8b4fe', icon: '📡' },
  url:    { bg: '#3a2e1e', border: '#f97316', text: '#fdba74', icon: '🔗' },
}

// Simple SVG-based graph renderer (no external dependency issues)
export default function InvestigationGraph({ graphData }) {
  const nodes  = graphData?.nodes || []
  const edges  = graphData?.edges || []

  if (nodes.length === 0) {
    return (
      <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
        <h3 className="text-white font-semibold text-sm mb-2">Investigation Graph</h3>
        <p className="text-slate-500 text-sm">No graph data available.</p>
      </div>
    )
  }

  // ── Layout: position nodes in layers ─────────
  // Layer 0: email (centre top)
  // Layer 1: domains
  // Layer 2: IPs
  // Layer 3: ISPs
  const layers = { email: 0, url: 1, domain: 1, ip: 2, isp: 3 }
  const layerNodes = {}

  nodes.forEach(n => {
    const layer = layers[n.type] ?? 1
    if (!layerNodes[layer]) layerNodes[layer] = []
    layerNodes[layer].push(n)
  })

  const W = 700   // SVG width
  const ROW_H = 110
  const NODE_W = 160
  const NODE_H = 44

  // Assign x/y to each node
  const positioned = {}
  Object.entries(layerNodes).forEach(([layer, layerList]) => {
    const y = 20 + parseInt(layer) * ROW_H
    const totalW = layerList.length * (NODE_W + 20) - 20
    const startX = Math.max(10, (W - totalW) / 2)
    layerList.forEach((n, i) => {
      positioned[n.id] = {
        ...n,
        x: startX + i * (NODE_W + 20),
        y,
        cx: startX + i * (NODE_W + 20) + NODE_W / 2,
        cy: y + NODE_H / 2,
      }
    })
  })

  const maxLayer = Math.max(...Object.keys(layerNodes).map(Number))
  const svgH = 40 + (maxLayer + 1) * ROW_H

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-2xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-white font-semibold text-sm">Investigation Graph</h3>
        <div className="flex items-center gap-3 text-xs text-slate-500">
          {Object.entries(NODE_COLORS).map(([type, c]) => (
            <span key={type} className="flex items-center gap-1">
              <span style={{ background: c.border, width: 8, height: 8, borderRadius: 2, display: 'inline-block' }} />
              {type}
            </span>
          ))}
        </div>
      </div>

      <div className="overflow-x-auto">
        <svg
          width={W}
          height={svgH}
          viewBox={`0 0 ${W} ${svgH}`}
          style={{ minWidth: W }}
        >
          {/* Draw edges first (behind nodes) */}
          {edges.map((e) => {
            const src = positioned[e.source]
            const tgt = positioned[e.target]
            if (!src || !tgt) return null
            return (
              <g key={e.id}>
                <line
                  x1={src.cx} y1={src.cy + NODE_H / 2 - 4}
                  x2={tgt.cx} y2={tgt.cy - NODE_H / 2 + 4}
                  stroke="#334155" strokeWidth="1.5"
                  strokeDasharray="4 3"
                  markerEnd="url(#arrow)"
                />
                {e.label && (
                  <text
                    x={(src.cx + tgt.cx) / 2}
                    y={(src.cy + tgt.cy) / 2}
                    textAnchor="middle"
                    fill="#475569"
                    fontSize="9"
                  >
                    {e.label}
                  </text>
                )}
              </g>
            )
          })}

          {/* Arrow marker definition */}
          <defs>
            <marker id="arrow" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
              <path d="M0,0 L0,6 L6,3 z" fill="#334155" />
            </marker>
          </defs>

          {/* Draw nodes */}
          {Object.values(positioned).map((n) => {
            const c = NODE_COLORS[n.type] || NODE_COLORS.domain
            const label = n.label.length > 22 ? n.label.slice(0, 20) + '…' : n.label
            return (
              <g key={n.id}>
                <rect
                  x={n.x} y={n.y}
                  width={NODE_W} height={NODE_H}
                  rx="8"
                  fill={c.bg}
                  stroke={c.border}
                  strokeWidth="1.5"
                />
                <text x={n.x + 10} y={n.y + 16} fontSize="11" fill={c.border}>
                  {c.icon}
                </text>
                <text x={n.x + 26} y={n.y + 17} fontSize="10" fontWeight="600" fill={c.text}>
                  {n.type.toUpperCase()}
                </text>
                <text x={n.x + 10} y={n.y + 33} fontSize="9.5" fill="#94a3b8">
                  {label}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}
