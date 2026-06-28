import './explorer.css';

import { useState, useCallback, useEffect } from 'react';
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  useNodesState,
  useEdgesState,
  useReactFlow,
  type Node,
  type Edge,
} from '@xyflow/react';

import GraphNodeCard, { type CardData } from './GraphNodeCard';
import {
  CONCEPT_NODES,
  CONCEPT_EDGES,
  PHYSICAL_NODES,
  PHYSICAL_EDGES,
  MAPPINGS,
  type GraphNode,
  type GraphEdge,
} from '../../data/graph';

// ── Helpers ─────────────────────────────────────────────────────────────────

/** nodeTypes must live outside the component to avoid recreating on each render */
const nodeTypes = { concept: GraphNodeCard } as const;

type Layer = 'conceptual' | 'physical';

function getPhysicalLabel(id: string): string {
  return PHYSICAL_NODES.find((n) => n.id === id)?.label ?? id;
}

const BOUNDARY_COLOR: Record<string, string> = {
  describe: 'var(--copper)',
  operate: 'var(--operate)',
  publish: 'var(--publish)',
  physical: 'var(--structural-light, #8a8280)',
};

function buildNodes(
  graphNodes: GraphNode[],
  selectedId: string | null,
  query: string
): Node<CardData>[] {
  const lc = query.toLowerCase().trim();
  return graphNodes.map((n) => ({
    id: n.id,
    type: 'concept' as const,
    position: { x: n.x, y: n.y },
    data: {
      ...n,
      isSelected: n.id === selectedId,
    } as CardData,
    style: {
      opacity:
        lc &&
        !n.label.toLowerCase().includes(lc) &&
        !n.kind.toLowerCase().includes(lc)
          ? 0.25
          : 1,
      transition: 'opacity 0.15s',
    },
    selectable: true,
    draggable: false,
    connectable: false,
  }));
}

function buildEdges(graphEdges: GraphEdge[]): Edge[] {
  return graphEdges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    ...(e.label
      ? {
          label: e.label,
          labelStyle: {
            fill: 'var(--text-tertiary)',
            fontSize: 9,
            fontFamily: 'DM Mono, monospace',
          },
          labelBgStyle: {
            fill: 'var(--canvas-deep)',
            fillOpacity: 0.85,
          },
          labelBgPadding: [4, 2] as [number, number],
          labelBgBorderRadius: 3,
          labelShowBg: true,
        }
      : {}),
    style: { stroke: 'var(--structural)', strokeWidth: 1.5 },
  }));
}

// ── Inner component (needs to be inside ReactFlowProvider for useReactFlow) ──

function ExplorerInner() {
  const { fitView } = useReactFlow();

  const [layer, setLayer] = useState<Layer>('conceptual');
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [query, setQuery] = useState('');

  // Initialise with conceptual layer data so the first render is not empty
  const [nodes, setNodes, onNodesChange] = useNodesState(
    buildNodes(CONCEPT_NODES, null, '')
  );
  const [edges, setEdges, onEdgesChange] = useEdgesState(
    buildEdges(CONCEPT_EDGES)
  );

  // Sync nodes whenever layer, selection, or search query changes
  useEffect(() => {
    const layerNodes = layer === 'conceptual' ? CONCEPT_NODES : PHYSICAL_NODES;
    setNodes(buildNodes(layerNodes, selectedId, query));
  }, [layer, selectedId, query, setNodes]);

  // Sync edges whenever layer changes
  useEffect(() => {
    const layerEdges =
      layer === 'conceptual' ? CONCEPT_EDGES : PHYSICAL_EDGES;
    setEdges(buildEdges(layerEdges));
  }, [layer, setEdges]);

  // fitView after layer change (and on mount)
  useEffect(() => {
    const t = setTimeout(() => {
      fitView({ duration: 300, padding: 0.15 });
    }, 100);
    return () => clearTimeout(t);
  }, [layer, fitView]);

  // Re-fit when the window resizes so the graph stays framed
  useEffect(() => {
    const onResize = () => fitView({ padding: 0.15, duration: 200 });
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, [fitView]);

  // Node click — toggle selection
  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      setSelectedId((prev) => (prev === node.id ? null : node.id));
    },
    []
  );

  const closePanel = useCallback(() => setSelectedId(null), []);

  // Chip click: switch to physical layer and select that component
  const selectPhysical = useCallback((physId: string) => {
    setLayer('physical');
    setSelectedId(physId);
  }, []);

  // Layer switch via toggle (clears selection to avoid stale cross-layer id)
  const switchLayer = useCallback(
    (next: Layer) => {
      setLayer(next);
      setSelectedId(null);
    },
    []
  );

  // Resolve selected node data from the currently active layer
  const selectedNode = selectedId
    ? (layer === 'conceptual' ? CONCEPT_NODES : PHYSICAL_NODES).find(
        (n) => n.id === selectedId
      )
    : null;

  // Mapping only applies when the conceptual layer is active
  const mapping =
    layer === 'conceptual' && selectedId
      ? MAPPINGS.find((m) => m.concept === selectedId)
      : null;

  return (
    <div className="explorer-island">
      {/* ── Top bar ── */}
      <div className="explorer-topbar">
        <div className="layer-toggle">
          <button
            className={`layer-btn${layer === 'conceptual' ? ' active' : ''}`}
            onClick={() => switchLayer('conceptual')}
          >
            Conceptual
          </button>
          <button
            className={`layer-btn${layer === 'physical' ? ' active' : ''}`}
            onClick={() => switchLayer('physical')}
          >
            Physical
          </button>
        </div>

        <input
          type="search"
          className="explorer-search"
          placeholder="Search nodes…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search nodes"
        />
      </div>

      {/* ── Canvas ── */}
      <div className="explorer-canvas">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          onNodeClick={handleNodeClick}
          nodesDraggable={false}
          nodesConnectable={false}
          elementsSelectable={true}
          panOnScroll={true}
          zoomOnScroll={true}
          minZoom={0.3}
          maxZoom={2}
        >
          <Background variant="dots" color="var(--grid-line)" gap={20} size={1} />
          <Controls showInteractive={false} />
        </ReactFlow>

        {/* ── Detail panel ── */}
        <div className={`detail-panel${selectedNode ? ' open' : ''}`}>
          {selectedNode ? (
            <>
              <button
                className="detail-close"
                onClick={closePanel}
                aria-label="Close detail panel"
              >
                ×
              </button>

              <p
                className="detail-kind"
                style={{
                  color: BOUNDARY_COLOR[selectedNode.boundary] ?? 'var(--copper)',
                }}
              >
                {selectedNode.kind}
              </p>

              <h2 className="detail-label">{selectedNode.label}</h2>

              <p className="detail-summary">{selectedNode.summary}</p>

              <hr className="detail-divider" />

              <p className="detail-text">{selectedNode.detail}</p>

              {mapping && (
                <>
                  <p className="detail-maps-label">Maps to</p>
                  <div className="maps-chips">
                    {mapping.components.map((compId) => (
                      <button
                        key={compId}
                        className="chip"
                        onClick={() => selectPhysical(compId)}
                        title="Switch to Physical layer and select this component"
                      >
                        {getPhysicalLabel(compId)}
                      </button>
                    ))}
                  </div>
                  {mapping.note && (
                    <p className="maps-note">{mapping.note}</p>
                  )}
                </>
              )}
            </>
          ) : (
            <p className="detail-hint">
              Select a node to inspect it.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Island export ────────────────────────────────────────────────────────────

export default function Explorer() {
  return (
    <ReactFlowProvider>
      <ExplorerInner />
    </ReactFlowProvider>
  );
}
