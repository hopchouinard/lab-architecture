import type { Node, NodeProps } from '@xyflow/react';
import { Handle, Position } from '@xyflow/react';

const BOUNDARY_COLOR: Record<string, string> = {
  describe: 'var(--copper)',
  operate: 'var(--operate)',
  publish: 'var(--publish)',
  physical: 'var(--structural-light, #8a8280)',
};

export interface CardData extends Record<string, unknown> {
  id: string;
  label: string;
  boundary: string;
  kind: string;
  summary: string;
  detail: string;
  x: number;
  y: number;
  source?: boolean;
  isSelected?: boolean;
}

export type CardNode = Node<CardData, 'concept'>;

export default function GraphNodeCard({ data }: NodeProps<CardNode>) {
  const color = BOUNDARY_COLOR[data.boundary] ?? '#8a8280';

  return (
    <div
      style={{
        borderLeft: `3px solid ${color}`,
        borderRadius: 7,
        background: data.source
          ? 'rgba(207, 126, 56, 0.14)'
          : 'var(--canvas-elevated)',
        padding: '8px 12px',
        minWidth: 120,
        maxWidth: 190,
        cursor: 'pointer',
        boxSizing: 'border-box',
        boxShadow: data.isSelected
          ? `0 0 0 2px var(--copper), 0 0 14px rgba(207, 126, 56, 0.35), 0 2px 8px rgba(0,0,0,0.4)`
          : '0 1px 4px rgba(0,0,0,0.35)',
        transition: 'box-shadow 0.15s ease',
      }}
    >
      <p
        style={{
          fontFamily: 'var(--mono)',
          fontSize: 9,
          letterSpacing: '2px',
          textTransform: 'uppercase',
          color,
          margin: '0 0 4px',
          lineHeight: 1,
        }}
      >
        {data.kind as string}
      </p>
      <p
        style={{
          fontFamily: 'var(--mono)',
          fontSize: 12,
          color: 'var(--text-primary)',
          lineHeight: 1.3,
          margin: 0,
        }}
      >
        {data.label as string}
      </p>
      {/* Hidden handles — provide attachment points for edges without visual clutter */}
      <Handle
        type="target"
        position={Position.Left}
        style={{ opacity: 0, width: 1, height: 1, minWidth: 0, minHeight: 0 }}
      />
      <Handle
        type="source"
        position={Position.Right}
        style={{ opacity: 0, width: 1, height: 1, minWidth: 0, minHeight: 0 }}
      />
    </div>
  );
}
