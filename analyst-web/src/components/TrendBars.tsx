type TrendBarsProps = {
  items: Array<{ label: string; value: number }>;
};

export function TrendBars({ items }: TrendBarsProps) {
  const max = Math.max(...items.map((item) => item.value), 1);

  return (
    <div className="trend-bars">
      {items.map((item) => (
        <div key={item.label} className="trend-row">
          <div className="trend-meta">
            <span>{item.label}</span>
            <strong>{item.value}</strong>
          </div>
          <div className="trend-track">
            <div className="trend-fill" style={{ width: `${(item.value / max) * 100}%` }} />
          </div>
        </div>
      ))}
    </div>
  );
}

