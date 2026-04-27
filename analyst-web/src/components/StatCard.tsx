type StatCardProps = {
  label: string;
  value: string | number;
  delta?: string;
};

export function StatCard({ label, value, delta }: StatCardProps) {
  return (
    <article className="stat-card">
      <div className="stat-card-top">
        <span className="stat-label">{label}</span>
        <span className="stat-pulse" aria-hidden="true" />
      </div>
      <strong>{value}</strong>
      {delta ? <span className="stat-delta">{delta}</span> : null}
    </article>
  );
}
