type SectionCardProps = {
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
};

export function SectionCard({ title, subtitle, actions, children }: SectionCardProps) {
  return (
    <section className="section-card">
      <header className="section-card-header">
        <div>
          <h2>{title}</h2>
          {subtitle ? <p>{subtitle}</p> : null}
        </div>
        {actions ? <div className="section-card-actions">{actions}</div> : null}
      </header>
      {children}
    </section>
  );
}

