import { NavLink } from "react-router-dom";
import { shouldHideTokenEntry } from "../lib/api";

type AppShellProps = {
  token: string;
  onTokenChange: (value: string) => void;
  children: React.ReactNode;
};

const navItems = [
  ["/", "Posture", "P"],
  ["/detections", "Detections", "D"],
  ["/investigations", "Investigations", "I"],
  ["/fleet", "Fleet", "F"],
  ["/exports", "Exports", "X"],
  ["/events", "Events", "E"],
] as const;

export function AppShell({ token, onTokenChange, children }: AppShellProps) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-mark" aria-hidden="true">
            HN
          </div>
          <span className="eyebrow">Enterprise Deception</span>
          <h1>Honeynet Analyst</h1>
          <p>Early-warning control plane for reconnaissance, credential abuse, and exposed sensor posture.</p>
        </div>
        <nav className="sidebar-nav">
          {navItems.map(([to, label, glyph]) => (
            <NavLink key={to} to={to} end={to === "/"} className="nav-link">
              <span className="nav-glyph">{glyph}</span>
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        {shouldHideTokenEntry() ? null : (
          <div className="sidebar-token">
            <label htmlFor="analyst-token">Analyst token</label>
            <input
              id="analyst-token"
              value={token}
              onChange={(event) => onTokenChange(event.target.value)}
              placeholder="OIDC bearer or dev token"
            />
            <small>Development mode only. In production, the console should hide this and rely on OIDC.</small>
          </div>
        )}
      </aside>
      <main className="app-content">
        <div className="top-strip">
          <span className="live-dot" aria-hidden="true" />
          <span>Live SOC workspace</span>
          <span className="top-strip-divider" />
          <span>Private control plane</span>
        </div>
        <div className="content-stage">{children}</div>
      </main>
    </div>
  );
}
