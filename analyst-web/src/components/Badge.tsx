type BadgeProps = {
  tone?: "default" | "danger" | "warning" | "success";
  children: React.ReactNode;
};

export function Badge({ tone = "default", children }: BadgeProps) {
  return <span className={`badge badge-${tone}`}>{children}</span>;
}

