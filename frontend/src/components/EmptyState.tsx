interface EmptyStateProps {
  title: string;
  description?: string;
}

export function EmptyState({ title, description }: EmptyStateProps) {
  return (
    <div className="empty-state-inline" data-testid="empty-state">
      <strong>{title}</strong>
      {description ? <div>{description}</div> : null}
    </div>
  );
}
