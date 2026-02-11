export function ConfidenceMeter({ value }: { value: number }) {
  const width = Math.round(value * 100);
  return (
    <div className="flex items-center gap-3">
      <div className="h-2 w-full rounded-full bg-panelElev">
        <div
          className="h-2 rounded-full bg-teal"
          style={{ width: `${width}%` }}
        />
      </div>
      <span className="text-xs text-muted">{width}%</span>
    </div>
  );
}
