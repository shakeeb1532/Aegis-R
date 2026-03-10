import React from "react";

type ErrorBoundaryProps = {
  children: React.ReactNode;
};

type ErrorBoundaryState = {
  hasError: boolean;
  error?: string;
};

export class ErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error: error.message };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("UI crashed", error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-base px-6 text-text">
          <div className="max-w-md rounded-2xl border border-border bg-panel p-6 text-center">
            <p className="text-xs uppercase tracking-[0.3em] text-muted">UI Error</p>
            <h1 className="section-title mt-2 text-xl font-semibold">Something broke in the UI</h1>
            <p className="mt-3 text-sm text-muted">
              Refresh the page. If it happens again, export logs and share the request ID.
            </p>
            {this.state.error ? (
              <p className="mt-4 rounded-xl border border-border bg-panelElev px-3 py-2 text-xs text-muted">
                {this.state.error}
              </p>
            ) : null}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
