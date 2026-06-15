import { Component, type ReactNode } from "react";
import { ErrorFallback } from "./ErrorFallback";

type ErrorBoundaryProps = {
  children: ReactNode;
};

type ErrorBoundaryState = {
  error: unknown;
  errorId: string;
};

function newErrorId(): string {
  return Math.random().toString(36).slice(2, 10).toUpperCase();
}

/**
 * ErrorBoundary is the top-level safety net. It catches render errors anywhere
 * in the tree below it and shows a recoverable fallback instead of a blank
 * white screen.
 */
export class ErrorBoundary extends Component<
  ErrorBoundaryProps,
  ErrorBoundaryState
> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { error: null, errorId: "" };
  }

  static getDerivedStateFromError(error: unknown): ErrorBoundaryState {
    return { error, errorId: newErrorId() };
  }

  componentDidCatch(error: unknown) {
    // Log so the failure is observable in the console / future telemetry sink.
    console.error("Unhandled UI error", { errorId: this.state.errorId, error });
  }

  handleReset = () => {
    this.setState({ error: null, errorId: "" });
  };

  render() {
    if (this.state.error) {
      return (
        <ErrorFallback
          error={this.state.error}
          errorId={this.state.errorId}
          onReset={this.handleReset}
        />
      );
    }
    return this.props.children;
  }
}
