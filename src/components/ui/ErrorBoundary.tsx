import { Component, type ErrorInfo, type ReactNode } from 'react'
import { cs } from '../../i18n/cs.ts'
import { Button } from '../../design-system/index.ts'
import { toSafeWorkerError } from '../../domain/safeWorkerError.ts'

interface Props {
  children: ReactNode
  onReset?: () => void
}

interface State {
  error: Error | null
  safeDetail: string | null
}

export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null, safeDetail: null }

  static getDerivedStateFromError(error: Error): State {
    const safe = toSafeWorkerError(error, 'unknown')
    return {
      error,
      safeDetail: `${safe.code} — ${safe.safeMessage}`,
    }
  }

  override componentDidCatch(error: Error, info: ErrorInfo): void {
    // Dev-only: never log identity-bearing messages in production builds.
    if (import.meta.env.DEV) {
      console.error('rnd-log-anonymizer error boundary', error.name, info.componentStack)
    }
  }

  private handleReset = () => {
    this.setState({ error: null, safeDetail: null })
    this.props.onReset?.()
  }

  override render() {
    if (this.state.error) {
      return (
        <div className="error-boundary" role="alert">
          <h1>{cs.errors.boundaryTitle}</h1>
          <p>{cs.errors.boundaryBody}</p>
          <p className="error-boundary__detail">
            <span className="visually-hidden">Technický detail: </span>
            {this.state.safeDetail ?? this.state.error.name}
          </p>
          <Button variant="primary" onClick={this.handleReset}>
            {cs.errors.boundaryRetry}
          </Button>
        </div>
      )
    }
    return this.props.children
  }
}
