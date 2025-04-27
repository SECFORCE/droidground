// Package imports
import ReactDOMServer from 'react-dom/server';

// Local imports
import { App } from '@client/App';

export function render() {
  const html = ReactDOMServer.renderToString(
    <App />
  )
  return { html }
}