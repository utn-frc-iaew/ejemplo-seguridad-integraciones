import React from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { Auth0Provider } from '@auth0/auth0-react'

const domain = import.meta.env.VITE_AUTH0_DOMAIN
const clientId = import.meta.env.VITE_AUTH0_CLIENT_ID
const audience = import.meta.env.VITE_AUTH0_AUDIENCE

createRoot(document.getElementById('root')).render(
  <Auth0Provider
    domain={domain}
    clientId={clientId}
    authorizationParams={{
      redirect_uri: window.location.origin,
      audience,
      scope: 'read:students'
    }}
    useRefreshTokens={true}
    cacheLocation="memory"
  >
    <App />
  </Auth0Provider>
)
